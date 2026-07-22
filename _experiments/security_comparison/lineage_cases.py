from __future__ import annotations

import dataclasses
import hashlib
import time
from dataclasses import dataclass
from functools import partial
from typing import Any, Callable

from eth_account import Account
from web3 import Web3

from infrastructure.agentdid_protocol import did_network
from infrastructure.lineage import (
    AgentType,
    BudgetLimits,
    LineageRegistryClient,
    LineageVerifier,
    LineageWallet,
    PermissionEnvelope,
    PolicyEngine,
    RootKeyManager,
    create_delegation_credential,
    create_epoch_certificate,
    credential_hash,
    version_did,
)
from infrastructure.lineage.crypto import (
    address_from_did,
    did_from_address,
    recover_typed_signer,
)
from infrastructure.lineage.models import DelegationCredential, LineageInvocation
from infrastructure.lineage.service import LineageGateway, ToolRouter
from infrastructure.security import sha256_json

from .chain import ChainConfig, query_root_state


AUDIENCE = "urn:agentdid:comparison:gateway"
OTHER_AUDIENCE = "urn:agentdid:comparison:other-gateway"
VERSION = version_did("agentdid-comparison-v1")
OTHER_VERSION = version_did("agentdid-comparison-unauthorized")
BODY = {"operation": "integer-addition", "left": 17, "right": 25}


@dataclass
class LineageCase:
    epoch: Any
    base_chain: list[DelegationCredential]
    registered_chains: list[list[DelegationCredential]]
    presented_chain: list[DelegationCredential]
    invocation: LineageInvocation
    body: dict[str, Any]
    expected_audience: str
    protocol_holder_private_key: str
    protocol_holder_did: str
    registry: LineageRegistryClient
    transactions: list[dict[str, Any]]
    mutation: str
    activation_steps: list[tuple[str, Callable[[], dict[str, Any]]]]
    activation_started: bool = False
    onchain_materialized: bool = False

    def materialize(self) -> list[dict[str, Any]]:
        """Publish prepared Lineage state after lower-layer verification passes."""

        if self.onchain_materialized:
            return self.transactions
        if self.activation_started:
            raise RuntimeError("LINEAGE_MATERIALIZATION_ALREADY_STARTED")
        self.activation_started = True
        for label, action in self.activation_steps:
            try:
                self.transactions.append(_tx(label, action()))
            except Exception as exc:
                transaction_hash = getattr(exc, "transaction_hash", None)
                if transaction_hash:
                    self.transactions.append({
                        "operation": label,
                        "transaction_hash": str(transaction_hash),
                        "status": "UNCERTAIN",
                        "error_type": type(exc).__name__,
                    })
                raise
        self.onchain_materialized = True
        return self.transactions

    def public_dict(self) -> dict[str, Any]:
        recovered_signer = recover_typed_signer(
            self.invocation.unsigned_dict(),
            self.invocation.signature,
            purpose="AgentLineage/REQUEST/v1",
            chain_id=self.registry.w3.eth.chain_id,
            verifying_contract=self.registry.address,
        )
        expected_signer = address_from_did(self.protocol_holder_did)
        return {
            "epoch_certificate": self.epoch.to_dict(),
            "registered_chain": [item.to_dict() for item in self.base_chain],
            "registered_chains": [
                [item.to_dict() for item in chain]
                for chain in self.registered_chains
            ],
            "presented_chain": [item.to_dict() for item in self.presented_chain],
            "invocation": self.invocation.to_dict(),
            "body": self.body,
            "expected_audience": self.expected_audience,
            "mutation": self.mutation,
            "prepared": True,
            "onchain_materialized": self.onchain_materialized,
            "enforcement_reached": self.onchain_materialized,
            "request_signature_control": {
                "passed": recovered_signer.lower() == expected_signer.lower(),
                "recovered_signer": recovered_signer,
                "expected_signer": expected_signer,
            },
        }

    def evaluate(self) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        verifier = LineageVerifier(
            chain_id=self.registry.w3.eth.chain_id,
            verifying_contract=self.registry.address,
            state_provider=self.registry,
            max_state_block_lag=0,
        )
        router = ToolRouter()
        for action, resource in (
            ("read", "urn:tool:a"),
            ("write", "urn:tool:a"),
            ("read", "urn:tool:b"),
            ("delete", "urn:tool:a"),
        ):
            router.register(
                action,
                resource,
                cost_units=2,
                handler=lambda body: {"sum": int(body["left"]) + int(body["right"])},
            )
        gateway = LineageGateway(
            verifier,
            self.registry,
            router,
            audience=self.expected_audience,
        )
        result = gateway.invoke({
            "epoch_certificate": self.epoch.to_dict(),
            "delegation_chain": [item.to_dict() for item in self.presented_chain],
            "invocation": self.invocation.to_dict(),
            "body": self.body,
        })
        for key in ("budget_begin", "budget_finish"):
            if result.get(key):
                self.transactions.append(result[key])
        decision = dict(result["decision"])
        decision["execution_output"] = result.get("output")
        return decision, self.transactions


def _wallet(agent_type: AgentType, *, delegable: bool, network: str) -> LineageWallet:
    generated = LineageWallet.generate(agent_type, delegable=delegable)
    generated.network = network
    return generated


def _tx(label: str, receipt: dict[str, Any]) -> dict[str, Any]:
    return {"operation": label, **receipt}


def _rebuild_leaf(
    *,
    original: DelegationCredential,
    first: DelegationCredential,
    permission: PermissionEnvelope,
    issuer_private_key: str,
    chain_id: int,
    contract: str,
    delegation_key: str | None = None,
) -> DelegationCredential:
    return create_delegation_credential(
        root_did=original.root_did,
        parent_did=original.parent_did,
        parent_credential_hash=original.parent_credential_hash,
        parent_lineage_commitment=first.lineage_commitment,
        child_did=original.child_did,
        child_operation_key=original.operation_key,
        child_delegation_key=delegation_key,
        agent_type=original.agent_type,
        version_id=original.version_id,
        replica_group_id=original.replica_group_id,
        permission=permission,
        budget_id=original.budget_id,
        reservation=original.reservation,
        epoch=original.epoch,
        status_ref=original.status_ref,
        issuer_delegation_private_key=issuer_private_key,
        chain_id=chain_id,
        verifying_contract=contract,
        jti=original.jti,
    )


def _resign(
    invocation: LineageInvocation,
    wallet: LineageWallet,
    chain_id: int,
    contract: str,
    **changes: Any,
) -> LineageInvocation:
    unsigned = dataclasses.replace(invocation, signature="", **changes)
    return wallet.sign_invocation(
        unsigned,
        chain_id=chain_id,
        verifying_contract=contract,
    )


def build_lineage_case(
    case_id: str,
    *,
    experiment_id: str,
    run_id: str,
    requested_epoch: int,
    chain_config: ChainConfig,
    chain_private_key: str,
) -> LineageCase:
    chain_id = chain_config.chain_id
    contract = chain_config.lineage_registry_address
    network = did_network(chain_id)
    root_account = Account.from_key(chain_private_key)
    root_did = did_from_address(root_account.address, network)
    seed = hashlib.sha256(
        bytes.fromhex(chain_private_key.removeprefix("0x")) + run_id.encode("utf-8")
    ).digest() * 2
    manager = RootKeyManager(root_did, seed)
    state = query_root_state(chain_config, root_did)
    epoch_number = max(1, int(requested_epoch))
    if state["active"] and epoch_number <= state["current_epoch"]:
        epoch_number = state["current_epoch"] + 1
    epoch_private_key = manager.derive(epoch_number)
    now = int(time.time())
    epoch = create_epoch_certificate(
        root_did=root_did,
        epoch=epoch_number,
        delegation_key=Account.from_key(epoch_private_key).address,
        not_before=now - 30,
        expires_at=now + 86_400,
        status_ref={"chain_id": chain_id, "contract": contract},
        root_identity_private_key=chain_private_key,
        chain_id=chain_id,
        verifying_contract=contract,
    )
    registry = LineageRegistryClient(
        Web3(Web3.HTTPProvider(
            chain_config.rpc_url,
            request_kwargs={"timeout": chain_config.rpc_timeout_seconds},
        )),
        contract,
        relayer_private_key=chain_private_key,
        confirmations=chain_config.confirmations,
    )
    transactions: list[dict[str, Any]] = []
    activation_steps: list[tuple[str, Callable[[], dict[str, Any]]]] = []
    if state["active"]:
        activation_steps.append((
            "rotate_epoch",
            partial(
                registry.rotate_epoch,
                epoch,
                chain_private_key,
                revoke_previous=True,
            ),
        ))
    else:
        activation_steps.append((
            "register_root",
            partial(registry.register_root, epoch, chain_private_key),
        ))

    root_budget_id = "0x" + hashlib.sha256(
        f"{experiment_id}:root-budget".encode("utf-8")
    ).hexdigest()
    activation_steps.append((
        "create_root_budget",
        partial(
            registry.create_root_budget,
            root_did,
            root_budget_id,
            BudgetLimits(1000, 10_000, 20),
            chain_private_key,
        ),
    ))

    persistent = _wallet(AgentType.PERSISTENT, delegable=True, network=network)
    session = _wallet(AgentType.SESSION, delegable=False, network=network)
    parent_permission = PermissionEnvelope(
        actions=("read", "write"),
        resources=("urn:tool:a", "urn:tool:b"),
        tasks=("task-1", "task-2"),
        audiences=(AUDIENCE,),
        versions=(VERSION,),
        not_before=now - 10,
        # Keep the parent window below the Session identity TTL ceiling.  L04
        # can then extend the child beyond its parent while remaining a valid
        # Session identity, so the intended attenuation check is the first
        # failing Lineage rule.
        expires_at=now + 3000,
        remaining_depth=3,
        delegable=True,
    )
    first_budget = "0x" + hashlib.sha256(
        f"{experiment_id}:persistent-budget".encode("utf-8")
    ).hexdigest()
    first = create_delegation_credential(
        root_did=root_did,
        parent_did=root_did,
        parent_credential_hash=credential_hash(epoch),
        parent_lineage_commitment=credential_hash(epoch),
        child_did=persistent.did,
        child_operation_key=persistent.operation_address,
        child_delegation_key=persistent.delegation_address,
        agent_type=AgentType.PERSISTENT,
        version_id=VERSION,
        replica_group_id=None,
        permission=parent_permission,
        budget_id=first_budget,
        reservation=BudgetLimits(100, 1000, 5),
        epoch=epoch_number,
        status_ref={"chain_id": chain_id, "contract": contract},
        issuer_delegation_private_key=epoch_private_key,
        chain_id=chain_id,
        verifying_contract=contract,
    )
    activation_steps.append((
        "register_persistent",
        partial(registry.register_delegation, first, epoch_private_key),
    ))
    activation_steps.append((
        "reserve_persistent_budget",
        partial(
            registry.reserve_child_budget,
            root_budget_id,
            first,
            epoch_private_key,
        ),
    ))

    child_permission = PolicyEngine().attenuate(
        parent_permission,
        {
            "actions": ["read"],
            "resources": ["urn:tool:a"],
            "tasks": ["task-1"],
            "remaining_depth": 0,
            "delegable": False,
            "expires_at": now + 1800,
        },
        AgentType.SESSION,
        now=now,
    )
    second_budget = "0x" + hashlib.sha256(
        f"{experiment_id}:session-budget".encode("utf-8")
    ).hexdigest()
    second = create_delegation_credential(
        root_did=root_did,
        parent_did=persistent.did,
        parent_credential_hash=credential_hash(first),
        parent_lineage_commitment=first.lineage_commitment,
        child_did=session.did,
        child_operation_key=session.operation_address,
        child_delegation_key=None,
        agent_type=AgentType.SESSION,
        version_id=VERSION,
        replica_group_id=None,
        permission=child_permission,
        budget_id=second_budget,
        reservation=BudgetLimits(10, 100, 1),
        epoch=epoch_number,
        status_ref={"chain_id": chain_id, "contract": contract},
        issuer_delegation_private_key=persistent.delegation_private_key,
        chain_id=chain_id,
        verifying_contract=contract,
    )
    activation_steps.append((
        "register_session",
        partial(
            registry.register_delegation,
            second,
            persistent.delegation_private_key,
            parent=first,
        ),
    ))
    activation_steps.append((
        "reserve_session_budget",
        partial(
            registry.reserve_child_budget,
            first_budget,
            second,
            persistent.delegation_private_key,
        ),
    ))

    request = LineageInvocation(
        leaf_did=session.did,
        credential_jti=second.jti,
        origin_did=session.did,
        on_behalf_of=root_did,
        audience=AUDIENCE,
        task_id="task-1",
        action="read",
        resource="urn:tool:a",
        version_id=VERSION,
        body_hash=sha256_json(BODY),
        challenge=f"lineage-{experiment_id}",
        sequence=1,
        timestamp=now,
        budget_id=second_budget,
        cost_units=2,
        lease_seconds=30,
    )
    invocation = session.sign_invocation(
        request,
        chain_id=chain_id,
        verifying_contract=contract,
    )
    presented_chain = [first, second]
    registered_chains = [[first, second]]
    holder_private_key = session.operation_private_key
    holder_did = session.did
    expected_audience = AUDIENCE
    mutation = "legitimate"

    if case_id == "L01":
        invocation = _resign(invocation, session, chain_id, contract, action="write")
        mutation = "leaf_action_escalation"
    elif case_id == "L02":
        invocation = _resign(invocation, session, chain_id, contract, resource="urn:tool:b")
        mutation = "leaf_resource_escalation"
    elif case_id == "L03":
        permission = dataclasses.replace(second.permission, actions=("delete", "read"))
        presented_chain = [first, _rebuild_leaf(
            original=second,
            first=first,
            permission=permission,
            issuer_private_key=persistent.delegation_private_key,
            chain_id=chain_id,
            contract=contract,
        )]
        invocation = _resign(invocation, session, chain_id, contract, action="delete")
        mutation = "delegation_scope_escalation"
    elif case_id == "L04":
        permission = dataclasses.replace(second.permission, expires_at=first.permission.expires_at + 60)
        presented_chain = [first, _rebuild_leaf(
            original=second,
            first=first,
            permission=permission,
            issuer_private_key=persistent.delegation_private_key,
            chain_id=chain_id,
            contract=contract,
        )]
        mutation = "validity_extension"
    elif case_id == "L05":
        permission = dataclasses.replace(second.permission, remaining_depth=3)
        presented_chain = [first, _rebuild_leaf(
            original=second,
            first=first,
            permission=permission,
            issuer_private_key=persistent.delegation_private_key,
            chain_id=chain_id,
            contract=contract,
        )]
        mutation = "depth_reset"
    elif case_id == "L06":
        rogue = _wallet(AgentType.CHILD, delegable=True, network=network)
        permission = dataclasses.replace(second.permission, remaining_depth=1, delegable=True)
        presented_chain = [first, _rebuild_leaf(
            original=second,
            first=first,
            permission=permission,
            issuer_private_key=persistent.delegation_private_key,
            chain_id=chain_id,
            contract=contract,
            delegation_key=rogue.delegation_address,
        )]
        mutation = "forbidden_session_delegation"
    elif case_id == "L07":
        presented_chain = [first, _rebuild_leaf(
            original=second,
            first=first,
            permission=second.permission,
            issuer_private_key=persistent.operation_private_key,
            chain_id=chain_id,
            contract=contract,
        )]
        mutation = "operation_key_signed_delegation"
    elif case_id == "L08":
        sibling = _wallet(AgentType.SESSION, delegable=False, network=network)
        sibling_request = dataclasses.replace(
            invocation,
            leaf_did=sibling.did,
            origin_did=sibling.did,
            signature="",
        )
        invocation = sibling.sign_invocation(
            sibling_request,
            chain_id=chain_id,
            verifying_contract=contract,
        )
        holder_private_key = sibling.operation_private_key
        holder_did = sibling.did
        mutation = "sibling_credential_impersonation"
    elif case_id == "L09":
        other_persistent = _wallet(AgentType.PERSISTENT, delegable=True, network=network)
        other_session = _wallet(AgentType.SESSION, delegable=False, network=network)
        other_first_budget = "0x" + hashlib.sha256(
            f"{experiment_id}:other-persistent-budget".encode("utf-8")
        ).hexdigest()
        other_second_budget = "0x" + hashlib.sha256(
            f"{experiment_id}:other-session-budget".encode("utf-8")
        ).hexdigest()
        other_first = create_delegation_credential(
            root_did=root_did,
            parent_did=root_did,
            parent_credential_hash=credential_hash(epoch),
            parent_lineage_commitment=credential_hash(epoch),
            child_did=other_persistent.did,
            child_operation_key=other_persistent.operation_address,
            child_delegation_key=other_persistent.delegation_address,
            agent_type=AgentType.PERSISTENT,
            version_id=VERSION,
            replica_group_id=None,
            permission=parent_permission,
            budget_id=other_first_budget,
            reservation=BudgetLimits(100, 1000, 5),
            epoch=epoch_number,
            status_ref={"chain_id": chain_id, "contract": contract},
            issuer_delegation_private_key=epoch_private_key,
            chain_id=chain_id,
            verifying_contract=contract,
        )
        other_second = create_delegation_credential(
            root_did=root_did,
            parent_did=other_persistent.did,
            parent_credential_hash=credential_hash(other_first),
            parent_lineage_commitment=other_first.lineage_commitment,
            child_did=other_session.did,
            child_operation_key=other_session.operation_address,
            child_delegation_key=None,
            agent_type=AgentType.SESSION,
            version_id=VERSION,
            replica_group_id=None,
            permission=child_permission,
            budget_id=other_second_budget,
            reservation=BudgetLimits(10, 100, 1),
            epoch=epoch_number,
            status_ref={"chain_id": chain_id, "contract": contract},
            issuer_delegation_private_key=other_persistent.delegation_private_key,
            chain_id=chain_id,
            verifying_contract=contract,
        )
        activation_steps.append((
            "register_other_persistent",
            partial(registry.register_delegation, other_first, epoch_private_key),
        ))
        activation_steps.append((
            "reserve_other_persistent_budget",
            partial(
                registry.reserve_child_budget,
                root_budget_id,
                other_first,
                epoch_private_key,
            ),
        ))
        activation_steps.append((
            "register_other_session",
            partial(
                registry.register_delegation,
                other_second,
                other_persistent.delegation_private_key,
                parent=other_first,
            ),
        ))
        activation_steps.append((
            "reserve_other_session_budget",
            partial(
                registry.reserve_child_budget,
                other_first_budget,
                other_second,
                other_persistent.delegation_private_key,
            ),
        ))
        registered_chains.append([other_first, other_second])
        other_request = dataclasses.replace(
            invocation,
            leaf_did=other_session.did,
            credential_jti=other_second.jti,
            origin_did=other_session.did,
            budget_id=other_second_budget,
            signature="",
        )
        invocation = other_session.sign_invocation(
            other_request,
            chain_id=chain_id,
            verifying_contract=contract,
        )
        presented_chain = [first, other_second]
        holder_private_key = other_session.operation_private_key
        holder_did = other_session.did
        mutation = "branch_splice"
    elif case_id == "L10":
        invocation = _resign(invocation, session, chain_id, contract, task_id="task-2")
        mutation = "cross_task_replay"
    elif case_id == "L11":
        invocation = _resign(invocation, session, chain_id, contract, audience=OTHER_AUDIENCE)
        mutation = "cross_audience_replay"
    elif case_id == "L12":
        activation_steps.append((
            "revoke_ancestor",
            partial(
                registry.revoke,
                root_did,
                "node",
                persistent.did,
                chain_private_key,
            ),
        ))
        mutation = "ancestor_revocation"
    elif case_id == "L13":
        invocation = _resign(invocation, session, chain_id, contract, origin_did=persistent.did)
        mutation = "confused_deputy"
    elif case_id == "L14":
        invocation = _resign(invocation, session, chain_id, contract, version_id=OTHER_VERSION)
        mutation = "version_substitution"

    return LineageCase(
        epoch=epoch,
        base_chain=[first, second],
        registered_chains=registered_chains,
        presented_chain=presented_chain,
        invocation=invocation,
        body=BODY,
        expected_audience=expected_audience,
        protocol_holder_private_key=holder_private_key,
        protocol_holder_did=holder_did,
        registry=registry,
        transactions=transactions,
        mutation=mutation,
        activation_steps=activation_steps,
    )
