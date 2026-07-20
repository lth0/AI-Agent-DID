from __future__ import annotations

import datetime
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable

from infrastructure.security import canonical_json, sha256_json
from .credentials import (
    create_delegation_credential,
    credential_hash,
    verify_enrollment_proof,
)
from .models import (
    AgentType,
    BudgetLimits,
    DelegationCredential,
    EpochKeyCertificate,
    LineageInvocation,
    PermissionEnvelope,
    VerificationDecision,
)
from .policy import PolicyEngine
from .verifier import LineageVerifier


class ChallengeStore:
    def __init__(self, ttl_seconds: int = 120):
        self.ttl_seconds = ttl_seconds
        self._items: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    def issue(self, parent_did: str) -> dict[str, Any]:
        nonce = str(uuid.uuid4())
        now = time.time()
        with self._lock:
            self._items[nonce] = (parent_did, now + self.ttl_seconds)
        return {"nonce": nonce, "parent_did": parent_did, "expires_at": int(now + self.ttl_seconds)}

    def consume(self, nonce: str, parent_did: str) -> bool:
        now = time.time()
        with self._lock:
            item = self._items.pop(nonce, None)
            self._items = {key: value for key, value in self._items.items() if value[1] >= now}
        return bool(item and item[0] == parent_did and item[1] >= now)


class LineageAuditRecorder:
    def __init__(self, output_file: str):
        self.output_file = output_file
        self._lock = threading.Lock()
        directory = os.path.dirname(output_file)
        if directory:
            os.makedirs(directory, exist_ok=True)

    def record(self, event_type: str, accepted: bool, code: str, **metadata: Any) -> dict[str, Any]:
        event = {
            "schema_version": "agentlineage-security-v1",
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "accepted": bool(accepted),
            "code": code,
            "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "metadata": metadata,
        }
        event["evidence_hash"] = sha256_json(event)
        with self._lock:
            with open(self.output_file, "a", encoding="utf-8") as handle:
                handle.write(canonical_json(event) + "\n")
        return event


@dataclass
class ParentAuthority:
    root_did: str
    parent_did: str
    epoch: EpochKeyCertificate
    delegation_private_key: str
    permission: PermissionEnvelope
    parent_budget_id: str
    parent_credential: DelegationCredential | None = None

    @property
    def parent_hash(self) -> str:
        return credential_hash(self.parent_credential or self.epoch)

    @property
    def parent_commitment(self) -> str:
        if self.parent_credential:
            return self.parent_credential.lineage_commitment
        return credential_hash(self.epoch)


class LineageAuthority:
    def __init__(
        self,
        authority: ParentAuthority,
        registry: Any,
        *,
        chain_id: int,
        verifying_contract: str,
        policy_engine: PolicyEngine | None = None,
        audit: LineageAuditRecorder | None = None,
    ):
        self.authority = authority
        self.registry = registry
        self.chain_id = chain_id
        self.verifying_contract = verifying_contract
        self.policy_engine = policy_engine or PolicyEngine()
        self.audit = audit
        self.challenges = ChallengeStore()

    def issue_challenge(self) -> dict[str, Any]:
        return self.challenges.issue(self.authority.parent_did)

    def spawn(self, request: dict[str, Any]) -> dict[str, Any]:
        proof = dict(request["enrollment_proof"])
        nonce = str(proof.get("nonce", ""))
        if not self.challenges.consume(nonce, self.authority.parent_did):
            raise ValueError("enrollment challenge is invalid or already used")
        valid, reason = verify_enrollment_proof(
            proof,
            expected_root_did=self.authority.root_did,
            expected_parent_did=self.authority.parent_did,
            expected_nonce=nonce,
            chain_id=self.chain_id,
            verifying_contract=self.verifying_contract,
        )
        if not valid:
            raise ValueError(reason)
        agent_type = AgentType(proof["agent_type"])
        replica_group_id = request.get("replica_group_id")
        permission = self.policy_engine.attenuate(
            self.authority.permission,
            dict(request["requested_permission"]),
            agent_type,
            replica_group_id=replica_group_id,
        )
        if permission.delegable != bool(proof.get("delegation_key")):
            raise ValueError("delegation key presence does not match delegated permission")
        reservation = BudgetLimits.from_dict(request["reservation"])
        if agent_type is AgentType.INSTANCE:
            budget_id = request.get("budget_id") or "0x" + sha256_json({
                "domain": "AgentLineage/REPLICA_GROUP_BUDGET/v1",
                "root_did": self.authority.root_did,
                "parent_budget_id": self.authority.parent_budget_id,
                "replica_group_id": replica_group_id,
            })
            reservation_tx = self.registry.ensure_replica_group_budget(
                self.authority.parent_budget_id,
                replica_group_id,
                budget_id,
                reservation,
                self.authority.delegation_private_key,
            )
        else:
            budget_id = request.get("budget_id") or "0x" + os.urandom(32).hex()
            reservation_tx = None
        status_ref = {
            "chain_id": self.chain_id,
            "contract": self.verifying_contract,
        }
        credential = create_delegation_credential(
            root_did=self.authority.root_did,
            parent_did=self.authority.parent_did,
            parent_credential_hash=self.authority.parent_hash,
            parent_lineage_commitment=self.authority.parent_commitment,
            child_did=proof["child_did"],
            child_operation_key=proof["operation_key"],
            child_delegation_key=proof.get("delegation_key"),
            agent_type=agent_type,
            version_id=request["version_id"],
            replica_group_id=replica_group_id,
            permission=permission,
            budget_id=budget_id,
            reservation=reservation,
            epoch=self.authority.epoch.epoch,
            status_ref=status_ref,
            issuer_delegation_private_key=self.authority.delegation_private_key,
            chain_id=self.chain_id,
            verifying_contract=self.verifying_contract,
        )
        registration = self.registry.register_delegation(
            credential,
            self.authority.delegation_private_key,
            parent=self.authority.parent_credential,
        )
        if reservation_tx is None:
            reservation_tx = self.registry.reserve_child_budget(
                self.authority.parent_budget_id,
                credential,
                self.authority.delegation_private_key,
            )
        if self.audit:
            self.audit.record(
                "delegation_issued", True, "DELEGATION_ISSUED",
                credential_hash=credential_hash(credential), child_did=credential.child_did,
                chain_depth=self.authority.permission.remaining_depth - permission.remaining_depth,
                registration_tx=registration["transaction_hash"],
                reservation_tx=reservation_tx["transaction_hash"],
            )
        return {
            "credential": credential.to_dict(),
            "registration": registration,
            "reservation": reservation_tx,
        }


class ToolRouter:
    def __init__(self):
        self._routes: dict[tuple[str, str], tuple[int, Callable[[Any], Any]]] = {}

    def register(self, action: str, resource: str, *, cost_units: int, handler: Callable[[Any], Any]) -> None:
        if cost_units < 0:
            raise ValueError("cost_units must be non-negative")
        self._routes[(action, resource)] = (cost_units, handler)

    def resolve(self, action: str, resource: str) -> tuple[int, Callable[[Any], Any]]:
        try:
            return self._routes[(action, resource)]
        except KeyError as exc:
            raise ValueError("tool route is not registered") from exc


class LineageGateway:
    def __init__(
        self,
        verifier: LineageVerifier,
        registry: Any,
        router: ToolRouter,
        *,
        audience: str,
        audit: LineageAuditRecorder | None = None,
    ):
        self.verifier = verifier
        self.registry = registry
        self.router = router
        self.audience = audience
        self.audit = audit

    def invoke(self, request: dict[str, Any]) -> dict[str, Any]:
        epoch = EpochKeyCertificate.from_dict(request["epoch_certificate"])
        chain = [DelegationCredential.from_dict(item) for item in request["delegation_chain"]]
        invocation = LineageInvocation.from_dict(request["invocation"])
        body = request.get("body")
        expected_cost, handler = self.router.resolve(invocation.action, invocation.resource)
        if invocation.cost_units != expected_cost:
            decision = VerificationDecision(False, "COST_MISMATCH", "request cost does not match gateway tariff")
            self._record(decision, invocation, chain)
            return {"decision": decision.to_dict()}
        decision = self.verifier.verify(
            epoch, chain, invocation,
            expected_audience=self.audience,
            expected_body_hash=sha256_json(body),
        )
        if not decision.accepted:
            self._record(decision, invocation, chain)
            return {"decision": decision.to_dict()}
        try:
            begin = self.registry.begin_invocation(chain[-1], invocation)
        except Exception as exc:
            rejected = VerificationDecision(
                False, "BUDGET_REJECTED", "on-chain budget or replay check rejected the request",
                chain_depth=decision.chain_depth,
                effective_permission=decision.effective_permission,
            )
            self._record(rejected, invocation, chain, error_type=type(exc).__name__)
            return {"decision": rejected.to_dict()}
        try:
            output = handler(body)
        except Exception as exc:
            try:
                finish = self.registry.finish_invocation(invocation)
            except Exception as finish_exc:
                failure = VerificationDecision(
                    False, "LEASE_RELEASE_FAILED",
                    "tool failed and the invocation lease requires on-chain reaping",
                    chain_depth=decision.chain_depth,
                    effective_permission=decision.effective_permission,
                    budget_tx_hash=begin["transaction_hash"],
                )
                self._record(
                    failure, invocation, chain, error_type=type(exc).__name__,
                    finish_error_type=type(finish_exc).__name__,
                )
                return {"decision": failure.to_dict(), "budget_begin": begin}
            failure = VerificationDecision(
                False, "TOOL_EXECUTION_FAILED", "tool execution failed after budget debit",
                chain_depth=decision.chain_depth,
                effective_permission=decision.effective_permission,
                budget_tx_hash=begin["transaction_hash"],
            )
            self._record(
                failure, invocation, chain,
                finish_tx=finish["transaction_hash"], error_type=type(exc).__name__,
            )
            return {
                "decision": failure.to_dict(),
                "budget_begin": begin,
                "budget_finish": finish,
            }
        try:
            finish = self.registry.finish_invocation(invocation)
        except Exception as exc:
            failure = VerificationDecision(
                False, "LEASE_RELEASE_FAILED",
                "tool executed but the invocation lease requires on-chain reaping",
                chain_depth=decision.chain_depth,
                effective_permission=decision.effective_permission,
                budget_tx_hash=begin["transaction_hash"],
            )
            self._record(failure, invocation, chain, error_type=type(exc).__name__)
            return {"decision": failure.to_dict(), "budget_begin": begin}
        final_decision = VerificationDecision(
            True, "ACCEPTED", "lineage verified and invocation executed",
            chain_depth=decision.chain_depth,
            effective_permission=decision.effective_permission,
            budget_tx_hash=begin["transaction_hash"],
        )
        self._record(final_decision, invocation, chain, finish_tx=finish["transaction_hash"])
        return {
            "decision": final_decision.to_dict(),
            "output": output,
            "budget_begin": begin,
            "budget_finish": finish,
        }

    def _record(
        self,
        decision: VerificationDecision,
        invocation: LineageInvocation,
        chain: list[DelegationCredential],
        **metadata: Any,
    ) -> None:
        if self.audit:
            self.audit.record(
                "lineage_invocation", decision.accepted, decision.code,
                request_hash=sha256_json(invocation.unsigned_dict()),
                leaf_did=invocation.leaf_did, chain_depth=len(chain), **metadata,
            )


def default_tool_router() -> ToolRouter:
    router = ToolRouter()
    router.register("echo", "urn:agentlineage:tool:echo", cost_units=1, handler=lambda body: body)
    router.register(
        "hash", "urn:agentlineage:tool:sha256", cost_units=2,
        handler=lambda body: sha256_json(body),
    )
    return router
