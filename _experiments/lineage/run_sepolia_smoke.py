from __future__ import annotations

import argparse
import datetime
import json
import os
import time
import uuid
from pathlib import Path

from infrastructure.lineage import (
    AgentType,
    DelegationCredential,
    EpochKeyCertificate,
    LineageInvocation,
    LineageVerifier,
    LineageWallet,
    PermissionEnvelope,
    RootKeyManager,
    version_did,
)
from infrastructure.lineage.runtime import (
    DEFAULT_CONFIG,
    DEFAULT_STATE,
    LineageRuntimeConfig,
    require_private_key,
)
from infrastructure.lineage.service import (
    LineageAuditRecorder,
    LineageAuthority,
    LineageGateway,
    ParentAuthority,
    default_tool_router,
)
from infrastructure.security import sha256_json
from _ops_services.setup_lineage_root import initialize_root, rotate_root


def signed_invocation(
    wallet: LineageWallet,
    credential: DelegationCredential,
    *,
    root_did: str,
    audience: str,
    version_id: str,
    action: str,
    resource: str,
    body: dict,
    cost_units: int,
    sequence: int,
    chain_id: int,
    contract: str,
) -> LineageInvocation:
    invocation = LineageInvocation(
        leaf_did=wallet.did,
        credential_jti=credential.jti,
        origin_did=wallet.did,
        on_behalf_of=root_did,
        audience=audience,
        task_id="sepolia-smoke",
        action=action,
        resource=resource,
        version_id=version_id,
        body_hash=sha256_json(body),
        challenge=str(uuid.uuid4()),
        sequence=sequence,
        timestamp=int(time.time()),
        budget_id=credential.budget_id,
        cost_units=cost_units,
        lease_seconds=60,
    )
    return wallet.sign_invocation(
        invocation,
        chain_id=chain_id,
        verifying_contract=contract,
    )


def invoke(gateway, epoch, chain, invocation, body):
    return gateway.invoke({
        "epoch_certificate": epoch.to_dict(),
        "delegation_chain": [item.to_dict() for item in chain],
        "invocation": invocation.to_dict(),
        "body": body,
    })


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the AgentLineage Sepolia acceptance smoke test")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--state", default=str(DEFAULT_STATE))
    args = parser.parse_args()
    config = LineageRuntimeConfig.load(args.config)
    root_private_key = require_private_key("AGENTLINEAGE_ROOT_IDENTITY_KEY")
    require_private_key("AGENTLINEAGE_RELAYER_KEY")
    if not os.getenv("AGENTLINEAGE_ROOT_SEED"):
        raise SystemExit("AGENTLINEAGE_ROOT_SEED is required")

    registry = config.registry()
    if Path(args.state).exists():
        state = rotate_root(args.config, args.state)
    else:
        state = initialize_root(args.config, args.state, 1)
    epoch = EpochKeyCertificate.from_dict(state["epoch_certificate"])
    epoch_key = RootKeyManager.from_environment(epoch.root_did).derive(epoch.epoch)
    audit = LineageAuditRecorder(
        str(Path(".codex") / "lineage" / "audit" / "sepolia_smoke.jsonl")
    )
    root_authority = LineageAuthority(
        ParentAuthority(
            root_did=epoch.root_did,
            parent_did=epoch.root_did,
            epoch=epoch,
            delegation_private_key=epoch_key,
            permission=PermissionEnvelope.from_dict(state["permission"]),
            parent_budget_id=state["parent_budget_id"],
        ),
        registry,
        chain_id=config.chain_id,
        verifying_contract=config.registry_address,
        audit=audit,
    )

    now = int(time.time())
    audience = config.raw["gateway_audience"]
    version_id = version_did("sepolia-smoke-agent-v1")
    persistent_wallet = LineageWallet.generate(AgentType.PERSISTENT, delegable=True)
    challenge = root_authority.issue_challenge()
    persistent_result = root_authority.spawn({
        "enrollment_proof": persistent_wallet.create_enrollment_proof(
            root_did=epoch.root_did,
            parent_did=epoch.root_did,
            nonce=challenge["nonce"],
            timestamp=now,
            chain_id=config.chain_id,
            verifying_contract=config.registry_address,
        ),
        "version_id": version_id,
        "requested_permission": {
            "actions": ["echo"],
            "resources": ["urn:agentlineage:tool:echo"],
            "tasks": ["sepolia-smoke"],
            "audiences": [audience],
            "versions": [version_id],
            "expires_at": now + 3600,
            "remaining_depth": 1,
            "delegable": True,
        },
        "reservation": {"calls": 10, "cost_units": 100, "concurrency": 2},
    })
    persistent = DelegationCredential.from_dict(persistent_result["credential"])

    child_authority = LineageAuthority(
        ParentAuthority(
            root_did=epoch.root_did,
            parent_did=persistent.child_did,
            epoch=epoch,
            delegation_private_key=persistent_wallet.delegation_private_key,
            permission=persistent.permission,
            parent_budget_id=persistent.budget_id,
            parent_credential=persistent,
        ),
        registry,
        chain_id=config.chain_id,
        verifying_contract=config.registry_address,
        audit=audit,
    )
    session_wallet = LineageWallet.generate(AgentType.SESSION)
    challenge = child_authority.issue_challenge()
    session_result = child_authority.spawn({
        "enrollment_proof": session_wallet.create_enrollment_proof(
            root_did=epoch.root_did,
            parent_did=persistent.child_did,
            nonce=challenge["nonce"],
            timestamp=int(time.time()),
            chain_id=config.chain_id,
            verifying_contract=config.registry_address,
        ),
        "version_id": version_id,
        "requested_permission": {
            "expires_at": now + 1200,
            "remaining_depth": 0,
            "delegable": False,
        },
        "reservation": {"calls": 2, "cost_units": 2, "concurrency": 1},
    })
    session = DelegationCredential.from_dict(session_result["credential"])

    verifier = LineageVerifier(
        chain_id=config.chain_id,
        verifying_contract=config.registry_address,
        state_provider=registry,
        max_request_age_seconds=120,
        max_state_block_lag=int(config.raw.get("max_state_block_lag", 2)),
    )
    gateway = LineageGateway(
        verifier, registry, default_tool_router(), audience=audience, audit=audit
    )
    chain = [persistent, session]
    body = {"message": "sepolia smoke"}
    legitimate_1 = invoke(
        gateway, epoch, chain,
        signed_invocation(
            session_wallet, session, root_did=epoch.root_did,
            audience=audience, version_id=version_id, action="echo",
            resource="urn:agentlineage:tool:echo", body=body,
            cost_units=1, sequence=1, chain_id=config.chain_id,
            contract=config.registry_address,
        ),
        body,
    )
    over_scope = invoke(
        gateway, epoch, chain,
        signed_invocation(
            session_wallet, session, root_did=epoch.root_did,
            audience=audience, version_id=version_id, action="hash",
            resource="urn:agentlineage:tool:sha256", body=body,
            cost_units=2, sequence=100, chain_id=config.chain_id,
            contract=config.registry_address,
        ),
        body,
    )
    legitimate_2 = invoke(
        gateway, epoch, chain,
        signed_invocation(
            session_wallet, session, root_did=epoch.root_did,
            audience=audience, version_id=version_id, action="echo",
            resource="urn:agentlineage:tool:echo", body=body,
            cost_units=1, sequence=2, chain_id=config.chain_id,
            contract=config.registry_address,
        ),
        body,
    )
    exhausted = invoke(
        gateway, epoch, chain,
        signed_invocation(
            session_wallet, session, root_did=epoch.root_did,
            audience=audience, version_id=version_id, action="echo",
            resource="urn:agentlineage:tool:echo", body=body,
            cost_units=1, sequence=3, chain_id=config.chain_id,
            contract=config.registry_address,
        ),
        body,
    )
    revoke_tx = registry.revoke(
        epoch.root_did, "node", persistent.child_did, root_private_key
    )
    revoked = invoke(
        gateway, epoch, chain,
        signed_invocation(
            session_wallet, session, root_did=epoch.root_did,
            audience=audience, version_id=version_id, action="echo",
            resource="urn:agentlineage:tool:echo", body=body,
            cost_units=1, sequence=4, chain_id=config.chain_id,
            contract=config.registry_address,
        ),
        body,
    )

    decisions = {
        "legitimate_1": legitimate_1["decision"],
        "over_scope": over_scope["decision"],
        "legitimate_2": legitimate_2["decision"],
        "budget_exhausted": exhausted["decision"],
        "ancestor_revoked": revoked["decision"],
    }
    expected = {
        "legitimate_1": (True, "ACCEPTED"),
        "over_scope": (False, "PERMISSION_DENIED"),
        "legitimate_2": (True, "ACCEPTED"),
        "budget_exhausted": (False, "BUDGET_REJECTED"),
        "ancestor_revoked": (False, "STATUS_REVOKED"),
    }
    for name, (accepted, code) in expected.items():
        if decisions[name]["accepted"] is not accepted or decisions[name]["code"] != code:
            raise SystemExit(f"Sepolia smoke assertion failed for {name}: {decisions[name]}")

    report = {
        "schema": "agentlineage-sepolia-smoke-v1",
        "chain_id": config.chain_id,
        "registry_address": config.registry_address,
        "root_did": epoch.root_did,
        "credential_chain": [persistent.jti, session.jti],
        "decisions": decisions,
        "transactions": {
            "root": state["transactions"],
            "persistent": {
                "registration": persistent_result["registration"],
                "reservation": persistent_result["reservation"],
            },
            "session": {
                "registration": session_result["registration"],
                "reservation": session_result["reservation"],
            },
            "revoke_ancestor": revoke_tx,
        },
        "leaf_budget": registry.get_status(session.budget_id),
    }
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = Path(".codex") / "lineage_runs" / f"sepolia_smoke_{timestamp}.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
    print(json.dumps({
        "output": str(output),
        "registry_address": config.registry_address,
        "root_did": epoch.root_did,
        "decisions": {name: value["code"] for name, value in decisions.items()},
    }, indent=2))


if __name__ == "__main__":
    main()
