from __future__ import annotations

import csv
import dataclasses
import datetime
import json
from pathlib import Path

from _experiments.lineage.baselines import (
    AuthorizationCase,
    FullLineageAdapter,
    IndependentDidAclAdapter,
    LineageNoBudgetAdapter,
    OpenFgaOverlayAdapter,
    OriginalAgentDidAdapter,
    PlainDelegationAdapter,
    SharedRootAdapter,
)
from _experiments.lineage.test_lineage_core import CHAIN_ID, LineageFixture
from infrastructure.lineage import (
    AgentType,
    InMemoryStateProvider,
    LineageVerifier,
    LineageWallet,
    create_delegation_credential,
    version_did,
)
from infrastructure.lineage.crypto import ZERO_ADDRESS, sign_typed_payload
from infrastructure.lineage.models import PermissionEnvelope
from infrastructure.lineage.service import LineageGateway, ToolRouter
from infrastructure.security import sha256_json


class SimulatedBudgetRegistry(InMemoryStateProvider):
    def __init__(self, **kwargs):
        super().__init__(block_number=1, **kwargs)
        self.used = set()

    def latest_block_number(self):
        return self.block_number

    def begin_invocation(self, credential, invocation):
        request_hash = sha256_json(invocation.unsigned_dict())
        if request_hash in self.used:
            raise ValueError("REQUEST_REPLAY")
        self.used.add(request_hash)
        return {"transaction_hash": "simulated-begin"}

    def finish_invocation(self, invocation):
        return {"transaction_hash": "simulated-finish"}


def resign_invocation(fixture: LineageFixture, **changes):
    request = dataclasses.replace(fixture.invocation(), signature="", **changes)
    return fixture.session.sign_invocation(request, chain_id=CHAIN_ID)


def rebuild_leaf(
    fixture: LineageFixture,
    permission: PermissionEnvelope,
    *,
    issuer_private_key: str | None = None,
    child_delegation_key: str | None = None,
):
    original = fixture.second
    return create_delegation_credential(
        root_did=original.root_did,
        parent_did=original.parent_did,
        parent_credential_hash=original.parent_credential_hash,
        parent_lineage_commitment=fixture.first.lineage_commitment,
        child_did=original.child_did,
        child_operation_key=original.operation_key,
        child_delegation_key=child_delegation_key,
        agent_type=original.agent_type,
        version_id=original.version_id,
        replica_group_id=original.replica_group_id,
        permission=permission,
        budget_id=original.budget_id,
        reservation=original.reservation,
        epoch=original.epoch,
        status_ref=original.status_ref,
        issuer_delegation_private_key=(
            issuer_private_key or fixture.persistent.delegation_private_key
        ),
        chain_id=CHAIN_ID,
        jti=original.jti,
    )


def build_cases():
    fixture = LineageFixture()
    body = {"input": "hello"}
    cases = []

    def add(name, chain, invocation, expected, state=None):
        cases.append((AuthorizationCase(
            name=name,
            epoch=fixture.epoch,
            chain=tuple(chain),
            invocation=invocation,
            body=body,
            expected_authorized=expected,
        ), state or SimulatedBudgetRegistry()))

    add("legitimate", [fixture.first, fixture.second], fixture.invocation(), True)
    add(
        "leaf_action_escalation",
        [fixture.first, fixture.second],
        resign_invocation(fixture, action="write"),
        False,
    )
    add(
        "leaf_resource_escalation",
        [fixture.first, fixture.second],
        resign_invocation(fixture, resource="urn:tool:b"),
        False,
    )
    escalated_scope = dataclasses.replace(
        fixture.second.permission,
        actions=("delete", "read"),
    )
    add(
        "delegation_scope_escalation",
        [fixture.first, rebuild_leaf(fixture, escalated_scope)],
        resign_invocation(fixture, action="delete"),
        False,
    )
    extended = dataclasses.replace(
        fixture.second.permission,
        expires_at=fixture.first.permission.expires_at + 60,
    )
    add(
        "validity_extension",
        [fixture.first, rebuild_leaf(fixture, extended)],
        fixture.invocation(),
        False,
    )
    reset_depth = dataclasses.replace(fixture.second.permission, remaining_depth=3)
    add(
        "depth_reset",
        [fixture.first, rebuild_leaf(fixture, reset_depth)],
        fixture.invocation(),
        False,
    )
    rogue_delegation_key = LineageWallet.generate(AgentType.CHILD).operation_address
    forbidden_delegation = dataclasses.replace(
        fixture.second.permission,
        remaining_depth=1,
        delegable=True,
    )
    add(
        "forbidden_session_delegation",
        [
            fixture.first,
            rebuild_leaf(
                fixture,
                forbidden_delegation,
                child_delegation_key=rogue_delegation_key,
            ),
        ],
        fixture.invocation(),
        False,
    )
    wrong_purpose = rebuild_leaf(
        fixture,
        fixture.second.permission,
        issuer_private_key=fixture.persistent.operation_private_key,
    )
    add(
        "operation_key_signed_delegation",
        [fixture.first, wrong_purpose],
        fixture.invocation(),
        False,
    )
    sibling = LineageWallet.generate(AgentType.SESSION)
    sibling_request = dataclasses.replace(fixture.invocation(), signature="")
    sibling_request = dataclasses.replace(
        sibling_request,
        signature=sign_typed_payload(
            sibling.operation_private_key,
            sibling_request.unsigned_dict(),
            purpose="AgentLineage/REQUEST/v1",
            chain_id=CHAIN_ID,
        ),
    )
    add("sibling_impersonation", [fixture.first, fixture.second], sibling_request, False)
    other = LineageFixture()
    add("branch_splice", [fixture.first, other.second], other.invocation(), False)
    add(
        "cross_task_replay",
        [fixture.first, fixture.second],
        resign_invocation(fixture, task_id="task-2"),
        False,
    )
    add(
        "cross_audience_replay",
        [fixture.first, fixture.second],
        resign_invocation(fixture, audience="urn:gateway:other"),
        False,
    )
    add(
        "ancestor_revocation",
        [fixture.first, fixture.second],
        fixture.invocation(),
        False,
        SimulatedBudgetRegistry(revoked_nodes={fixture.persistent.did}),
    )
    add(
        "confused_deputy",
        [fixture.first, fixture.second],
        resign_invocation(fixture, origin_did=fixture.persistent.did),
        False,
    )
    add(
        "version_substitution",
        [fixture.first, fixture.second],
        resign_invocation(fixture, version_id=version_did("unauthorized-version")),
        False,
    )
    return fixture, cases


def adapters_for(fixture: LineageFixture, registry: SimulatedBudgetRegistry):
    verifier = LineageVerifier(
        chain_id=CHAIN_ID,
        verifying_contract=ZERO_ADDRESS,
        state_provider=registry,
        max_state_block_lag=0,
    )
    router = ToolRouter()
    for action in ("read", "write"):
        for resource in ("urn:tool:a", "urn:tool:b"):
            router.register(action, resource, cost_units=2, handler=lambda body: body)
    acl = {fixture.session.did: {("read", "urn:tool:a")}}
    return [
        SharedRootAdapter(),
        IndependentDidAclAdapter(acl, chain_id=CHAIN_ID, contract=ZERO_ADDRESS),
        OriginalAgentDidAdapter(chain_id=CHAIN_ID, contract=ZERO_ADDRESS),
        PlainDelegationAdapter(chain_id=CHAIN_ID, contract=ZERO_ADDRESS),
        OpenFgaOverlayAdapter(
            checker=lambda user, relation, obj: (
                user == f"agent:{fixture.session.did}"
                and relation == "read"
                and obj == "resource:urn:tool:a"
            )
        ),
        LineageNoBudgetAdapter(verifier, audience="urn:gateway:test"),
        FullLineageAdapter(
            LineageGateway(verifier, registry, router, audience="urn:gateway:test")
        ),
    ]


def main() -> None:
    fixture, cases = build_cases()
    rows = []
    for case, registry in cases:
        for adapter in adapters_for(fixture, registry):
            decision = adapter.evaluate(case)
            rows.append({
                "adapter": adapter.name,
                "case": case.name,
                "expected_authorized": case.expected_authorized,
                "accepted": decision.accepted,
                "code": decision.code,
                "latency_ms": round(decision.latency_ms, 6),
            })

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_dir = Path(".codex") / "lineage_runs" / f"attack_matrix_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / "decisions.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    metrics = {}
    for adapter in sorted({row["adapter"] for row in rows}):
        selected = [row for row in rows if row["adapter"] == adapter]
        attacks = [row for row in selected if not row["expected_authorized"]]
        honest = [row for row in selected if row["expected_authorized"]]
        metrics[adapter] = {
            "pesr": sum(row["accepted"] for row in attacks) / len(attacks),
            "har": sum(row["accepted"] for row in honest) / len(honest),
            "qor": None,
        }
    report = {"schema": "agentlineage-attack-matrix-v1", "metrics": metrics, "rows": rows}
    with (output_dir / "report.json").open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)

    lineage = metrics["Lineage"]
    if lineage["pesr"] != 0 or lineage["har"] != 1:
        raise SystemExit("full Lineage adapter failed deterministic acceptance criteria")
    print(json.dumps({"output_dir": str(output_dir), "lineage": lineage}, indent=2))


if __name__ == "__main__":
    main()
