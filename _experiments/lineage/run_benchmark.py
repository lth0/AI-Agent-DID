from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import json
import statistics
import time
from pathlib import Path

from eth_account import Account

from infrastructure.lineage import (
    AgentType,
    BudgetLimits,
    InMemoryStateProvider,
    LineageVerifier,
    LineageWallet,
    PermissionEnvelope,
    RootKeyManager,
    create_delegation_credential,
    create_epoch_certificate,
    credential_hash,
    version_did,
)
from infrastructure.lineage.crypto import ZERO_ADDRESS, did_from_address
from infrastructure.lineage.models import LineageInvocation
from infrastructure.security import canonical_json, sha256_json


CHAIN_ID = 11155111
AUDIENCE = "urn:agentlineage:benchmark"
VERSION = version_did("benchmark-agent-v1")
BODY = {"input": "benchmark"}


def build_chain(depth: int):
    started = time.perf_counter()
    now = int(time.time())
    root = Account.create()
    root_did = did_from_address(root.address)
    epoch_key = RootKeyManager(root_did, b"benchmark-root-seed" * 4).derive(1)
    epoch = create_epoch_certificate(
        root_did=root_did,
        epoch=1,
        delegation_key=Account.from_key(epoch_key).address,
        not_before=now - 10,
        expires_at=now + 86400,
        status_ref={"contract": ZERO_ADDRESS},
        root_identity_private_key=root.key.hex(),
        chain_id=CHAIN_ID,
    )
    chain = []
    parent_did = root_did
    parent_hash = credential_hash(epoch)
    parent_commitment = parent_hash
    issuer_key = epoch_key
    leaf_wallet = None
    for index in range(depth):
        remaining = depth - index - 1
        wallet = LineageWallet.generate(AgentType.CHILD, delegable=remaining > 0)
        permission = PermissionEnvelope(
            actions=("read",),
            resources=("urn:tool:benchmark",),
            tasks=("benchmark-task",),
            audiences=(AUDIENCE,),
            versions=(VERSION,),
            not_before=now - 5,
            expires_at=now + 1800,
            remaining_depth=remaining,
            delegable=remaining > 0,
        )
        credential = create_delegation_credential(
            root_did=root_did,
            parent_did=parent_did,
            parent_credential_hash=parent_hash,
            parent_lineage_commitment=parent_commitment,
            child_did=wallet.did,
            child_operation_key=wallet.operation_address,
            child_delegation_key=wallet.delegation_address,
            agent_type=AgentType.CHILD,
            version_id=VERSION,
            replica_group_id=None,
            permission=permission,
            budget_id="0x" + f"{index + 1:064x}",
            reservation=BudgetLimits(100, 1000, 10),
            epoch=1,
            status_ref={"contract": ZERO_ADDRESS},
            issuer_delegation_private_key=issuer_key,
            chain_id=CHAIN_ID,
        )
        chain.append(credential)
        parent_did = wallet.did
        parent_hash = credential_hash(credential)
        parent_commitment = credential.lineage_commitment
        issuer_key = wallet.delegation_private_key or ""
        leaf_wallet = wallet
    invocation = LineageInvocation(
        leaf_did=leaf_wallet.did,
        credential_jti=chain[-1].jti,
        origin_did=leaf_wallet.did,
        on_behalf_of=root_did,
        audience=AUDIENCE,
        task_id="benchmark-task",
        action="read",
        resource="urn:tool:benchmark",
        version_id=VERSION,
        body_hash=sha256_json(BODY),
        challenge="benchmark-challenge",
        sequence=1,
        timestamp=now,
        budget_id=chain[-1].budget_id,
        cost_units=1,
        lease_seconds=30,
    )
    invocation = leaf_wallet.sign_invocation(invocation, chain_id=CHAIN_ID)
    return epoch, chain, invocation, (time.perf_counter() - started) * 1000


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int((len(ordered) - 1) * fraction))]


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark AgentLineage issuance and verification")
    parser.add_argument("--iterations", type=int, default=20)
    args = parser.parse_args()
    verifier = LineageVerifier(
        chain_id=CHAIN_ID,
        verifying_contract=ZERO_ADDRESS,
        state_provider=InMemoryStateProvider(),
    )
    depth_results = []
    reusable = None
    for depth in (1, 2, 4, 8, 16):
        epoch, chain, invocation, issuance_ms = build_chain(depth)
        durations = []
        decision = None
        for _ in range(args.iterations):
            started = time.perf_counter()
            decision = verifier.verify(
                epoch, chain, invocation,
                expected_audience=AUDIENCE,
                expected_body_hash=sha256_json(BODY),
            )
            durations.append((time.perf_counter() - started) * 1000)
        proof_size = len(canonical_json({
            "epoch": epoch.to_dict(),
            "chain": [item.to_dict() for item in chain],
            "invocation": invocation.to_dict(),
        }).encode("utf-8"))
        depth_results.append({
            "depth": depth,
            "accepted": decision.accepted,
            "code": decision.code,
            "issuance_ms": issuance_ms,
            "verification_p50_ms": statistics.median(durations),
            "verification_p95_ms": percentile(durations, 0.95),
            "proof_bytes": proof_size,
        })
        if depth == 8:
            reusable = (epoch, chain, invocation)

    fanout_results = []
    for fanout in (1, 10, 100, 1000):
        started = time.perf_counter()
        proof_bytes = 0
        for _ in range(fanout):
            epoch, chain, invocation, _ = build_chain(1)
            proof_bytes += len(canonical_json({
                "epoch": epoch.to_dict(), "chain": [chain[0].to_dict()],
                "invocation": invocation.to_dict(),
            }).encode("utf-8"))
        elapsed = time.perf_counter() - started
        fanout_results.append({
            "fanout": fanout,
            "issuance_tps": fanout / elapsed,
            "elapsed_ms": elapsed * 1000,
            "average_proof_bytes": proof_bytes / fanout,
        })

    epoch, chain, invocation = reusable
    concurrency_results = []
    for workers in (1, 10, 100, 1000):
        executor_workers = min(workers, 128)
        started = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=executor_workers) as executor:
            decisions = list(executor.map(
                lambda _: verifier.verify(
                    epoch, chain, invocation,
                    expected_audience=AUDIENCE,
                    expected_body_hash=sha256_json(BODY),
                ),
                range(workers),
            ))
        elapsed = time.perf_counter() - started
        concurrency_results.append({
            "concurrency": workers,
            "executor_workers": executor_workers,
            "verification_tps": workers / elapsed,
            "accepted": sum(item.accepted for item in decisions),
            "elapsed_ms": elapsed * 1000,
        })

    report = {
        "schema": "agentlineage-offline-benchmark-v1",
        "depth": depth_results,
        "fanout": fanout_results,
        "concurrency": concurrency_results,
    }
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_dir = Path(".codex") / "lineage_runs"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"offline_benchmark_{timestamp}.json"
    with output_file.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
    print(json.dumps({"output_file": str(output_file), "report": report}, indent=2))


if __name__ == "__main__":
    main()
