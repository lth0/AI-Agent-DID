"""Run the complete 21-case by 3-scheme AgentDID comparison matrix."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import subprocess
import sys
import time
import uuid
from collections import Counter
from pathlib import Path
from typing import Any, Callable
from web3 import Web3

from _experiments.security_comparison.cases import (
    CASE_BY_ID,
    LINEAGE_ROBUSTNESS_CASE_IDS,
    ROBUSTNESS_CASE_IDS,
    SCHEME_DIRECTORIES,
    SCHEME_LABELS,
    SCHEMES,
    expected_outcome,
)
from _experiments.security_comparison.chain import (
    ChainConfig,
    HardhatNode,
    configure_did_registry,
    decode_lineage_events,
    deploy_local_contracts,
    load_actor_keys,
    local_config,
    sepolia_config,
)
from _experiments.security_comparison.cli_common import redact_rpc_text, run_id_argument
from _experiments.security_comparison.evidence import read_json, write_json
from _experiments.security_comparison.preflight import (
    DID_SETUP_GAS_UPPER_BOUND_PER_CONTROLLER,
    FULL_LINEAGE_GAS_LIMIT_PER_TRANSACTION,
    run_sepolia_full_preflight,
)
from _experiments.security_comparison.run_lineage_phase1 import _semantics_report
from _experiments.security_comparison.run_robustness import (
    _collect_result as collect_experiment_result,
    _isolation_report as build_isolation_report,
    _verify_evidence as verify_evidence,
)
from infrastructure.evidence_anchor import EthereumEvidenceAnchor
from infrastructure.security import sha256_json


PROJECT_ROOT = Path(__file__).resolve().parents[2]
FULL_CASE_IDS = (
    "H00",
    *ROBUSTNESS_CASE_IDS,
    *LINEAGE_ROBUSTNESS_CASE_IDS,
)
FULL_EXPERIMENT_COUNT = len(FULL_CASE_IDS) * len(SCHEMES)


def _positive_seconds(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("timeout must be greater than zero")
    return parsed


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run all 63 isolated AgentDID comparison experiments",
    )
    parser.add_argument(
        "--run-id",
        type=run_id_argument,
        default="full-" + uuid.uuid4().hex[:12],
    )
    parser.add_argument("--chain", choices=("hardhat", "sepolia"), default="hardhat")
    parser.add_argument(
        "--sepolia",
        action="store_true",
        help="alias for --chain sepolia",
    )
    parser.add_argument(
        "--output-root",
        default=str(PROJECT_ROOT / ".codex" / "comparison_runs"),
    )
    parser.add_argument(
        "--temp-root",
        default=str(PROJECT_ROOT / ".codex" / "comparison_tmp"),
    )
    parser.add_argument(
        "--timeout-seconds",
        type=_positive_seconds,
        default=900.0,
        help="maximum runtime for each child experiment",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="stop scheduling after the first failed child (debugging only)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the fixed 63-item plan without starting a chain",
    )
    args = parser.parse_args(argv)
    if args.sepolia:
        args.chain = "sepolia"
    return args


def build_full_plan(run_id: str) -> list[dict[str, Any]]:
    """Return the stable, complete 63-item execution plan."""

    plan: list[dict[str, Any]] = []
    ordinal = 0
    for case_id in FULL_CASE_IDS:
        case = CASE_BY_ID[case_id]
        for scheme in SCHEMES:
            ordinal += 1
            expected = expected_outcome(scheme, case_id)
            plan.append({
                "ordinal": ordinal,
                "scheme": scheme,
                "scheme_label": SCHEME_LABELS[scheme],
                "case_id": case_id,
                "case_name": case.name,
                "case_family": case.family,
                "experiment_id": (
                    f"{run_id}-{ordinal:02d}-{scheme}-{case_id.lower()}"
                ),
                "lineage_epoch": ordinal,
                "expected_accepted": expected.accepted,
                "expected_code": expected.code,
                "expected_detection_layer": expected.detection_layer,
            })
    if len(plan) != FULL_EXPERIMENT_COUNT:
        raise RuntimeError("FULL_PLAN_SIZE_MISMATCH")
    return plan


def build_child_command(
    item: dict[str, Any],
    *,
    run_id: str,
    output_root: Path,
    temp_root: Path,
    chain: ChainConfig,
    full_preflight_path: Path | None = None,
    full_preflight_hash: str | None = None,
) -> list[str]:
    """Build one child command without exposing RPC credentials."""

    command = [
        sys.executable,
        "-B",
        "-m",
        "_experiments.security_comparison.run_one",
        "--scheme",
        str(item["scheme"]),
        "--case",
        str(item["case_id"]),
        "--run-id",
        run_id,
        "--experiment-id",
        str(item["experiment_id"]),
        "--chain",
        chain.backend,
        "--chain-id",
        str(chain.chain_id),
        "--did-registry",
        chain.did_registry_address,
        "--lineage-registry",
        chain.lineage_registry_address,
        "--confirmations",
        str(chain.confirmations),
        "--rpc-timeout-seconds",
        str(chain.rpc_timeout_seconds),
        "--lineage-epoch",
        str(item["lineage_epoch"]),
        "--output-root",
        str(output_root),
        "--temp-root",
        str(temp_root),
    ]
    if full_preflight_path is not None or full_preflight_hash is not None:
        if full_preflight_path is None or full_preflight_hash is None:
            raise ValueError("full preflight path and hash must be supplied together")
        command.extend([
            "--full-preflight",
            str(full_preflight_path),
            "--full-preflight-hash",
            full_preflight_hash,
        ])
    return command


def _experiment_directory(
    output_root: Path,
    run_id: str,
    item: dict[str, Any],
) -> Path:
    return (
        output_root
        / run_id
        / "experiments"
        / SCHEME_DIRECTORIES[str(item["scheme"])]
        / str(item["case_id"])
    )


def _infrastructure_result(
    item: dict[str, Any],
    output_root: Path,
    run_id: str,
    *,
    code: str,
    reason: str,
    return_code: int = 1,
) -> dict[str, Any]:
    return {
        **item,
        "status": "INFRA_ERROR",
        "accepted": None,
        "passed": False,
        "code": code,
        "reason": reason,
        "detection_layer": "infrastructure",
        "return_code": return_code,
        "anchor_matches": False,
        "anchor_transaction": None,
        "anchor_merkle_root": None,
        "output": str(_experiment_directory(output_root, run_id, item)),
    }


def _chain_activity(directory: Path) -> dict[str, Any]:
    path = directory / "chain-activity.json"
    if not path.exists():
        return {
            "transaction_count": 0,
            "event_count": 0,
            "gas_used": 0,
            "event_names": [],
            "chain": {},
        }
    artifact = read_json(path)
    transactions = artifact.get("transactions") or []
    events = artifact.get("lineage_events") or []
    return {
        "transaction_count": len(transactions),
        "event_count": len(events),
        "gas_used": sum(int(item.get("gas_used") or 0) for item in transactions),
        "event_names": [str(item.get("event")) for item in events],
        "chain": artifact.get("chain") or {},
    }


def _expected_lineage_activity(scheme: str, case_id: str) -> int:
    if scheme != "lineage":
        return 0
    if case_id in ROBUSTNESS_CASE_IDS:
        return 0
    if case_id == "H00":
        return 8
    if case_id == "L09":
        return 10
    if case_id == "L12":
        return 7
    return 6


def _expected_lineage_events(scheme: str, case_id: str) -> Counter[str]:
    if scheme != "lineage" or case_id in ROBUSTNESS_CASE_IDS:
        return Counter()
    expected = Counter({
        "BudgetCreated": 3,
        "DelegationRegistered": 2,
    })
    if case_id == "H00":
        expected.update({"InvocationStarted": 1, "InvocationFinished": 1})
    elif case_id == "L09":
        expected.update({"BudgetCreated": 2, "DelegationRegistered": 2})
    elif case_id == "L12":
        expected.update({"StatusRevoked": 1})
    return expected


def _enrich_chain_shape(
    result: dict[str, Any],
    expected_chain: ChainConfig | None = None,
) -> dict[str, Any]:
    activity = _chain_activity(Path(str(result["output"])))
    expected_count = _expected_lineage_activity(
        str(result["scheme"]),
        str(result["case_id"]),
    )
    event_names = activity["event_names"]
    observed_events = Counter(event_names)
    root_events = observed_events.pop("RootRegistered", 0) + observed_events.pop(
        "EpochRotated", 0
    )
    expected_events = _expected_lineage_events(
        str(result["scheme"]),
        str(result["case_id"]),
    )
    exact_event_shape = bool(
        root_events == (1 if expected_count else 0)
        and observed_events == expected_events
    )
    chain_matches = True
    if expected_chain is not None:
        actual_chain = activity["chain"]
        chain_matches = bool(
            actual_chain.get("backend") == expected_chain.backend
            and int(actual_chain.get("chain_id", -1)) == expected_chain.chain_id
            and str(actual_chain.get("did_registry_address", "")).lower()
            == expected_chain.did_registry_address.lower()
            and str(actual_chain.get("lineage_registry_address", "")).lower()
            == expected_chain.lineage_registry_address.lower()
        )
    result.update({
        "lineage_transaction_count": activity["transaction_count"],
        "lineage_event_count": activity["event_count"],
        "lineage_gas_used": activity["gas_used"],
        "lineage_event_names": event_names,
        "expected_lineage_activity_count": expected_count,
        "chain_config_matches_parent": chain_matches,
        "lineage_event_multiset_matches": exact_event_shape,
        "lineage_chain_shape_passed": bool(
            activity["transaction_count"] == expected_count
            and activity["event_count"] == expected_count
            and exact_event_shape
            and chain_matches
        ),
    })
    return result


def _write_decisions_csv(path: Path, results: list[dict[str, Any]]) -> None:
    fields = (
        "ordinal",
        "experiment_id",
        "scheme",
        "scheme_label",
        "case_id",
        "case_name",
        "case_family",
        "status",
        "accepted",
        "passed",
        "code",
        "detection_layer",
        "return_code",
        "anchor_matches",
        "anchor_transaction",
        "anchor_merkle_root",
        "lineage_transaction_count",
        "lineage_event_count",
        "lineage_gas_used",
        "duration_ms",
        "output",
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)


def _write_comparison_csv(path: Path, results: list[dict[str, Any]]) -> None:
    by_key = {
        (str(item["case_id"]), str(item["scheme"])): item
        for item in results
    }
    fields = ["case_id", "case_name", "case_family"]
    for scheme in SCHEMES:
        fields.extend([
            f"{scheme}_status",
            f"{scheme}_accepted",
            f"{scheme}_code",
            f"{scheme}_detection_layer",
            f"{scheme}_passed",
        ])
    rows = []
    for case_id in FULL_CASE_IDS:
        case = CASE_BY_ID[case_id]
        row: dict[str, Any] = {
            "case_id": case_id,
            "case_name": case.name,
            "case_family": case.family,
        }
        for scheme in SCHEMES:
            result = by_key.get((case_id, scheme), {})
            row.update({
                f"{scheme}_status": result.get("status", "NOT_RUN"),
                f"{scheme}_accepted": result.get("accepted"),
                f"{scheme}_code": result.get("code"),
                f"{scheme}_detection_layer": result.get("detection_layer"),
                f"{scheme}_passed": result.get("passed", False),
            })
        rows.append(row)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _scheme_metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    metrics: dict[str, Any] = {}
    for scheme in SCHEMES:
        items = [item for item in results if item["scheme"] == scheme]
        completed = sum(item["status"] == "COMPLETED" for item in items)
        passed = sum(bool(item["passed"]) for item in items)
        metrics[scheme] = {
            "planned": len(FULL_CASE_IDS),
            "executed": len(items),
            "completed": completed,
            "accepted": sum(item["accepted"] is True for item in items),
            "rejected": sum(item["accepted"] is False for item in items),
            "passed": passed,
            "response_conformance_rate": (
                passed / completed if completed else 0.0
            ),
        }
    return metrics


def _case_metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        case_id: {
            "planned": len(SCHEMES),
            "executed": sum(item["case_id"] == case_id for item in results),
            "completed": sum(
                item["case_id"] == case_id and item["status"] == "COMPLETED"
                for item in results
            ),
            "passed": sum(
                item["case_id"] == case_id and bool(item["passed"])
                for item in results
            ),
        }
        for case_id in FULL_CASE_IDS
    }


def _live_anchor_verification(
    chain: ChainConfig,
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    try:
        actor_keys = load_actor_keys(chain.backend)
        verifier = EthereumEvidenceAnchor(
            chain.rpc_url,
            actor_keys.chain_private_key,
            request_timeout_seconds=chain.rpc_timeout_seconds,
            receipt_timeout_seconds=max(600.0, chain.rpc_timeout_seconds * 10),
        )
        verifier_address = verifier.account.address.lower()
        actual_chain_id = int(verifier.w3.eth.chain_id)
        latest_block = int(verifier.w3.eth.block_number)
        for result in results:
            transaction_hash = result.get("anchor_transaction")
            merkle_root = result.get("anchor_merkle_root")
            if not transaction_hash or not merkle_root:
                checks.append({
                    "experiment_id": result["experiment_id"],
                    "passed": False,
                    "code": "ANCHOR_REFERENCE_MISSING",
                })
                continue
            try:
                verified = verifier.verify_transaction(
                    str(transaction_hash),
                    str(merkle_root),
                )
                receipt = verifier.w3.eth.get_transaction_receipt(transaction_hash)
                block_number = verified.get("block_number")
                confirmations_observed = (
                    latest_block - int(block_number) + 1
                    if block_number is not None
                    else 0
                )
                chain_matches = bool(
                    actual_chain_id == chain.chain_id
                    and int(verified.get("chain_id") or -1) == chain.chain_id
                )
                sender_matches = str(verified.get("from") or "").lower() == verifier_address
                recipient_matches = str(verified.get("to") or "").lower() == verifier_address
                confirmation_matches = confirmations_observed >= chain.confirmations
                passed = bool(
                    verified["matches"]
                    and int(receipt.status) == 1
                    and chain_matches
                    and sender_matches
                    and recipient_matches
                    and confirmation_matches
                )
                gas_used = int(receipt.gasUsed)
                effective_gas_price = int(receipt.get("effectiveGasPrice") or 0)
                checks.append({
                    "experiment_id": result["experiment_id"],
                    "transaction_hash": transaction_hash,
                    "merkle_root": merkle_root,
                    "block_number": block_number,
                    "receipt_status": int(receipt.status),
                    "chain_id_matches": chain_matches,
                    "sender_matches": sender_matches,
                    "recipient_matches": recipient_matches,
                    "confirmations_required": chain.confirmations,
                    "confirmations_observed": confirmations_observed,
                    "gas_used": gas_used,
                    "effective_gas_price": effective_gas_price,
                    "actual_cost_wei": gas_used * effective_gas_price,
                    "passed": passed,
                })
            except Exception as exc:
                checks.append({
                    "experiment_id": result["experiment_id"],
                    "transaction_hash": transaction_hash,
                    "passed": False,
                    "code": "ANCHOR_REVERSE_VERIFICATION_FAILED",
                    "reason": type(exc).__name__,
                })
    except Exception as exc:
        return {
            "passed": False,
            "verified": 0,
            "expected": FULL_EXPERIMENT_COUNT,
            "code": "ANCHOR_VERIFIER_UNAVAILABLE",
            "reason": type(exc).__name__,
            "checks": checks,
        }
    return {
        "passed": bool(
            len(checks) == FULL_EXPERIMENT_COUNT
            and all(item["passed"] for item in checks)
        ),
        "verified": sum(bool(item["passed"]) for item in checks),
        "expected": FULL_EXPERIMENT_COUNT,
        "actual_cost_wei": sum(
            int(item.get("actual_cost_wei") or 0) for item in checks
        ),
        "checks": checks,
    }


def _live_protocol_transaction_verification(
    chain: ChainConfig,
    results: list[dict[str, Any]],
    did_setup: dict[str, Any] | None,
) -> dict[str, Any]:
    """Re-query DID and Lineage receipts from the canonical chain at run end."""

    checks: list[dict[str, Any]] = []
    event_checks: list[dict[str, Any]] = []
    try:
        w3 = Web3(Web3.HTTPProvider(
            chain.rpc_url,
            request_kwargs={"timeout": chain.rpc_timeout_seconds},
        ))
        if not w3.is_connected() or int(w3.eth.chain_id) != chain.chain_id:
            raise RuntimeError("CHAIN_REVERIFICATION_CONNECTION_MISMATCH")
        latest_block = int(w3.eth.block_number)
        actor_keys = load_actor_keys(chain.backend)
        relayer = actor_keys.chain_private_key
        relayer_address = w3.eth.account.from_key(relayer).address

        def check_transaction(
            *,
            category: str,
            experiment_id: str,
            recorded: dict[str, Any],
            expected_sender: str,
            expected_recipient: str,
        ) -> None:
            tx_hash = str(recorded.get("transaction_hash") or "")
            if not tx_hash:
                checks.append({
                    "category": category,
                    "experiment_id": experiment_id,
                    "passed": False,
                    "code": "TRANSACTION_HASH_MISSING",
                })
                return
            try:
                transaction = w3.eth.get_transaction(tx_hash)
                receipt = w3.eth.get_transaction_receipt(tx_hash)
                confirmations_observed = latest_block - int(receipt.blockNumber) + 1
                recorded_block_hash = str(recorded.get("block_hash") or "").lower()
                canonical_block_hash = receipt.blockHash.hex().lower()
                optional_chain_id = transaction.get("chainId")
                transaction_chain_matches = bool(
                    optional_chain_id is None
                    or int(optional_chain_id) == chain.chain_id
                )
                passed = bool(
                    int(receipt.status) == 1
                    and int(recorded.get("block_number", -1)) == int(receipt.blockNumber)
                    and recorded_block_hash == canonical_block_hash
                    and str(transaction.get("from") or "").lower()
                    == expected_sender.lower()
                    and str(transaction.get("to") or "").lower()
                    == expected_recipient.lower()
                    and confirmations_observed >= chain.confirmations
                    and transaction_chain_matches
                )
                gas_used = int(receipt.gasUsed)
                effective_gas_price = int(receipt.get("effectiveGasPrice") or 0)
                checks.append({
                    "category": category,
                    "experiment_id": experiment_id,
                    "transaction_hash": tx_hash,
                    "block_number": int(receipt.blockNumber),
                    "block_hash": canonical_block_hash,
                    "status": int(receipt.status),
                    "sender_matches": str(transaction.get("from") or "").lower()
                    == expected_sender.lower(),
                    "recipient_matches": str(transaction.get("to") or "").lower()
                    == expected_recipient.lower(),
                    "transaction_chain_matches": transaction_chain_matches,
                    "confirmations_observed": confirmations_observed,
                    "confirmations_required": chain.confirmations,
                    "gas_used": gas_used,
                    "effective_gas_price": effective_gas_price,
                    "actual_cost_wei": gas_used * effective_gas_price,
                    "passed": passed,
                })
            except Exception as exc:
                checks.append({
                    "category": category,
                    "experiment_id": experiment_id,
                    "transaction_hash": tx_hash,
                    "passed": False,
                    "code": "TRANSACTION_REVERSE_VERIFICATION_FAILED",
                    "reason": type(exc).__name__,
                })

        identities = actor_keys.identities(chain.chain_id)
        for item in (did_setup or {}).get("transactions", []):
            recorded = item.get("transaction")
            if not recorded:
                continue
            role = str(item.get("role") or "")
            identity = identities.get(role)
            if identity is None:
                checks.append({
                    "category": "did-setup",
                    "experiment_id": f"did-setup:{role}",
                    "passed": False,
                    "code": "DID_SETUP_ROLE_UNKNOWN",
                })
                continue
            check_transaction(
                category="did-setup",
                experiment_id=f"did-setup:{role}",
                recorded=recorded,
                expected_sender=identity.controller_address,
                expected_recipient=chain.did_registry_address,
            )

        for result in results:
            activity_path = Path(str(result["output"])) / "chain-activity.json"
            activity = read_json(activity_path)
            transactions = activity.get("transactions") or []
            tx_hashes = []
            for recorded in transactions:
                tx_hash = str(recorded.get("transaction_hash") or "")
                if tx_hash:
                    tx_hashes.append(tx_hash)
                check_transaction(
                    category="lineage",
                    experiment_id=str(result["experiment_id"]),
                    recorded=recorded,
                    expected_sender=relayer_address,
                    expected_recipient=chain.lineage_registry_address,
                )
            try:
                live_events = decode_lineage_events(chain, tx_hashes)
                names = [str(item.get("event")) for item in live_events]
                observed = Counter(names)
                root_events = observed.pop("RootRegistered", 0) + observed.pop(
                    "EpochRotated", 0
                )
                expected_count = _expected_lineage_activity(
                    str(result["scheme"]),
                    str(result["case_id"]),
                )
                expected_events = _expected_lineage_events(
                    str(result["scheme"]),
                    str(result["case_id"]),
                )
                event_passed = bool(
                    len(live_events) == expected_count
                    and root_events == (1 if expected_count else 0)
                    and observed == expected_events
                )
                event_checks.append({
                    "experiment_id": result["experiment_id"],
                    "transaction_count": len(tx_hashes),
                    "event_count": len(live_events),
                    "event_names": names,
                    "passed": event_passed,
                })
            except Exception as exc:
                event_checks.append({
                    "experiment_id": result["experiment_id"],
                    "passed": False,
                    "code": "LINEAGE_EVENT_REVERSE_VERIFICATION_FAILED",
                    "reason": type(exc).__name__,
                })
    except Exception as exc:
        return {
            "passed": False,
            "verified": 0,
            "code": "PROTOCOL_TRANSACTION_VERIFIER_UNAVAILABLE",
            "reason": type(exc).__name__,
            "checks": checks,
            "event_checks": event_checks,
        }

    return {
        "passed": bool(
            all(item.get("passed") for item in checks)
            and len(event_checks) == len(results)
            and all(item.get("passed") for item in event_checks)
        ),
        "verified": sum(bool(item.get("passed")) for item in checks),
        "transaction_count": len(checks),
        "event_experiment_count": len(event_checks),
        "actual_cost_wei": sum(int(item.get("actual_cost_wei") or 0) for item in checks),
        "checks": checks,
        "event_checks": event_checks,
    }


def _failed_isolation_report(configs: list[dict[str, Any]], reason: str) -> dict[str, Any]:
    return {
        "passed": False,
        "experiment_count": len(configs),
        "code": "ISOLATION_REPORT_INCOMPLETE",
        "reason": reason,
    }


def execute_full_plan(
    args: argparse.Namespace,
    chain: ChainConfig,
    *,
    executor: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    full_preflight: dict[str, Any] | None = None,
    full_preflight_path: Path | None = None,
    did_setup: dict[str, Any] | None = None,
) -> int:
    output_root = Path(args.output_root).resolve()
    temp_root = Path(args.temp_root).resolve()
    run_directory = output_root / args.run_id
    orchestration_directory = run_directory / "orchestration"
    orchestration_directory.mkdir(parents=True, exist_ok=False)
    plan = build_full_plan(args.run_id)
    preflight_hash = sha256_json(full_preflight) if full_preflight is not None else None
    preflight_reference = (
        {
            "path": str(full_preflight_path),
            "sha256": preflight_hash,
            "code": full_preflight.get("code"),
        }
        if full_preflight is not None and full_preflight_path is not None
        else None
    )
    did_setup_transactions = [
        item.get("transaction")
        for item in (did_setup or {}).get("transactions", [])
        if item.get("transaction")
    ]
    did_setup_transaction_count = len(did_setup_transactions)
    did_setup_gas_used = sum(
        int(item.get("gas_used") or 0) for item in did_setup_transactions
    )
    write_json(run_directory / "run-config.json", {
        "schema_version": "agentdid-full-run-config-v1",
        "run_id": args.run_id,
        "mode": "full-63",
        "acceptance_run": True,
        "planned": FULL_EXPERIMENT_COUNT,
        "case_ids": list(FULL_CASE_IDS),
        "schemes": list(SCHEMES),
        "chain": chain.public_dict(),
        "preflight": preflight_reference,
        "shared_did_setup": {
            "path": str(run_directory / "setup" / "did-registry.json")
            if did_setup is not None
            else None,
            "transaction_count": did_setup_transaction_count,
            "gas_used": did_setup_gas_used,
        },
        "timeout_seconds": args.timeout_seconds,
        "fail_fast": bool(args.fail_fast),
        "plan": plan,
        "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    })

    environment = os.environ.copy()
    environment["AGENTDID_EXPERIMENT_RPC_URL"] = chain.rpc_url
    environment["AGENTDID_EXPERIMENT_CONFIRMATIONS"] = str(chain.confirmations)
    environment["AGENTDID_EXPERIMENT_RPC_TIMEOUT_SECONDS"] = str(
        chain.rpc_timeout_seconds
    )
    if full_preflight is not None:
        fee_cap = int(full_preflight["gas_budget"]["fee_upper_bound_wei"])
        environment["AGENTDID_EXPERIMENT_MAX_FEE_PER_GAS_WEI"] = str(fee_cap)
        environment["AGENTDID_LINEAGE_GAS_LIMIT_CAP"] = str(
            FULL_LINEAGE_GAS_LIMIT_PER_TRANSACTION
        )
    results: list[dict[str, Any]] = []
    configs: list[dict[str, Any]] = []
    run_started = time.perf_counter()

    for item in plan:
        command = build_child_command(
            item,
            run_id=args.run_id,
            output_root=output_root,
            temp_root=temp_root,
            chain=chain,
            full_preflight_path=full_preflight_path,
            full_preflight_hash=preflight_hash,
        )
        stem = f"{item['ordinal']:02d}-{item['scheme']}-{item['case_id']}"
        started_at = dt.datetime.now(dt.timezone.utc).isoformat()
        started = time.perf_counter()
        stdout = ""
        stderr = ""
        config: dict[str, Any] | None = None
        try:
            completed = executor(
                command,
                cwd=PROJECT_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=args.timeout_seconds,
            )
            stdout = redact_rpc_text(completed.stdout, chain.rpc_url)
            stderr = redact_rpc_text(completed.stderr, chain.rpc_url)
            result, config = collect_experiment_result(
                output_root,
                args.run_id,
                item,
                int(completed.returncode),
            )
        except subprocess.TimeoutExpired as exc:
            stdout = redact_rpc_text(exc.stdout, chain.rpc_url)
            stderr = redact_rpc_text(exc.stderr, chain.rpc_url)
            result = _infrastructure_result(
                item,
                output_root,
                args.run_id,
                code="CHILD_PROCESS_TIMEOUT",
                reason=f"child exceeded {args.timeout_seconds:g} seconds",
            )
        except OSError as exc:
            result = _infrastructure_result(
                item,
                output_root,
                args.run_id,
                code="CHILD_PROCESS_START_FAILED",
                reason=type(exc).__name__,
            )
        except Exception as exc:
            result = _infrastructure_result(
                item,
                output_root,
                args.run_id,
                code="CHILD_RESULT_COLLECTION_FAILED",
                reason=type(exc).__name__,
            )

        (orchestration_directory / f"{stem}.stdout.log").write_text(
            stdout,
            encoding="utf-8",
        )
        (orchestration_directory / f"{stem}.stderr.log").write_text(
            stderr,
            encoding="utf-8",
        )
        result.update({
            "orchestration_started_at": started_at,
            "orchestration_completed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "duration_ms": round((time.perf_counter() - started) * 1000, 6),
        })
        try:
            _enrich_chain_shape(result, chain)
        except Exception as exc:
            result.update({
                "status": "INFRA_ERROR",
                "accepted": None,
                "passed": False,
                "code": "CHAIN_ACTIVITY_ARTIFACT_INVALID",
                "reason": type(exc).__name__,
                "detection_layer": "infrastructure",
                "lineage_transaction_count": 0,
                "lineage_event_count": 0,
                "lineage_gas_used": 0,
                "lineage_event_names": [],
                "expected_lineage_activity_count": _expected_lineage_activity(
                    str(item["scheme"]),
                    str(item["case_id"]),
                ),
                "lineage_chain_shape_passed": False,
            })
        results.append(result)
        if config is not None:
            configs.append(config)
        print(json.dumps({
            "progress": f"{len(results)}/{FULL_EXPERIMENT_COUNT}",
            "scheme": item["scheme"],
            "case_id": item["case_id"],
            "status": result["status"],
            "passed": result["passed"],
            "code": result["code"],
        }, ensure_ascii=False), flush=True)
        if (args.fail_fast or chain.backend == "sepolia") and (
            result["status"] != "COMPLETED"
            or not result["passed"]
            or int(result.get("return_code", 1)) != 0
        ):
            break

    evidence_checks = []
    for result in results:
        directory = Path(str(result["output"]))
        try:
            check = (
                verify_evidence(directory)
                if directory.exists()
                else {"passed": False, "code": "EXPERIMENT_DIRECTORY_MISSING"}
            )
        except Exception as exc:
            check = {
                "passed": False,
                "code": "EVIDENCE_VERIFICATION_FAILED",
                "reason": type(exc).__name__,
            }
        result["evidence_integrity"] = bool(check.get("passed"))
        evidence_checks.append({"experiment_id": result["experiment_id"], **check})

    if len(configs) == FULL_EXPERIMENT_COUNT:
        try:
            isolation = build_isolation_report(configs)
        except (KeyError, TypeError, ValueError) as exc:
            isolation = _failed_isolation_report(configs, type(exc).__name__)
    else:
        isolation = _failed_isolation_report(configs, "missing experiment configs")

    try:
        semantics = _semantics_report(configs, FULL_CASE_IDS)
    except (KeyError, TypeError, ValueError) as exc:
        semantics = {
            "passed": False,
            "code": "SCENARIO_SEMANTICS_REPORT_INVALID",
            "reason": type(exc).__name__,
            "expected_case_hash_count": len(FULL_CASE_IDS),
        }
    protocol_transaction_reverification = _live_protocol_transaction_verification(
        chain,
        results,
        did_setup,
    )
    anchor_reverification = _live_anchor_verification(chain, results)
    completed_count = sum(item["status"] == "COMPLETED" for item in results)
    infra_errors = sum(item["status"] == "INFRA_ERROR" for item in results)
    passed_count = sum(bool(item["passed"]) for item in results)
    anchors_verified = sum(bool(item.get("anchor_matches")) for item in results)
    anchor_transaction_count = sum(bool(item.get("anchor_transaction")) for item in results)
    chain_shapes_ok = bool(
        len(results) == FULL_EXPERIMENT_COUNT
        and all(item["lineage_chain_shape_passed"] for item in results)
    )
    anchor_transactions = [
        str(item.get("anchor_transaction") or "") for item in results
    ]
    merkle_roots = [str(item.get("anchor_merkle_root") or "") for item in results]
    uniqueness = {
        "anchor_transactions": bool(
            len(anchor_transactions) == FULL_EXPERIMENT_COUNT
            and all(anchor_transactions)
            and len(set(anchor_transactions)) == FULL_EXPERIMENT_COUNT
        ),
        "merkle_roots": bool(
            len(merkle_roots) == FULL_EXPERIMENT_COUNT
            and all(merkle_roots)
            and len(set(merkle_roots)) == FULL_EXPERIMENT_COUNT
        ),
    }
    infrastructure_ok = bool(
        len(results) == FULL_EXPERIMENT_COUNT
        and len(configs) == FULL_EXPERIMENT_COUNT
        and completed_count == FULL_EXPERIMENT_COUNT
        and infra_errors == 0
        and anchors_verified == FULL_EXPERIMENT_COUNT
        and isolation.get("passed")
        and semantics.get("passed")
        and chain_shapes_ok
        and all(uniqueness.values())
        and all(item["evidence_integrity"] for item in results)
        and protocol_transaction_reverification["passed"]
        and anchor_reverification["passed"]
    )
    integrity_ok = bool(
        infrastructure_ok
        and passed_count == FULL_EXPERIMENT_COUNT
        and all(int(item.get("return_code", 1)) == 0 for item in results)
    )
    exit_code = 0 if integrity_ok else (2 if infrastructure_ok else 1)

    summary = {
        "schema_version": "agentdid-full-comparison-run-v1",
        "run_id": args.run_id,
        "classification": "agentdid-21x3-robustness-matrix",
        "acceptance_run": True,
        "excluded_from_pesr": True,
        "pesr": None,
        "planned": FULL_EXPERIMENT_COUNT,
        "executed": len(results),
        "completed": completed_count,
        "infra_errors": infra_errors,
        "passed": passed_count,
        "anchors_verified": anchors_verified,
        "chain": chain.public_dict(),
        "chain_lifecycle": {
            "shared_chain": True,
            "shared_contract_deployment": chain.backend == "hardhat",
            "predeployed_contracts": chain.backend == "sepolia",
            "shared_remote_config": chain.backend == "sepolia",
            "serial_children": True,
            "fallback": False,
        },
        "preflight": preflight_reference,
        "did_setup_transaction_count": did_setup_transaction_count,
        "did_setup_gas_used": did_setup_gas_used,
        "anchor_transaction_count": anchor_transaction_count,
        "scheme_metrics": _scheme_metrics(results),
        "case_metrics": _case_metrics(results),
        "lineage_transaction_count": sum(
            int(item["lineage_transaction_count"]) for item in results
        ),
        "lineage_event_count": sum(
            int(item["lineage_event_count"]) for item in results
        ),
        "lineage_gas_used": sum(int(item["lineage_gas_used"]) for item in results),
        "anchor_gas_used": sum(int(item.get("anchor_gas_used") or 0) for item in results),
        "total_onchain_transaction_count": (
            did_setup_transaction_count
            + sum(int(item["lineage_transaction_count"]) for item in results)
            + anchor_transaction_count
        ),
        "total_onchain_gas_used": (
            did_setup_gas_used
            + sum(int(item["lineage_gas_used"]) for item in results)
            + sum(int(item.get("anchor_gas_used") or 0) for item in results)
        ),
        "lineage_chain_shapes_passed": chain_shapes_ok,
        "isolation": isolation,
        "scenario_semantics": semantics,
        "uniqueness": uniqueness,
        "evidence_integrity": evidence_checks,
        "anchor_reverse_verification": anchor_reverification,
        "protocol_transaction_reverse_verification": protocol_transaction_reverification,
        "actual_onchain_cost_wei": (
            int(protocol_transaction_reverification.get("actual_cost_wei") or 0)
            + int(anchor_reverification.get("actual_cost_wei") or 0)
        ),
        "infrastructure_ok": infrastructure_ok,
        "integrity_ok": integrity_ok,
        "exit_code": exit_code,
        "duration_ms": round((time.perf_counter() - run_started) * 1000, 6),
        "experiments": results,
    }
    summary_path = run_directory / "summary.json"
    decisions_path = run_directory / "decisions.csv"
    comparison_path = run_directory / "comparison-table.csv"
    integrity_path = run_directory / "integrity-report.json"
    write_json(summary_path, summary)
    _write_decisions_csv(decisions_path, results)
    _write_comparison_csv(comparison_path, results)
    write_json(integrity_path, {
        "schema_version": "agentdid-full-comparison-integrity-v1",
        "run_id": args.run_id,
        "planned": FULL_EXPERIMENT_COUNT,
        "executed": len(results),
        "completed": completed_count,
        "infra_errors": infra_errors,
        "passed": passed_count,
        "anchors_verified": anchors_verified,
        "preflight": preflight_reference,
        "did_setup_transaction_count": did_setup_transaction_count,
        "did_setup_gas_used": did_setup_gas_used,
        "anchor_transaction_count": anchor_transaction_count,
        "lineage_chain_shapes_passed": chain_shapes_ok,
        "isolation": isolation,
        "scenario_semantics": semantics,
        "uniqueness": uniqueness,
        "anchor_reverse_verification": anchor_reverification,
        "protocol_transaction_reverse_verification": protocol_transaction_reverification,
        "infrastructure_ok": infrastructure_ok,
        "integrity_ok": integrity_ok,
        "exit_code": exit_code,
    })
    print(json.dumps({
        "run_id": args.run_id,
        "summary": str(summary_path),
        "decisions_csv": str(decisions_path),
        "comparison_table": str(comparison_path),
        "integrity_report": str(integrity_path),
        "integrity_ok": integrity_ok,
        "completed": completed_count,
        "anchors_verified": anchors_verified,
        "chain_backend": chain.backend,
        "exit_code": exit_code,
    }, ensure_ascii=False))
    return exit_code


def _existing_run_error(args: argparse.Namespace) -> int | None:
    output_run = Path(args.output_root).resolve() / args.run_id
    temp_run = Path(args.temp_root).resolve() / args.run_id
    existing = [str(path) for path in (output_run, temp_run) if path.exists()]
    if not existing:
        return None
    print(json.dumps({
        "status": "INFRA_ERROR",
        "code": "RUN_ID_ALREADY_EXISTS",
        "run_id": args.run_id,
        "paths": existing,
        "exit_code": 1,
    }, ensure_ascii=False))
    return 1


def run(args: argparse.Namespace) -> int:
    plan = build_full_plan(args.run_id)
    if args.dry_run:
        print(json.dumps({
            "run_id": args.run_id,
            "mode": "full-63-dry-run",
            "planned": len(plan),
            "case_ids": list(FULL_CASE_IDS),
            "schemes": list(SCHEMES),
            "plan": plan,
        }, ensure_ascii=False, indent=2))
        return 0

    existing_error = _existing_run_error(args)
    if existing_error is not None:
        return existing_error

    if args.chain == "sepolia":
        run_directory = Path(args.output_root).resolve() / args.run_id
        preflight_path = run_directory / "preflight.json"
        try:
            chain = sepolia_config()
        except Exception as exc:
            configured_rpc = os.environ.get("AGENTDID_EXPERIMENT_RPC_URL", "").strip()
            report = {
                "schema_version": "agentdid-sepolia-full-preflight-v1",
                "status": "FAILED",
                "passed": False,
                "code": "SEPOLIA_CONFIG_INVALID",
                "run_id": args.run_id,
                "planned": FULL_EXPERIMENT_COUNT,
                "started": 0,
                "fallback": False,
                "reason": redact_rpc_text(
                    f"{type(exc).__name__}: {exc}",
                    configured_rpc,
                ),
            }
            write_json(preflight_path, report)
            print(json.dumps({
                "status": "INFRA_ERROR",
                "code": report["code"],
                "preflight": str(preflight_path),
                "fallback": False,
                "exit_code": 1,
            }, ensure_ascii=False))
            return 1

        preflight = run_sepolia_full_preflight(
            chain,
            run_id=args.run_id,
            plan=plan,
            child_timeout_seconds=args.timeout_seconds,
        )
        write_json(preflight_path, preflight)
        if not preflight.get("passed"):
            print(json.dumps({
                "status": "INFRA_ERROR",
                "code": preflight.get("code", "SEPOLIA_FULL_PREFLIGHT_FAILED"),
                "preflight": str(preflight_path),
                "fallback": False,
                "exit_code": 1,
            }, ensure_ascii=False))
            return 1

        setup_path = run_directory / "setup" / "did-registry.json"
        try:
            actor_keys = load_actor_keys("sepolia")
            did_setup = configure_did_registry(
                chain,
                actor_keys.identities(chain.chain_id),
                actor_keys,
                max_fee_per_gas_wei=int(
                    preflight["gas_budget"]["fee_upper_bound_wei"]
                ),
                gas_limit_cap=DID_SETUP_GAS_UPPER_BOUND_PER_CONTROLLER,
                allowed_setup_roles=set(
                    preflight["did_setup_plan"]["roles_requiring_setup"]
                ),
            )
            write_json(setup_path, did_setup)
        except Exception as exc:
            reason = redact_rpc_text(
                f"{type(exc).__name__}: {exc}",
                chain.rpc_url,
            )
            failure = {
                "schema_version": "agentdid-sepolia-shared-setup-error-v1",
                "status": "INFRA_ERROR",
                "code": "SEPOLIA_SHARED_DID_SETUP_FAILED",
                "run_id": args.run_id,
                "reason": reason,
                "fallback": False,
            }
            write_json(run_directory / "setup" / "failure.json", failure)
            print(json.dumps({**failure, "exit_code": 1}, ensure_ascii=False))
            return 1
        return execute_full_plan(
            args,
            chain,
            full_preflight=preflight,
            full_preflight_path=preflight_path,
            did_setup=did_setup,
        )

    log_directory = Path(args.temp_root).resolve() / args.run_id / "shared-chain"
    try:
        with HardhatNode(log_directory):
            chain = local_config(deploy_local_contracts())
            actor_keys = load_actor_keys("hardhat")
            did_setup = configure_did_registry(
                chain,
                actor_keys.identities(chain.chain_id),
                actor_keys,
            )
            write_json(
                Path(args.output_root).resolve()
                / args.run_id
                / "setup"
                / "did-registry.json",
                did_setup,
            )
            return execute_full_plan(args, chain, did_setup=did_setup)
    except Exception as exc:
        print(json.dumps({
            "status": "INFRA_ERROR",
            "code": "FULL_RUN_SETUP_FAILED",
            "reason": redact_rpc_text(f"{type(exc).__name__}: {exc}"),
            "exit_code": 1,
        }, ensure_ascii=False))
        return 1


def main(argv: list[str] | None = None) -> int:
    return run(parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
