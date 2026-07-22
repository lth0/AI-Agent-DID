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
from pathlib import Path
from typing import Any, Callable

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
    deploy_local_contracts,
    load_actor_keys,
    local_config,
)
from _experiments.security_comparison.cli_common import redact_rpc_text, run_id_argument
from _experiments.security_comparison.evidence import read_json, write_json
from _experiments.security_comparison.run_lineage_phase1 import _semantics_report
from _experiments.security_comparison.run_robustness import (
    _collect_result as collect_experiment_result,
    _isolation_report as build_isolation_report,
    _verify_evidence as verify_evidence,
)
from infrastructure.evidence_anchor import EthereumEvidenceAnchor


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
        default=300.0,
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
) -> list[str]:
    """Build one child command without exposing RPC credentials."""

    return [
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
        "--lineage-epoch",
        str(item["lineage_epoch"]),
        "--output-root",
        str(output_root),
        "--temp-root",
        str(temp_root),
    ]


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
        }
    artifact = read_json(path)
    transactions = artifact.get("transactions") or []
    events = artifact.get("lineage_events") or []
    return {
        "transaction_count": len(transactions),
        "event_count": len(events),
        "gas_used": sum(int(item.get("gas_used") or 0) for item in transactions),
        "event_names": [str(item.get("event")) for item in events],
    }


def _expected_lineage_activity(scheme: str, case_id: str) -> int:
    if scheme != "lineage":
        return 0
    if case_id == "H00":
        return 8
    if case_id in ROBUSTNESS_CASE_IDS:
        return 6
    if case_id == "L09":
        return 10
    if case_id == "L12":
        return 7
    return 6


def _enrich_chain_shape(result: dict[str, Any]) -> dict[str, Any]:
    activity = _chain_activity(Path(str(result["output"])))
    expected_count = _expected_lineage_activity(
        str(result["scheme"]),
        str(result["case_id"]),
    )
    event_names = activity["event_names"]
    invocation_shape_ok = (
        event_names.count("InvocationStarted") == 1
        and event_names.count("InvocationFinished") == 1
        if result["scheme"] == "lineage" and result["case_id"] == "H00"
        else "InvocationStarted" not in event_names
        and "InvocationFinished" not in event_names
    )
    revocation_shape_ok = (
        event_names.count("StatusRevoked") == 1
        if result["scheme"] == "lineage" and result["case_id"] == "L12"
        else "StatusRevoked" not in event_names
    )
    result.update({
        "lineage_transaction_count": activity["transaction_count"],
        "lineage_event_count": activity["event_count"],
        "lineage_gas_used": activity["gas_used"],
        "lineage_event_names": event_names,
        "expected_lineage_activity_count": expected_count,
        "lineage_chain_shape_passed": bool(
            activity["transaction_count"] == expected_count
            and activity["event_count"] == expected_count
            and invocation_shape_ok
            and revocation_shape_ok
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
        verifier = EthereumEvidenceAnchor(chain.rpc_url, actor_keys.chain_private_key)
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
                passed = bool(verified["matches"] and int(receipt.status) == 1)
                checks.append({
                    "experiment_id": result["experiment_id"],
                    "transaction_hash": transaction_hash,
                    "merkle_root": merkle_root,
                    "block_number": verified.get("block_number"),
                    "receipt_status": int(receipt.status),
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
        "checks": checks,
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
) -> int:
    output_root = Path(args.output_root).resolve()
    temp_root = Path(args.temp_root).resolve()
    run_directory = output_root / args.run_id
    orchestration_directory = run_directory / "orchestration"
    orchestration_directory.mkdir(parents=True, exist_ok=False)
    plan = build_full_plan(args.run_id)
    write_json(run_directory / "run-config.json", {
        "schema_version": "agentdid-full-run-config-v1",
        "run_id": args.run_id,
        "mode": "full-63",
        "acceptance_run": True,
        "planned": FULL_EXPERIMENT_COUNT,
        "case_ids": list(FULL_CASE_IDS),
        "schemes": list(SCHEMES),
        "chain": chain.public_dict(),
        "timeout_seconds": args.timeout_seconds,
        "fail_fast": bool(args.fail_fast),
        "plan": plan,
        "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    })

    environment = os.environ.copy()
    environment["AGENTDID_EXPERIMENT_RPC_URL"] = chain.rpc_url
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
            _enrich_chain_shape(result)
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
        if args.fail_fast and (
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
    anchor_reverification = _live_anchor_verification(chain, results)
    completed_count = sum(item["status"] == "COMPLETED" for item in results)
    infra_errors = sum(item["status"] == "INFRA_ERROR" for item in results)
    passed_count = sum(bool(item["passed"]) for item in results)
    anchors_verified = sum(bool(item.get("anchor_matches")) for item in results)
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
            "shared_contract_deployment": True,
            "serial_children": True,
        },
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
        "lineage_chain_shapes_passed": chain_shapes_ok,
        "isolation": isolation,
        "scenario_semantics": semantics,
        "uniqueness": uniqueness,
        "evidence_integrity": evidence_checks,
        "anchor_reverse_verification": anchor_reverification,
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
        "lineage_chain_shapes_passed": chain_shapes_ok,
        "isolation": isolation,
        "scenario_semantics": semantics,
        "uniqueness": uniqueness,
        "anchor_reverse_verification": anchor_reverification,
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
        print(json.dumps({
            "status": "INFRA_ERROR",
            "code": "SEPOLIA_FULL_PREFLIGHT_INCOMPLETE",
            "reason": (
                "full Sepolia execution is disabled until balance, relayer, "
                "Lineage Registry and gas-budget preflight checks are implemented"
            ),
            "fallback": False,
            "exit_code": 1,
        }, ensure_ascii=False))
        return 1

    log_directory = Path(args.temp_root).resolve() / args.run_id / "shared-chain"
    try:
        with HardhatNode(log_directory):
            chain = local_config(deploy_local_contracts())
            return execute_full_plan(args, chain)
    except Exception as exc:
        print(json.dumps({
            "status": "INFRA_ERROR",
            "code": "FULL_RUN_SETUP_FAILED",
            "reason": f"{type(exc).__name__}: {exc}",
            "exit_code": 1,
        }, ensure_ascii=False))
        return 1


def main(argv: list[str] | None = None) -> int:
    return run(parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
