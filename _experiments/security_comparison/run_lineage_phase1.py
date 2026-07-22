"""Run the L01-L05 Agent lineage robustness checks on a local Hardhat chain."""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

from _experiments.security_comparison.cases import (
    LINEAGE_PHASE1_CASE_IDS,
    LINEAGE_PHASE1_CHECKS,
    LINEAGE_REJECTION_CODES,
    SCHEMES,
)
from _experiments.security_comparison.chain import (
    HARDHAT_RPC_URL,
    HardhatNode,
    deploy_local_contracts,
    local_config,
)
from _experiments.security_comparison.cli_common import run_id_argument
from _experiments.security_comparison.evidence import read_json, write_json
from _experiments.security_comparison.run_robustness import (
    _child_command,
    _collect_result,
    _isolation_report,
    _verify_evidence,
)
from infrastructure.lineage.registry_client import bytes32_id


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run L01-L05 as 15 independent Agent lineage robustness checks",
    )
    parser.add_argument(
        "--run-id",
        type=run_id_argument,
        default="lineage-robustness-" + uuid.uuid4().hex[:12],
    )
    parser.add_argument(
        "--output-root",
        default=str(PROJECT_ROOT / ".codex" / "comparison_runs"),
    )
    parser.add_argument(
        "--temp-root",
        default=str(PROJECT_ROOT / ".codex" / "comparison_tmp"),
    )
    return parser.parse_args()


def build_lineage_robustness_plan(
    run_id: str,
    case_ids: tuple[str, ...] = LINEAGE_PHASE1_CASE_IDS,
) -> list[dict[str, Any]]:
    plan = []
    ordinal = 0
    for case_id in case_ids:
        for scheme in SCHEMES:
            ordinal += 1
            plan.append({
                "ordinal": ordinal,
                "scheme": scheme,
                "case_id": case_id,
                "experiment_id": f"{run_id}-{scheme}-{case_id.lower()}",
                "lineage_epoch": ordinal,
            })
    return plan


# Compatibility name retained for early local callers.
build_lineage_phase1_plan = build_lineage_robustness_plan


def _enrich_result(result: dict[str, Any]) -> dict[str, Any]:
    directory = Path(result["output"])
    decision_path = directory / "decision.json"
    trace_path = directory / "verification-trace.json"
    activity_path = directory / "chain-activity.json"
    config_path = directory / "experiment-config.json"
    lineage_path = directory / "lineage-evidence.json"
    if not decision_path.exists():
        return result
    decision = read_json(decision_path)
    trace = read_json(trace_path) if trace_path.exists() else {}
    activity = read_json(activity_path) if activity_path.exists() else {}
    config = read_json(config_path) if config_path.exists() else {}
    lineage_evidence = read_json(lineage_path) if lineage_path.exists() else {}
    transactions = activity.get("transactions", [])
    lineage_events = activity.get("lineage_events", [])
    expected_lineage_code = LINEAGE_REJECTION_CODES[result["case_id"]]
    if result["scheme"] == "original":
        non_target_layers_passed = bool(
            decision.get("accepted")
            and decision.get("layer_passed", {}).get("did-vc-vp")
        )
    elif result["scheme"] == "baseline":
        non_target_layers_passed = bool(
            decision.get("accepted")
            and decision.get("layer_passed", {}).get("did-vc-vp")
            and decision.get("layer_passed", {}).get("baseline-agentdid")
        )
    else:
        non_target_layers_passed = bool(
            decision.get("accepted") is False
            and decision.get("code") == expected_lineage_code
            and decision.get("detection_layer") == "lineage-agentdid"
            and decision.get("layer_passed", {}).get("did-vc-vp")
            and decision.get("layer_passed", {}).get("baseline-agentdid")
            and trace.get("lineage", {}).get("accepted") is False
        )
    event_names = [item.get("event") for item in lineage_events]
    request_signature_control_passed = bool(
        lineage_evidence.get("evidence", {})
        .get("request_signature_control", {})
        .get("passed")
    ) if result["scheme"] == "lineage" else True
    revocation_detail_passed = True
    if result["scheme"] == "lineage":
        expects_revocation = result["case_id"] == "L12"
        expects_second_branch = result["case_id"] == "L09"
        expected_chain_items = 10 if expects_second_branch else (7 if expects_revocation else 6)
        expected_delegations = 4 if expects_second_branch else 2
        expected_budgets = 5 if expects_second_branch else 3
        if expects_revocation:
            status_events = [
                item for item in lineage_events
                if item.get("event") == "StatusRevoked"
            ]
            registered_chain = (
                lineage_evidence.get("evidence", {}).get("registered_chain", [])
            )
            expected_subject = (
                bytes32_id(registered_chain[0]["child_did"]).hex()
                if registered_chain
                else None
            )
            actual_subject = (
                str(status_events[0].get("args", {}).get("subject", ""))
                .lower()
                .removeprefix("0x")
                if len(status_events) == 1
                else None
            )
            revocation_detail_passed = bool(
                len(status_events) == 1
                and int(status_events[0].get("args", {}).get("kind", -1)) == 3
                and actual_subject == expected_subject
                and sum(
                    item.get("operation") == "revoke_ancestor"
                    for item in transactions
                ) == 1
            )
        chain_shape_passed = bool(
            len(transactions) == expected_chain_items
            and len(lineage_events) == expected_chain_items
            and event_names.count("DelegationRegistered") == expected_delegations
            and event_names.count("BudgetCreated") == expected_budgets
            and sum(name in {"RootRegistered", "EpochRotated"} for name in event_names) == 1
            and event_names.count("StatusRevoked") == (1 if expects_revocation else 0)
            and "InvocationStarted" not in event_names
            and "InvocationFinished" not in event_names
            and revocation_detail_passed
            and request_signature_control_passed
        )
    else:
        chain_shape_passed = not transactions and not lineage_events
    result.update({
        "robustness_dimension": decision.get("lineage_robustness_dimension"),
        "expected_accepted": decision.get("expected_accepted"),
        "expected_code": decision.get("expected_code"),
        "expected_detection_layer": decision.get("expected_detection_layer"),
        "layer_passed": decision.get("layer_passed"),
        "protocol_passed": bool(decision.get("layer_passed", {}).get("did-vc-vp")),
        "baseline_passed": bool(decision.get("layer_passed", {}).get("baseline-agentdid")),
        "lineage_passed": bool(decision.get("layer_passed", {}).get("lineage-agentdid")),
        "non_target_layers_passed": non_target_layers_passed,
        "latency_ms": decision.get("latency_ms"),
        "lineage_transaction_count": len(transactions),
        "lineage_event_count": len(lineage_events),
        "lineage_gas_used": sum(int(item.get("gas_used", 0)) for item in transactions),
        "lineage_chain_shape_passed": chain_shape_passed,
        "request_signature_control_passed": request_signature_control_passed,
        "revocation_detail_passed": revocation_detail_passed,
        "actual_epoch": config.get("independent_state", {}).get("lineage", {}).get("epoch"),
    })
    return result


def _write_csv(path: Path, results: list[dict[str, Any]]) -> None:
    fields = (
        "ordinal",
        "experiment_id",
        "scheme",
        "case_id",
        "robustness_dimension",
        "status",
        "expected_accepted",
        "accepted",
        "passed",
        "code",
        "expected_code",
        "detection_layer",
        "expected_detection_layer",
        "protocol_passed",
        "baseline_passed",
        "lineage_passed",
        "non_target_layers_passed",
        "latency_ms",
        "lineage_transaction_count",
        "lineage_event_count",
        "lineage_gas_used",
        "lineage_chain_shape_passed",
        "request_signature_control_passed",
        "revocation_detail_passed",
        "actual_epoch",
        "anchor_matches",
        "anchor_transaction",
        "anchor_block_number",
        "anchor_gas_used",
        "anchor_merkle_root",
        "evidence_integrity",
        "output",
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)


def _scheme_metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    metrics = {}
    for scheme in SCHEMES:
        items = [item for item in results if item["scheme"] == scheme]
        metrics[scheme] = {
            "completed": sum(item["status"] == "COMPLETED" for item in items),
            "accepted": sum(item["accepted"] is True for item in items),
            "rejected": sum(item["accepted"] is False for item in items),
            "passed": sum(item["passed"] for item in items),
            "target_lineage_detections": sum(
                item["detection_layer"] == "lineage-agentdid"
                and item["accepted"] is False
                for item in items
            ),
            "non_target_layers_passed": sum(
                bool(item.get("non_target_layers_passed")) for item in items
            ),
            "response_conformance_rate": (
                sum(bool(item["passed"]) for item in items) / len(items)
                if items
                else 0.0
            ),
        }
    return metrics


def _case_metrics(
    results: list[dict[str, Any]],
    case_ids: tuple[str, ...] = LINEAGE_PHASE1_CASE_IDS,
) -> dict[str, Any]:
    return {
        case_id: {
            "completed": sum(item["status"] == "COMPLETED" for item in results if item["case_id"] == case_id),
            "passed": sum(bool(item["passed"]) for item in results if item["case_id"] == case_id),
            "accepted": sum(item["accepted"] is True for item in results if item["case_id"] == case_id),
            "rejected": sum(item["accepted"] is False for item in results if item["case_id"] == case_id),
            "lineage_response_code": next(
                (item["code"] for item in results if item["case_id"] == case_id and item["scheme"] == "lineage"),
                None,
            ),
        }
        for case_id in case_ids
    }


def _semantics_report(
    configs: list[dict[str, Any]],
    case_ids: tuple[str, ...],
) -> dict[str, Any]:
    by_case: dict[str, list[str]] = {case_id: [] for case_id in case_ids}
    for config in configs:
        case_id = str(config.get("case_id"))
        if case_id in by_case:
            value = str(
                config.get("independent_state", {})
                .get("lineage", {})
                .get("scenario_semantics_hash", "")
            )
            by_case[case_id].append(value)
    one_hash_per_case = all(
        len(values) == len(SCHEMES)
        and all(values)
        and len(set(values)) == 1
        for values in by_case.values()
    )
    distinct_case_hashes = {
        values[0]
        for values in by_case.values()
        if values
    }
    return {
        "passed": one_hash_per_case and len(distinct_case_hashes) == len(case_ids),
        "one_hash_per_case": one_hash_per_case,
        "distinct_case_hash_count": len(distinct_case_hashes),
        "expected_case_hash_count": len(case_ids),
        "hashes_by_case": by_case,
    }


def run_group(
    args: argparse.Namespace,
    *,
    case_ids: tuple[str, ...] = LINEAGE_PHASE1_CASE_IDS,
    robustness_definitions: dict[str, dict[str, str]] = LINEAGE_PHASE1_CHECKS,
    output_stem: str = "lineage-robustness",
) -> int:
    output_root = Path(args.output_root).resolve()
    temp_root = Path(args.temp_root).resolve()
    plan = build_lineage_robustness_plan(args.run_id, case_ids)
    planned_count = len(plan)
    log_directory = temp_root / args.run_id / "shared-chain"
    orchestration_directory = output_root / args.run_id / "orchestration"
    orchestration_directory.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    configs: list[dict[str, Any]] = []

    with HardhatNode(log_directory):
        chain = local_config(deploy_local_contracts())
        environment = os.environ.copy()
        environment["AGENTDID_EXPERIMENT_RPC_URL"] = HARDHAT_RPC_URL
        for item in plan:
            command = _child_command(
                item,
                run_id=args.run_id,
                output_root=output_root,
                temp_root=temp_root,
                chain_id=chain.chain_id,
                did_registry=chain.did_registry_address,
                lineage_registry=chain.lineage_registry_address,
            )
            completed = subprocess.run(
                command,
                cwd=PROJECT_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=300,
            )
            stem = f"{item['ordinal']:02d}-{item['scheme']}-{item['case_id']}"
            (orchestration_directory / f"{stem}.stdout.log").write_text(
                completed.stdout,
                encoding="utf-8",
            )
            (orchestration_directory / f"{stem}.stderr.log").write_text(
                completed.stderr,
                encoding="utf-8",
            )
            result, config = _collect_result(
                output_root,
                args.run_id,
                item,
                completed.returncode,
            )
            results.append(_enrich_result(result))
            if config is not None:
                configs.append(config)

    isolation = _isolation_report(configs)
    evidence_checks = []
    for item in results:
        directory = Path(item["output"])
        check = _verify_evidence(directory) if directory.exists() else {"passed": False}
        item["evidence_integrity"] = bool(check["passed"])
        evidence_checks.append({"experiment_id": item["experiment_id"], **check})

    completed_count = sum(item["status"] == "COMPLETED" for item in results)
    infra_errors = sum(item["status"] == "INFRA_ERROR" for item in results)
    passed_count = sum(item["passed"] for item in results)
    anchors_verified = sum(item["anchor_matches"] for item in results)
    non_target_layers_ok = all(
        bool(item.get("non_target_layers_passed")) for item in results
    )
    chain_shapes_ok = all(
        bool(item.get("lineage_chain_shape_passed")) for item in results
    )
    semantics = _semantics_report(configs, case_ids)
    anchor_transactions = [
        str(item.get("anchor_transaction", "")) for item in results
    ]
    merkle_roots = [
        str(item.get("anchor_merkle_root", "")) for item in results
    ]
    lineage_epochs = [
        int(
            config.get("independent_state", {})
            .get("lineage", {})
            .get("epoch", -1)
        )
        for config in configs
        if config.get("scheme_id") == "lineage"
    ]
    uniqueness = {
        "anchor_transactions": bool(
            len(anchor_transactions) == planned_count
            and all(anchor_transactions)
            and len(set(anchor_transactions)) == planned_count
        ),
        "merkle_roots": bool(
            len(merkle_roots) == planned_count
            and all(merkle_roots)
            and len(set(merkle_roots)) == planned_count
        ),
        "lineage_epochs": bool(
            len(lineage_epochs) == len(case_ids)
            and len(set(lineage_epochs)) == len(case_ids)
            and all(right > left for left, right in zip(lineage_epochs, lineage_epochs[1:]))
        ),
    }
    integrity_ok = (
        len(results) == planned_count
        and len(configs) == planned_count
        and completed_count == planned_count
        and infra_errors == 0
        and passed_count == planned_count
        and anchors_verified == planned_count
        and all(int(item.get("return_code", 1)) == 0 for item in results)
        and isolation["passed"]
        and non_target_layers_ok
        and chain_shapes_ok
        and semantics["passed"]
        and all(uniqueness.values())
        and all(item["evidence_integrity"] for item in results)
    )
    summary = {
        "schema_version": "agentdid-lineage-robustness-run-v1",
        "run_id": args.run_id,
        "classification": "agent-lineage-robustness-checks",
        "excluded_from_pesr": True,
        "case_ids": list(case_ids),
        "robustness_definitions": robustness_definitions,
        "planned": planned_count,
        "completed": completed_count,
        "infra_errors": infra_errors,
        "passed": passed_count,
        "anchors_verified": anchors_verified,
        "non_target_layers_passed": non_target_layers_ok,
        "lineage_chain_shapes_passed": chain_shapes_ok,
        "isolation": isolation,
        "scenario_semantics": semantics,
        "uniqueness": uniqueness,
        "evidence_integrity": evidence_checks,
        "scheme_metrics": _scheme_metrics(results),
        "case_metrics": _case_metrics(results, case_ids),
        "lineage_gas_used": sum(int(item.get("lineage_gas_used") or 0) for item in results),
        "lineage_transaction_count": sum(int(item.get("lineage_transaction_count") or 0) for item in results),
        "lineage_event_count": sum(int(item.get("lineage_event_count") or 0) for item in results),
        "anchor_gas_used": sum(int(item.get("anchor_gas_used") or 0) for item in results),
        "integrity_ok": integrity_ok,
        "experiments": results,
    }
    run_directory = output_root / args.run_id
    summary_path = run_directory / f"{output_stem}-summary.json"
    decisions_path = run_directory / f"{output_stem}-decisions.csv"
    integrity_path = run_directory / f"{output_stem}-integrity.json"
    write_json(summary_path, summary)
    _write_csv(decisions_path, results)
    write_json(integrity_path, {
        "schema_version": "agentdid-lineage-robustness-integrity-v1",
        "run_id": args.run_id,
        "integrity_ok": integrity_ok,
        "completed": completed_count,
        "infra_errors": infra_errors,
        "anchors_verified": anchors_verified,
        "non_target_layers_passed": non_target_layers_ok,
        "lineage_chain_shapes_passed": chain_shapes_ok,
        "isolation": isolation,
        "scenario_semantics": semantics,
        "uniqueness": uniqueness,
        "evidence_integrity": evidence_checks,
    })
    print(json.dumps({
        "run_id": args.run_id,
        "summary": str(summary_path),
        "decisions_csv": str(decisions_path),
        "integrity_report": str(integrity_path),
        "integrity_ok": integrity_ok,
        "completed": completed_count,
        "anchors_verified": anchors_verified,
    }, ensure_ascii=False))
    return 0 if integrity_ok else 1


def main() -> int:
    return run_group(parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
