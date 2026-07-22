"""Run the six AgentDID robustness cases across all three formal schemes."""

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
    ROBUSTNESS_CASE_IDS,
    SCHEME_DIRECTORIES,
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
from infrastructure.security import sha256_json


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run A01-A06 as 18 independent AgentDID robustness checks",
    )
    parser.add_argument(
        "--run-id",
        type=run_id_argument,
        default="robustness-" + uuid.uuid4().hex[:12],
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


def build_robustness_plan(run_id: str) -> list[dict[str, Any]]:
    plan = []
    ordinal = 0
    for case_id in ROBUSTNESS_CASE_IDS:
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


def _experiment_directory(output_root: Path, run_id: str, item: dict[str, Any]) -> Path:
    return (
        output_root
        / run_id
        / "experiments"
        / SCHEME_DIRECTORIES[item["scheme"]]
        / item["case_id"]
    )


def _child_command(
    item: dict[str, Any],
    *,
    run_id: str,
    output_root: Path,
    temp_root: Path,
    chain_id: int,
    did_registry: str,
    lineage_registry: str,
) -> list[str]:
    return [
        sys.executable,
        "-B",
        "-m",
        "_experiments.security_comparison.run_one",
        "--scheme",
        item["scheme"],
        "--case",
        item["case_id"],
        "--run-id",
        run_id,
        "--experiment-id",
        item["experiment_id"],
        "--chain",
        "hardhat",
        "--chain-id",
        str(chain_id),
        "--did-registry",
        did_registry,
        "--lineage-registry",
        lineage_registry,
        "--lineage-epoch",
        str(item["lineage_epoch"]),
        "--output-root",
        str(output_root),
        "--temp-root",
        str(temp_root),
    ]


def _collect_result(
    output_root: Path,
    run_id: str,
    item: dict[str, Any],
    return_code: int,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    directory = _experiment_directory(output_root, run_id, item)
    decision_path = directory / "decision.json"
    anchor_path = directory / "chain-anchor.json"
    config_path = directory / "experiment-config.json"
    if not decision_path.exists():
        return ({
            **item,
            "status": "INFRA_ERROR",
            "accepted": None,
            "passed": False,
            "code": "CHILD_PROCESS_FAILED",
            "detection_layer": "infrastructure",
            "return_code": return_code,
            "anchor_matches": False,
            "output": str(directory),
        }, None)

    decision = read_json(decision_path)
    anchor = read_json(anchor_path) if anchor_path.exists() else {}
    config = read_json(config_path) if config_path.exists() else None
    return ({
        **item,
        "status": decision.get("status"),
        "accepted": decision.get("accepted"),
        "passed": bool(decision.get("passed")),
        "code": decision.get("code"),
        "detection_layer": decision.get("detection_layer"),
        "robustness_dimension": decision.get("robustness_dimension"),
        "return_code": return_code,
        "anchor_matches": bool(anchor.get("verification", {}).get("matches")),
        "anchor_transaction": anchor.get("tx_hash"),
        "anchor_block_number": anchor.get("block_number"),
        "anchor_gas_used": anchor.get("gas_used"),
        "anchor_merkle_root": anchor.get("evidence_merkle_root"),
        "output": str(directory),
    }, config)


def _isolation_report(configs: list[dict[str, Any]]) -> dict[str, Any]:
    fields = (
        "replay_guard_id",
        "vp_challenge",
        "vp_hash",
        "state_nonce",
        "context_nonce",
    )
    collisions: dict[str, list[str]] = {}
    experiment_ids = [str(config.get("experiment_id")) for config in configs]
    if len(experiment_ids) != len(set(experiment_ids)):
        collisions["experiment_id"] = experiment_ids
    for field in fields:
        values = [str(config["independent_state"][field]) for config in configs]
        if len(values) != len(set(values)):
            collisions[field] = values

    vc_ids = [
        credential_id
        for config in configs
        for credential_id in config["independent_state"]["vc_ids"]
    ]
    if len(vc_ids) != len(set(vc_ids)):
        collisions["vc_ids"] = vc_ids
    for field in (
        "child_did",
        "child_operation_address",
        "credential_jti",
        "epoch",
        "budget_id",
        "request_hash",
    ):
        values = [str(config["independent_state"]["lineage"][field]) for config in configs]
        if len(values) != len(set(values)):
            collisions[f"lineage.{field}"] = values
    return {
        "passed": not collisions,
        "experiment_count": len(configs),
        "unique_fields": list(fields) + [
            "experiment_id",
            "vc_ids",
            "lineage.credential_jti",
            "lineage.epoch",
            "lineage.budget_id",
            "lineage.request_hash",
            "lineage.child_did",
            "lineage.child_operation_address",
        ],
        "collisions": collisions,
    }


def _verify_evidence(directory: Path) -> dict[str, Any]:
    audit_path = directory / "audit.jsonl"
    manifest_path = directory / "evidence-manifest.json"
    anchor_path = directory / "chain-anchor.json"
    previous_hash = None
    audit_events = 0
    audit_valid = audit_path.exists()
    if audit_valid:
        for line in audit_path.read_text(encoding="utf-8").splitlines():
            event = json.loads(line)
            evidence_hash = event.pop("evidence_hash")
            if event.get("previous_evidence_hash") != previous_hash:
                audit_valid = False
                break
            if sha256_json(event) != evidence_hash:
                audit_valid = False
                break
            previous_hash = evidence_hash
            audit_events += 1

    manifest_valid = manifest_path.exists()
    manifest = read_json(manifest_path) if manifest_valid else {}
    if manifest_valid:
        import hashlib

        for relative, expected_hash in manifest.get("files", {}).items():
            path = directory / relative
            if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != expected_hash:
                manifest_valid = False
                break
    anchor = read_json(anchor_path) if anchor_path.exists() else {}
    anchor_valid = bool(
        anchor.get("verification", {}).get("matches")
        and anchor.get("evidence_merkle_root") == manifest.get("merkle_root")
    )
    return {
        "passed": audit_valid and manifest_valid and anchor_valid,
        "audit_hash_chain": audit_valid,
        "audit_events": audit_events,
        "manifest_files": manifest_valid,
        "anchor_matches_manifest": anchor_valid,
    }


def _write_decisions_csv(path: Path, results: list[dict[str, Any]]) -> None:
    fields = (
        "ordinal",
        "experiment_id",
        "scheme",
        "case_id",
        "robustness_dimension",
        "status",
        "accepted",
        "passed",
        "code",
        "detection_layer",
        "return_code",
        "anchor_matches",
        "anchor_transaction",
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
            "protocol_robustness_detections": sum(
                item["case_id"] in {"A01", "A02", "A03"}
                and item["detection_layer"] == "did-vc-vp"
                and item["accepted"] is False
                for item in items
            ),
            "semantic_robustness_detections": sum(
                item["case_id"] in {"A04", "A05", "A06"}
                and item["detection_layer"] == "baseline-agentdid"
                and item["accepted"] is False
                for item in items
            ),
        }
    return metrics


def main() -> int:
    args = parse_args()
    output_root = Path(args.output_root).resolve()
    temp_root = Path(args.temp_root).resolve()
    plan = build_robustness_plan(args.run_id)
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
            results.append(result)
            if config is not None:
                configs.append(config)

    isolation = _isolation_report(configs)
    evidence_checks = []
    for item in results:
        directory = Path(item["output"])
        check = _verify_evidence(directory) if directory.exists() else {"passed": False}
        item["evidence_integrity"] = bool(check["passed"])
        evidence_checks.append({
            "experiment_id": item["experiment_id"],
            **check,
        })
    anchors_verified = sum(item["anchor_matches"] for item in results)
    completed_count = sum(item["status"] == "COMPLETED" for item in results)
    infra_errors = sum(item["status"] == "INFRA_ERROR" for item in results)
    passed_count = sum(item["passed"] for item in results)
    integrity_ok = (
        len(results) == 18
        and completed_count == 18
        and infra_errors == 0
        and passed_count == 18
        and anchors_verified == 18
        and isolation["passed"]
        and all(item["evidence_integrity"] for item in results)
    )
    summary = {
        "schema_version": "agentdid-robustness-run-v1",
        "run_id": args.run_id,
        "classification": "agent-robustness-checks",
        "excluded_from_pesr": True,
        "case_ids": list(ROBUSTNESS_CASE_IDS),
        "planned": 18,
        "completed": completed_count,
        "infra_errors": infra_errors,
        "passed": passed_count,
        "anchors_verified": anchors_verified,
        "isolation": isolation,
        "evidence_integrity": evidence_checks,
        "scheme_metrics": _scheme_metrics(results),
        "integrity_ok": integrity_ok,
        "experiments": results,
    }
    summary_path = output_root / args.run_id / "robustness-summary.json"
    decisions_path = output_root / args.run_id / "robustness-decisions.csv"
    integrity_path = output_root / args.run_id / "robustness-integrity.json"
    write_json(summary_path, summary)
    _write_decisions_csv(decisions_path, results)
    write_json(integrity_path, {
        "schema_version": "agentdid-robustness-integrity-v1",
        "run_id": args.run_id,
        "integrity_ok": integrity_ok,
        "completed": completed_count,
        "infra_errors": infra_errors,
        "anchors_verified": anchors_verified,
        "isolation": isolation,
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


if __name__ == "__main__":
    raise SystemExit(main())
