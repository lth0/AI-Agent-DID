from __future__ import annotations

import argparse
import datetime as dt
import json
import time
import traceback
import uuid
from pathlib import Path
from typing import Any

from _experiments.security_comparison.adapters import (
    bind_resolved_documents,
    build_experiment_bundle,
    evaluate_scheme,
)
from _experiments.security_comparison.cases import (
    CASE_BY_ID,
    SCHEME_DIRECTORIES,
    SCHEME_LABELS,
    SCHEMES,
    expected_outcome,
)
from _experiments.security_comparison.chain import (
    ChainConfig,
    HardhatNode,
    anchor_evidence,
    configure_did_registry,
    decode_lineage_events,
    deploy_local_contracts,
    load_actor_keys,
    local_config,
    resolve_and_verify_dids,
    sepolia_config,
)
from _experiments.security_comparison.evidence import (
    ComparisonAuditRecorder,
    build_evidence_manifest,
    finalize_experiment,
    read_json,
    write_json,
)
from infrastructure.security import sha256_json


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one isolated AgentDID comparison experiment")
    parser.add_argument("--scheme", required=True, choices=SCHEMES)
    parser.add_argument("--case", required=True, choices=sorted(CASE_BY_ID))
    parser.add_argument("--run-id", default="single-" + uuid.uuid4().hex[:12])
    parser.add_argument("--experiment-id")
    parser.add_argument("--chain", choices=("hardhat", "sepolia"), default="hardhat")
    parser.add_argument("--chain-id", type=int)
    parser.add_argument("--did-registry")
    parser.add_argument("--lineage-registry")
    parser.add_argument("--lineage-epoch", type=int, default=1)
    parser.add_argument(
        "--output-root",
        default=str(PROJECT_ROOT / ".codex" / "comparison_runs"),
    )
    parser.add_argument("--temp-root", default=str(PROJECT_ROOT / ".codex" / "comparison_tmp"))
    return parser.parse_args()


def _config_from_args(args: argparse.Namespace) -> ChainConfig | None:
    if not args.lineage_registry or not args.did_registry or not args.chain_id:
        return None
    import os

    rpc_url = os.environ.get("AGENTDID_EXPERIMENT_RPC_URL", "").strip()
    if not rpc_url:
        raise ValueError("AGENTDID_EXPERIMENT_RPC_URL is required")
    return ChainConfig(
        backend=args.chain,
        rpc_url=rpc_url,
        chain_id=args.chain_id,
        did_registry_address=args.did_registry,
        lineage_registry_address=args.lineage_registry,
    )


def _transaction_hashes(transactions: list[dict[str, Any]]) -> list[str]:
    values = []
    for transaction in transactions:
        value = transaction.get("transaction_hash")
        if value:
            values.append(str(value))
    return values


def execute_experiment(args: argparse.Namespace, chain_config: ChainConfig) -> tuple[int, Path]:
    case = CASE_BY_ID[args.case]
    outcome = expected_outcome(args.scheme, args.case)
    experiment_id = args.experiment_id or f"{args.scheme}-{args.case}-{uuid.uuid4().hex[:12]}"
    temp_directory = (
        Path(args.temp_root).resolve()
        / args.run_id
        / SCHEME_DIRECTORIES[args.scheme]
        / args.case
    )
    final_directory = (
        Path(args.output_root).resolve()
        / args.run_id
        / "experiments"
        / SCHEME_DIRECTORIES[args.scheme]
        / args.case
    )
    if temp_directory.exists() or final_directory.exists():
        raise FileExistsError(f"experiment directory already exists for {args.scheme}/{args.case}")
    temp_directory.mkdir(parents=True, exist_ok=False)
    audit = ComparisonAuditRecorder(
        temp_directory / "audit.jsonl",
        run_id=args.run_id,
        experiment_id=experiment_id,
        scheme=SCHEME_LABELS[args.scheme],
        case_id=args.case,
    )
    started = time.perf_counter()
    audit.record(
        "experiment_started",
        accepted=None,
        code="STARTED",
        detection_layer="orchestrator",
        case_name=case.name,
        chain_backend=chain_config.backend,
    )
    try:
        actor_keys = load_actor_keys(chain_config.backend)
        bundle = build_experiment_bundle(
            case,
            args.scheme,
            experiment_id=experiment_id,
            run_id=args.run_id,
            lineage_epoch=args.lineage_epoch,
            chain_config=chain_config,
            actor_keys=actor_keys,
        )
        setup_path = (
            Path(args.output_root).resolve()
            / args.run_id
            / "setup"
            / "did-registry.json"
        )
        if setup_path.exists():
            did_setup = read_json(setup_path)
        else:
            did_setup = configure_did_registry(
                chain_config,
                actor_keys.identities(chain_config.chain_id),
                actor_keys,
            )
            write_json(setup_path, did_setup)
        resolved_dids = resolve_and_verify_dids(chain_config, bundle.identities)
        bind_resolved_documents(bundle, resolved_dids["documents"])
        audit.record(
            "did_resolution",
            accepted=True,
            code="DID_RESOLUTION_VERIFIED",
            detection_layer="did-vc-vp",
            did_document_hashes={
                did: sha256_json(document)
                for did, document in bundle.documents.items()
            },
            setup_path="../../../setup/did-registry.json",
            chain_id=chain_config.chain_id,
            registry_address=chain_config.did_registry_address,
        )
        write_json(temp_directory / "experiment-config.json", {
            "schema_version": "agentdid-comparison-experiment-v1",
            "run_id": args.run_id,
            "experiment_id": experiment_id,
            "scheme": SCHEME_LABELS[args.scheme],
            "scheme_id": args.scheme,
            "case_id": case.case_id,
            "case_name": case.name,
            "case_family": case.family,
            "description": case.description,
            "expected_accepted": outcome.accepted,
            "expected_code": outcome.code,
            "expected_detection_layer": outcome.detection_layer,
            "required_pass_layers": list(outcome.required_pass_layers),
            "chain": chain_config.public_dict(),
            "did_setup": "../../../setup/did-registry.json",
            "independent_state": bundle.independent_state,
            "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        })
        write_json(temp_directory / "did-documents.json", {
            "schema_version": "agentdid-resolved-documents-v1",
            "documents": bundle.documents,
            "resolutions": resolved_dids["resolutions"],
        })
        write_json(temp_directory / "credentials.json", {
            "credentials": bundle.credentials,
            "status_lists": bundle.status_lists,
        })
        write_json(temp_directory / "presentation.json", bundle.presentation)
        write_json(temp_directory / "state-and-context.json", bundle.state_artifact())
        write_json(
            temp_directory / "lineage-evidence.json",
            {
                "enabled": bundle.lineage is not None,
                "isolation": bundle.independent_state["lineage"],
                "evidence": bundle.lineage.public_dict() if bundle.lineage else None,
                "reason": (
                    None
                    if bundle.lineage
                    else "scheme records but does not enforce the Lineage control request"
                ),
            },
        )

        decision = evaluate_scheme(bundle)
        expected = outcome.accepted
        layer_passed = {
            "did-vc-vp": bool(decision.protocol.get("accepted")),
            "baseline-agentdid": bool(
                decision.baseline and decision.baseline.get("accepted")
            ),
            "lineage-agentdid": bool(
                decision.lineage and decision.lineage.get("accepted")
            ),
        }
        passed = (
            decision.accepted == outcome.accepted
            and decision.code == outcome.code
            and decision.detection_layer == outcome.detection_layer
            and all(layer_passed[layer] for layer in outcome.required_pass_layers)
        )
        latency_ms = (time.perf_counter() - started) * 1000
        result = {
            "schema_version": "agentdid-comparison-decision-v1",
            "status": "COMPLETED",
            "run_id": args.run_id,
            "experiment_id": experiment_id,
            "scheme": SCHEME_LABELS[args.scheme],
            "scheme_id": args.scheme,
            "case_id": args.case,
            "case_name": case.name,
            "family": case.family,
            "expected_accepted": expected,
            "expected_code": outcome.code,
            "expected_detection_layer": outcome.detection_layer,
            "accepted": decision.accepted,
            "passed": passed,
            "layer_passed": layer_passed,
            "code": decision.code,
            "reason": decision.reason,
            "detection_layer": decision.detection_layer,
            "latency_ms": round(latency_ms, 6),
            "completed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        }
        write_json(temp_directory / "verification-trace.json", {
            "protocol": decision.protocol,
            "baseline": decision.baseline,
            "lineage": decision.lineage,
        })
        write_json(temp_directory / "decision.json", result)

        audit.record(
            "protocol_verification",
            accepted=bool(decision.protocol["accepted"]),
            code=str(decision.protocol["code"]),
            detection_layer="did-vc-vp",
            request_hash=sha256_json(bundle.presentation),
            vp_hash=sha256_json(bundle.presentation),
            did_document_hashes={
                did: sha256_json(document)
                for did, document in bundle.documents.items()
            },
            credential_hashes=[sha256_json(item) for item in bundle.credentials],
        )
        if decision.baseline is not None:
            audit.record(
                "baseline_verification",
                accepted=bool(decision.baseline.get("accepted", decision.accepted)),
                code=str(decision.baseline.get("code", decision.code)),
                detection_layer="baseline-agentdid",
                state_hash=sha256_json(bundle.state_statement),
                context_hash=sha256_json(bundle.context_statement),
                context_version=bundle.context_statement.get("context_version"),
            )
        if decision.lineage is not None:
            audit.record(
                "lineage_verification",
                accepted=bool(decision.lineage["accepted"]),
                code=str(decision.lineage["code"]),
                detection_layer="lineage-agentdid",
                request_hash=sha256_json(bundle.lineage.invocation.unsigned_dict()),
                chain_depth=len(bundle.lineage.presented_chain),
                lineage_hash=sha256_json(bundle.lineage.public_dict()),
            )
        audit.record(
            "experiment_decision",
            accepted=decision.accepted,
            code=decision.code,
            detection_layer=decision.detection_layer,
            request_hash=sha256_json(bundle.presentation),
            expected_accepted=expected,
            passed=passed,
        )

        transactions = list(decision.chain_transactions)
        tx_hashes = _transaction_hashes(transactions)
        if transactions:
            audit.record(
                "chain_activity",
                accepted=decision.accepted,
                code="CHAIN_ACTIVITY_RECORDED",
                detection_layer="on-chain",
                transaction_hashes=tx_hashes,
                block_numbers=[
                    item.get("block_number")
                    for item in transactions
                    if item.get("block_number") is not None
                ],
            )
        chain_activity = {
            "schema_version": "agentdid-comparison-chain-activity-v1",
            "chain": chain_config.public_dict(),
            "shared_did_setup": "../../../setup/did-registry.json",
            "transactions": transactions,
            "lineage_events": decode_lineage_events(chain_config, tx_hashes),
        }
        write_json(temp_directory / "chain-activity.json", chain_activity)
        (temp_directory / "stdout.log").write_text(
            json.dumps({
                "experiment_id": experiment_id,
                "accepted": decision.accepted,
                "code": decision.code,
                "passed": passed,
            }, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (temp_directory / "stderr.log").write_text("", encoding="utf-8")
        manifest = build_evidence_manifest(
            temp_directory,
            run_id=args.run_id,
            experiment_id=experiment_id,
        )
        anchor = anchor_evidence(
            chain_config,
            actor_keys.chain_private_key,
            manifest["merkle_root"],
        )
        if not anchor.get("verification", {}).get("matches"):
            raise RuntimeError("chain anchor verification did not match the evidence root")
        write_json(temp_directory / "chain-anchor.json", {
            "schema_version": "agentdid-comparison-anchor-v1",
            "evidence_merkle_root": manifest["merkle_root"],
            **anchor,
        })
        finalize_experiment(temp_directory, final_directory)
        return (0 if passed else 2), final_directory
    except Exception as exc:
        error = {
            "schema_version": "agentdid-comparison-decision-v1",
            "status": "INFRA_ERROR",
            "run_id": args.run_id,
            "experiment_id": experiment_id,
            "scheme": SCHEME_LABELS[args.scheme],
            "scheme_id": args.scheme,
            "case_id": args.case,
            "case_name": case.name,
            "expected_accepted": outcome.accepted,
            "expected_code": outcome.code,
            "expected_detection_layer": outcome.detection_layer,
            "accepted": None,
            "passed": False,
            "code": "INFRA_ERROR",
            "reason": str(exc),
            "detection_layer": "infrastructure",
            "completed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        }
        write_json(temp_directory / "decision.json", error)
        audit.record(
            "experiment_failed",
            accepted=None,
            code="INFRA_ERROR",
            detection_layer="infrastructure",
            error_type=type(exc).__name__,
            error_hash=sha256_json({"type": type(exc).__name__, "message": str(exc)}),
        )
        (temp_directory / "stdout.log").write_text("", encoding="utf-8")
        (temp_directory / "stderr.log").write_text(traceback.format_exc(), encoding="utf-8")
        build_evidence_manifest(temp_directory, run_id=args.run_id, experiment_id=experiment_id)
        finalize_experiment(temp_directory, final_directory)
        return 1, final_directory


def _run_with_config(args: argparse.Namespace, config: ChainConfig) -> int:
    code, output = execute_experiment(args, config)
    print(json.dumps({"output": str(output), "exit_code": code}, ensure_ascii=False))
    return code


def main() -> int:
    args = parse_args()
    supplied = _config_from_args(args)
    if supplied is not None:
        return _run_with_config(args, supplied)
    if args.chain == "sepolia":
        return _run_with_config(args, sepolia_config())
    node_logs = Path(args.temp_root) / args.run_id / "standalone-chain"
    with HardhatNode(node_logs):
        deployment = deploy_local_contracts()
        return _run_with_config(args, local_config(deployment))


if __name__ == "__main__":
    raise SystemExit(main())
