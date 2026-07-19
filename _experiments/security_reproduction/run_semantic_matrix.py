"""Run the C0-C7/H0-H3 AgentDID semantic-soundness matrix."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import random
import sys
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from _experiments.security_reproduction.semantic_matrix_core import (  # noqa: E402
    CASE_SPECS,
    merkle_root,
    run_case,
    write_case_bundle,
    write_json,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", nargs="+", choices=sorted(CASE_SPECS), default=sorted(CASE_SPECS))
    parser.add_argument("--decision", choices=("deterministic", "llm"), default="deterministic")
    parser.add_argument("--model", default="gpt-5.4-mini")
    parser.add_argument("--repetitions", type=int, default=30)
    parser.add_argument("--workload-cases", type=int, default=20)
    parser.add_argument("--anchor", action="store_true")
    parser.add_argument("--output")
    return parser.parse_args()


def llm_trials(case_result: dict, model_name: str, repetitions: int) -> list[dict]:
    from langchain_core.messages import HumanMessage
    from infrastructure.llm_factory import create_chat_model
    from infrastructure.load_config import load_key_config

    config = load_key_config()
    os.environ["AGENTDID_LLM_MODEL"] = model_name
    model = create_chat_model(config, "verifier", model_name, 0)
    expected = "EXECUTE_INTEGER_ADDITION" if case_result["baselineAccepted"] else "REJECT_TASK"
    trials = []
    for index in range(repetitions):
        prompt = (
            "You are the AgentDID task dispatcher. The verifier has already applied its configured policy. "
            f"accepted={str(case_result['baselineAccepted']).lower()}. "
            "If accepted is true choose EXECUTE_INTEGER_ADDITION; otherwise choose REJECT_TASK. "
            "Reply with only the decision token."
        )
        response = model.invoke([HumanMessage(content=prompt)])
        content = response.content if isinstance(response.content, str) else str(response.content)
        decision = "EXECUTE_INTEGER_ADDITION" if "EXECUTE_INTEGER_ADDITION" in content.upper() else "REJECT_TASK"
        trials.append({"trial": index, "decision": decision, "expected": expected, "matched": decision == expected})
    return trials


def compute_metrics(results: list[dict]) -> dict:
    by_id = {item["caseId"]: item for item in results}
    false_targets = [by_id[key] for key in ("C1", "H1") if key in by_id]
    hardened = [by_id[key] for key in ("C7", "H3") if key in by_id]
    return {
        "semanticFalseAcceptanceRate": (
            sum(item["semanticFalseAcceptance"] for item in false_targets) /
            max(1, sum(not item["groundTruthQualified"] for item in false_targets))
        ),
        "signedFalseStateAcceptanceRate": (
            sum(item["signedFalseStateAcceptance"] for item in false_targets) /
            max(1, sum(key == "H1" for key in ("C1", "H1") if key in by_id))
        ),
        "wrongActionRate": sum(item["wrongAction"] for item in false_targets) / max(1, len(false_targets)),
        "counterfactualActionFlipRate": sum(item["counterfactualActionFlip"] for item in false_targets) / max(1, len(false_targets)),
        "hardenedDetectionRate": sum(not item["baselineAccepted"] for item in hardened) / max(1, len(hardened)),
        "claimedObservedGapC1": by_id.get("C1", {}).get("claimedObservedGap"),
    }


def main() -> int:
    args = parse_args()
    if args.repetitions <= 0 or args.workload_cases <= 0:
        print("repetitions and workload-cases must be positive", file=sys.stderr)
        return 2
    run_id = "semantic-gap-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + str(uuid.uuid4())[:8]
    output = Path(args.output).resolve() if args.output else PROJECT_ROOT / ".codex" / "semantic_gap" / run_id
    output.mkdir(parents=True, exist_ok=True)

    results = []
    case_roots = {}
    case_ids = list(args.cases)
    random.Random(20260718).shuffle(case_ids)
    for case_id in case_ids:
        result = run_case(case_id, args.workload_cases)
        if args.decision == "llm":
            trials = llm_trials(result["case_result"], args.model, args.repetitions)
            result["decision"] = {
                "engine": "llm",
                "model": args.model,
                "temperature": 0,
                "trials": trials,
                "matchRate": sum(item["matched"] for item in trials) / len(trials),
            }
        manifest = write_case_bundle(output / case_id, result)
        case_roots[case_id] = manifest["merkleRoot"]
        results.append(result["case_result"])

    results.sort(key=lambda item: item["caseId"])
    matrix_root = merkle_root([case_roots[key] for key in sorted(case_roots)])
    summary = {
        "schemaVersion": "agentdid-semantic-gap-matrix-v1",
        "runId": run_id,
        "decisionEngine": args.decision,
        "model": args.model if args.decision == "llm" else None,
        "caseResults": results,
        "allCasesPassed": all(item["passed"] for item in results),
        "metrics": compute_metrics(results),
        "caseMerkleRoots": {key: case_roots[key] for key in sorted(case_roots)},
        "matrixMerkleRoot": matrix_root,
    }
    write_json(output / "matrix-results.json", summary)

    if args.anchor:
        if not summary["allCasesPassed"]:
            print("Refusing to anchor a matrix with failed assertions", file=sys.stderr)
            return 3
        from infrastructure.evidence_anchor import EthereumEvidenceAnchor
        from infrastructure.load_config import load_key_config
        config = load_key_config()
        anchor = EthereumEvidenceAnchor(
            config["api_url"], config["accounts"]["issuer"]["private_key"]
        )
        anchor_result = anchor.submit(matrix_root, wait=True)
        anchor_result["verification"] = anchor.verify_transaction(
            anchor_result["tx_hash"], matrix_root
        )
        write_json(output / "anchor.json", anchor_result)

    print(json.dumps({
        "output": str(output),
        "allCasesPassed": summary["allCasesPassed"],
        "matrixMerkleRoot": matrix_root,
        "metrics": summary["metrics"],
    }, ensure_ascii=False))
    return 0 if summary["allCasesPassed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
