"""Create evaluator-signed benchmark evidence for the strict Issuer control."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import sys
import uuid


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from infrastructure.security import canonical_json  # noqa: E402
from infrastructure.wallet import IdentityWallet  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-role", default="agent_a_op")
    parser.add_argument("--evaluator-role", default="agent_c_op")
    parser.add_argument("--rating", type=float, default=0.75)
    parser.add_argument("--dataset-id", default="agentdid-security-benchmark-v1")
    parser.add_argument("--report", default="controlled benchmark completed")
    parser.add_argument("--output")
    return parser.parse_args()


def digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def main() -> int:
    args = parse_args()
    if not 0.0 <= args.rating <= 1.0:
        print("--rating must be in [0, 1]", file=sys.stderr)
        return 2

    evaluated_agent = IdentityWallet(args.agent_role)
    evaluator = IdentityWallet(args.evaluator_role)
    evidence = {
        "evaluationRunId": f"eval-{uuid.uuid4()}",
        "evaluatedAgentDID": evaluated_agent.did,
        "evaluatorDID": evaluator.did,
        "datasetHash": digest(args.dataset_id),
        "ratingValue": f"{args.rating:.3f}",
        "evaluatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "reportHash": digest(args.report),
    }
    evidence["signature"] = evaluator.sign_message(canonical_json(evidence))

    output = args.output or os.path.join(
        PROJECT_ROOT, ".codex", "security_experiments",
        f"capability_evidence_{args.agent_role}.json",
    )
    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(evidence, handle, indent=2, ensure_ascii=False)
    print(os.path.abspath(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
