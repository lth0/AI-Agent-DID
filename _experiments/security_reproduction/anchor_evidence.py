"""Anchor or verify an AgentDID JSONL security evidence record on Sepolia."""

from __future__ import annotations

import argparse
import json
import os
import sys


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from infrastructure.evidence_anchor import EthereumEvidenceAnchor  # noqa: E402
from infrastructure.load_config import load_key_config  # noqa: E402
from infrastructure.security import canonical_json, verify_evidence_event  # noqa: E402


def read_event(path: str, line_number: int) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        lines = [line for line in handle if line.strip()]
    if not lines:
        raise ValueError("Evidence file is empty")
    index = line_number - 1 if line_number > 0 else line_number
    return json.loads(lines[index])


def get_anchor(role: str) -> EthereumEvidenceAnchor:
    config = load_key_config()
    if role not in config["accounts"]:
        raise ValueError(f"Unknown anchor role: {role}")
    rpc_url = config.get("api_url") or config["api_url_pool"][0]
    return EthereumEvidenceAnchor(rpc_url, config["accounts"][role]["private_key"])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    anchor_parser = subparsers.add_parser("anchor")
    anchor_parser.add_argument("evidence_file")
    anchor_parser.add_argument("--line", type=int, default=-1, help="1-based line, or -1 for last")
    anchor_parser.add_argument("--role", default="agent_c_op")
    anchor_parser.add_argument("--no-wait", action="store_true")
    anchor_parser.add_argument("--output")

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("tx_hash")
    verify_parser.add_argument("--evidence-hash")
    verify_parser.add_argument("--role", default="agent_c_op")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        anchor = get_anchor(args.role)
        if args.command == "verify":
            result = anchor.verify_transaction(args.tx_hash, args.evidence_hash)
        else:
            event = read_event(args.evidence_file, args.line)
            valid, reason = verify_evidence_event(event)
            if not valid:
                raise ValueError(reason)
            result = anchor.submit(event["evidence_hash"], wait=not args.no_wait)
            output = args.output or os.path.join(
                PROJECT_ROOT, ".codex", "security_results", "blockchain_anchors.jsonl"
            )
            os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
            with open(output, "a", encoding="utf-8") as handle:
                handle.write(canonical_json(result) + "\n")
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return 0 if result.get("matches", True) else 1
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
