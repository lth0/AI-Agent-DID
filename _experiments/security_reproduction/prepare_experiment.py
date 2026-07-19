"""Generate a runtime network config for one controlled security scenario."""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import uuid


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_INPUT = os.path.join(PROJECT_ROOT, "config", "network_config.json")
DEFAULT_OUTPUT_DIR = os.path.join(PROJECT_ROOT, ".codex", "security_experiments")

SCENARIOS = (
    "baseline",
    "impersonation",
    "vp_replay",
    "vc_replay_duplicate",
    "false_capability",
    "false_state",
    "context_reset_secure",
    "context_reset_legacy",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("--input", default=DEFAULT_INPUT)
    parser.add_argument("--holder", default="Holder-A")
    parser.add_argument("--impersonated-did", default="")
    parser.add_argument(
        "--legacy-verifier",
        action="store_true",
        help="Disable strict checks to reproduce the original 2v2 verifier behaviour.",
    )
    parser.add_argument(
        "--real-llm",
        action="store_true",
        help="Use the configured LLM instead of deterministic local responses.",
    )
    return parser.parse_args()


def prepare(args: argparse.Namespace) -> tuple[str, dict]:
    with open(args.input, "r", encoding="utf-8") as handle:
        config = json.load(handle)

    result = copy.deepcopy(config)
    result["experiment_id"] = f"{args.scenario}-{uuid.uuid4()}"

    selected_holder = None
    for holder in result.get("holders", []):
        holder["security"] = {
            "attack_mode": "none",
            "allow_unsafe_reset": False,
            "deterministic_mode": not args.real_llm,
        }
        if holder.get("name") == args.holder:
            selected_holder = holder

    if selected_holder is None:
        raise ValueError(f"Holder {args.holder!r} not found in {args.input}")

    if args.scenario in {
        "impersonation", "vp_replay", "vc_replay_duplicate",
        "false_capability", "false_state",
    }:
        selected_holder["security"]["attack_mode"] = args.scenario

    if args.scenario == "impersonation":
        if not args.impersonated_did:
            raise ValueError("--impersonated-did is required for impersonation")
        selected_holder["security"]["impersonated_did"] = args.impersonated_did

    if args.scenario == "context_reset_legacy":
        selected_holder["security"]["allow_unsafe_reset"] = True

    strict_verifier = not args.legacy_verifier
    for verifier in result.get("verifiers", []):
        verifier["strict_security"] = strict_verifier

    os.makedirs(DEFAULT_OUTPUT_DIR, exist_ok=True)
    output_file = os.path.join(DEFAULT_OUTPUT_DIR, f"{args.scenario}_network.json")
    with open(output_file, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, ensure_ascii=False)
    return output_file, result


def main() -> int:
    args = parse_args()
    try:
        output_file, config = prepare(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    print(output_file)
    print(f"experiment_id={config['experiment_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
