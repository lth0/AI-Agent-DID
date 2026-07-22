"""Unified command-line entry for AgentDID comparison experiments.

Examples:
    python main.py single --scheme baseline --case A04
    python main.py all
    python main.py list
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from _experiments.security_comparison.cases import (
    CASE_BY_ID,
    LINEAGE_ROBUSTNESS_CASE_IDS,
    ROBUSTNESS_CASE_IDS,
    SCHEME_LABELS,
    SCHEMES,
)
from _experiments.security_comparison.cli_common import run_id_argument


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_OUTPUT_ROOT = PROJECT_ROOT / ".codex" / "comparison_runs"
DEFAULT_TEMP_ROOT = PROJECT_ROOT / ".codex" / "comparison_tmp"
SCHEME_ALIASES = {
    "original": "original",
    "original-agentdid": "original",
    "baseline": "baseline",
    "baseline-agentdid": "baseline",
    "lineage": "lineage",
    "lineage-agentdid": "lineage",
}
DISPLAY_CASE_IDS = ("H00", *ROBUSTNESS_CASE_IDS, *LINEAGE_ROBUSTNESS_CASE_IDS)


def _scheme_argument(value: str) -> str:
    normalized = value.strip().lower().replace("_", "-")
    try:
        return SCHEME_ALIASES[normalized]
    except KeyError as exc:
        allowed = ", ".join(SCHEMES)
        raise argparse.ArgumentTypeError(
            f"unsupported DID scheme {value!r}; choose one of: {allowed}"
        ) from exc


def _case_argument(value: str) -> str:
    normalized = value.strip().upper()
    if normalized not in CASE_BY_ID:
        allowed = ", ".join(sorted(CASE_BY_ID))
        raise argparse.ArgumentTypeError(
            f"unsupported case {value!r}; choose one of: {allowed}"
        )
    return normalized


def _positive_integer(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def _positive_seconds(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("timeout must be greater than zero")
    return parsed


def _add_storage_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--run-id",
        type=run_id_argument,
        help="stable, single-component identifier for this run",
    )
    parser.add_argument(
        "--output-root",
        default=str(DEFAULT_OUTPUT_ROOT),
        help="final evidence root (default: .codex/comparison_runs)",
    )
    parser.add_argument(
        "--temp-root",
        default=str(DEFAULT_TEMP_ROOT),
        help="temporary work root (default: .codex/comparison_tmp)",
    )
    parser.add_argument(
        "--chain",
        choices=("hardhat", "sepolia"),
        default="hardhat",
        help=(
            "blockchain backend; Sepolia never falls back to Hardhat, and full "
            "Sepolia runs remain blocked until complete preflight is available"
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Run AgentDID single experiments or the complete 63-item matrix",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    single = commands.add_parser(
        "single",
        help="run exactly one DID scheme and one test case",
    )
    single.add_argument(
        "--scheme",
        required=True,
        type=_scheme_argument,
        help="original, baseline, lineage, or the corresponding *-AgentDID label",
    )
    single.add_argument(
        "--case",
        "--case-id",
        dest="case_id",
        required=True,
        type=_case_argument,
        help="H00, A01-A06, or L01-L14 (case-insensitive)",
    )
    single.add_argument("--experiment-id")
    single.add_argument("--lineage-epoch", type=_positive_integer, default=1)
    single.add_argument("--chain-id", type=_positive_integer)
    single.add_argument("--did-registry")
    single.add_argument("--lineage-registry")
    _add_storage_arguments(single)

    full = commands.add_parser(
        "all",
        help="run the fixed 21 cases x 3 schemes = 63 experiments",
    )
    full.add_argument(
        "--timeout-seconds",
        "--timeout",
        dest="timeout_seconds",
        type=_positive_seconds,
        default=300.0,
        help="maximum runtime for each isolated child process",
    )
    full.add_argument(
        "--fail-fast",
        action="store_true",
        help="stop at the first failed child; intended only for debugging",
    )
    full.add_argument(
        "--dry-run",
        action="store_true",
        help="print all 63 planned instances without starting the chain",
    )
    _add_storage_arguments(full)

    listing = commands.add_parser(
        "list",
        help="list the supported DID schemes and test cases",
    )
    listing.add_argument("--json", action="store_true", dest="as_json")
    return parser


def _append_common_arguments(arguments: list[str], args: argparse.Namespace) -> None:
    arguments.extend(["--chain", args.chain])
    if args.run_id:
        arguments.extend(["--run-id", args.run_id])
    arguments.extend(["--output-root", args.output_root])
    arguments.extend(["--temp-root", args.temp_root])


def _validate_single_chain_arguments(args: argparse.Namespace) -> None:
    supplied = (args.chain_id, args.did_registry, args.lineage_registry)
    if any(value is not None for value in supplied) and not all(
        value is not None for value in supplied
    ):
        raise ValueError(
            "--chain-id, --did-registry and --lineage-registry must be supplied together"
        )


def _standalone_single_conflicts(args: argparse.Namespace) -> list[str]:
    supplied = (args.chain_id, args.did_registry, args.lineage_registry)
    if args.chain != "hardhat" or all(value is not None for value in supplied):
        return []
    if not args.run_id:
        return []
    paths = (
        Path(args.output_root).resolve() / args.run_id,
        Path(args.temp_root).resolve() / args.run_id,
    )
    return [str(path) for path in paths if path.exists()]


def run_single(args: argparse.Namespace) -> int:
    """Delegate one instance to the established isolated experiment runner."""

    from _experiments.security_comparison import run_one

    existing = _standalone_single_conflicts(args)
    if existing:
        print(json.dumps({
            "status": "INFRA_ERROR",
            "code": "STANDALONE_RUN_ID_ALREADY_EXISTS",
            "run_id": args.run_id,
            "paths": existing,
            "reason": "standalone Hardhat single runs require a fresh run-id",
            "exit_code": 1,
        }, ensure_ascii=False))
        return 1

    forwarded = [
        "--scheme",
        args.scheme,
        "--case",
        args.case_id,
        "--lineage-epoch",
        str(args.lineage_epoch),
    ]
    if args.experiment_id:
        forwarded.extend(["--experiment-id", args.experiment_id])
    supplied_chain = (args.chain_id, args.did_registry, args.lineage_registry)
    if all(value is not None for value in supplied_chain):
        forwarded.extend([
            "--chain-id",
            str(args.chain_id),
            "--did-registry",
            args.did_registry,
            "--lineage-registry",
            args.lineage_registry,
        ])
    _append_common_arguments(forwarded, args)
    try:
        return run_one.main(forwarded)
    except Exception as exc:
        print(json.dumps({
            "status": "INFRA_ERROR",
            "code": "SINGLE_RUN_SETUP_FAILED",
            "reason": type(exc).__name__,
            "exit_code": 1,
        }, ensure_ascii=False))
        return 1


def run_full(args: argparse.Namespace) -> int:
    """Delegate the fixed 63-item matrix to the shared-chain orchestrator."""

    from _experiments.security_comparison import run_all

    forwarded = ["--timeout-seconds", str(args.timeout_seconds)]
    if args.fail_fast:
        forwarded.append("--fail-fast")
    if args.dry_run:
        forwarded.append("--dry-run")
    _append_common_arguments(forwarded, args)
    return run_all.main(forwarded)


def list_capabilities(*, as_json: bool = False) -> int:
    payload = {
        "schemes": [
            {"id": scheme, "label": SCHEME_LABELS[scheme]}
            for scheme in SCHEMES
        ],
        "cases": [
            {
                "id": case.case_id,
                "name": case.name,
                "family": case.family,
                "description": case.description,
            }
            for case in (CASE_BY_ID[case_id] for case_id in DISPLAY_CASE_IDS)
        ],
        "full_experiment_count": len(SCHEMES) * len(CASE_BY_ID),
    }
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    print("DID schemes:")
    for item in payload["schemes"]:
        print(f"  {item['id']:<8} {item['label']}")
    print("\nTest cases:")
    for item in payload["cases"]:
        print(f"  {item['id']:<3} {item['name']}: {item['description']}")
    print(f"\nFull matrix: {payload['full_experiment_count']} experiments")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "single":
        try:
            _validate_single_chain_arguments(args)
        except ValueError as exc:
            parser.error(str(exc))
        return run_single(args)
    if args.command == "all":
        return run_full(args)
    return list_capabilities(as_json=args.as_json)


if __name__ == "__main__":
    raise SystemExit(main())
