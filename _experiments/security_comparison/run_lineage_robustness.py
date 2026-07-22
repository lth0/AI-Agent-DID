"""Canonical CLI for phased Agent lineage robustness checks."""

from __future__ import annotations

import argparse
import uuid

from _experiments.security_comparison.cases import (
    LINEAGE_L06_L14_ROBUSTNESS_CASE_IDS,
    LINEAGE_L06_L14_ROBUSTNESS_CHECKS,
    LINEAGE_PHASE1_CASE_IDS,
    LINEAGE_PHASE1_CHECKS,
)
from _experiments.security_comparison.cli_common import run_id_argument
from _experiments.security_comparison.run_lineage_phase1 import (
    PROJECT_ROOT,
    run_group,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run phased Agent lineage robustness checks on Hardhat",
    )
    parser.add_argument("--phase", choices=("1", "2"), default="1")
    parser.add_argument("--run-id", type=run_id_argument)
    parser.add_argument(
        "--output-root",
        default=str(PROJECT_ROOT / ".codex" / "comparison_runs"),
    )
    parser.add_argument(
        "--temp-root",
        default=str(PROJECT_ROOT / ".codex" / "comparison_tmp"),
    )
    args = parser.parse_args()
    if not args.run_id:
        scope = "l01-l05" if args.phase == "1" else "l06-l14"
        args.run_id = f"lineage-robustness-{scope}-" + uuid.uuid4().hex[:12]
    return args


def main() -> int:
    args = parse_args()
    if args.phase == "1":
        return run_group(
            args,
            case_ids=LINEAGE_PHASE1_CASE_IDS,
            robustness_definitions=LINEAGE_PHASE1_CHECKS,
            output_stem="lineage-robustness",
        )
    return run_group(
        args,
        case_ids=LINEAGE_L06_L14_ROBUSTNESS_CASE_IDS,
        robustness_definitions=LINEAGE_L06_L14_ROBUSTNESS_CHECKS,
        output_stem="lineage-robustness-l06-l14",
    )


if __name__ == "__main__":
    raise SystemExit(main())
