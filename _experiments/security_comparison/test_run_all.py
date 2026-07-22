from __future__ import annotations

import contextlib
import io
import json
import subprocess
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from _experiments.security_comparison.cases import CASE_BY_ID, SCHEMES
from _experiments.security_comparison.chain import ChainConfig
from _experiments.security_comparison.run_all import (
    FULL_CASE_IDS,
    FULL_EXPERIMENT_COUNT,
    build_child_command,
    build_full_plan,
    execute_full_plan,
    main,
)


DUMMY_CHAIN = ChainConfig(
    backend="hardhat",
    rpc_url="http://127.0.0.1:8545",
    chain_id=31337,
    did_registry_address="0x0000000000000000000000000000000000000001",
    lineage_registry_address="0x0000000000000000000000000000000000000002",
)


class FullRunPlanTests(unittest.TestCase):
    def test_plan_contains_exactly_all_63_scheme_case_pairs(self) -> None:
        plan = build_full_plan("unit-full")

        self.assertEqual(21, len(FULL_CASE_IDS))
        self.assertEqual(63, FULL_EXPERIMENT_COUNT)
        self.assertEqual(63, len(plan))
        self.assertEqual(set(CASE_BY_ID), set(FULL_CASE_IDS))
        self.assertEqual(
            {
                (scheme, case_id)
                for case_id in FULL_CASE_IDS
                for scheme in SCHEMES
            },
            {(item["scheme"], item["case_id"]) for item in plan},
        )

    def test_plan_order_and_independent_identifiers_are_stable(self) -> None:
        first = build_full_plan("unit-full")
        second = build_full_plan("unit-full")

        self.assertEqual(first, second)
        self.assertEqual(list(range(1, 64)), [item["ordinal"] for item in first])
        self.assertEqual(list(range(1, 64)), [item["lineage_epoch"] for item in first])
        self.assertEqual(63, len({item["experiment_id"] for item in first}))
        self.assertEqual(
            [("original", "H00"), ("baseline", "H00"), ("lineage", "H00")],
            [(item["scheme"], item["case_id"]) for item in first[:3]],
        )

    def test_child_command_targets_run_one_with_shared_chain_config(self) -> None:
        item = build_full_plan("unit-full")[10]
        command = build_child_command(
            item,
            run_id="unit-full",
            output_root=Path(".codex/output"),
            temp_root=Path(".codex/temp"),
            chain=DUMMY_CHAIN,
        )
        joined = " ".join(command)

        self.assertIn("_experiments.security_comparison.run_one", command)
        self.assertIn(f"--scheme {item['scheme']}", joined)
        self.assertIn(f"--case {item['case_id']}", joined)
        self.assertIn("--chain hardhat", joined)
        self.assertIn("--chain-id 31337", joined)
        self.assertIn(DUMMY_CHAIN.did_registry_address, command)
        self.assertIn(DUMMY_CHAIN.lineage_registry_address, command)
        self.assertNotIn(DUMMY_CHAIN.rpc_url, command)

    def test_dry_run_prints_complete_plan_without_chain_access(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["--dry-run", "--run-id", "unit-dry-run"])
        payload = json.loads(output.getvalue())

        self.assertEqual(0, code)
        self.assertEqual(63, payload["planned"])
        self.assertEqual(63, len(payload["plan"]))
        self.assertEqual("full-63-dry-run", payload["mode"])

    def test_full_sepolia_is_blocked_before_any_remote_execution(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main([
                "--chain",
                "sepolia",
                "--run-id",
                f"unit-sepolia-{uuid.uuid4().hex[:12]}",
            ])
        payload = json.loads(output.getvalue())

        self.assertEqual(1, code)
        self.assertEqual("SEPOLIA_FULL_PREFLIGHT_INCOMPLETE", payload["code"])
        self.assertFalse(payload["fallback"])

    def test_timeout_continues_through_all_63_items_by_default(self) -> None:
        calls = 0

        def timeout_executor(command, **kwargs):
            nonlocal calls
            calls += 1
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])

        root = Path(".codex") / "test_runs" / f"runall-{uuid.uuid4().hex}"
        args = SimpleNamespace(
            run_id="unit-timeouts",
            output_root=str(root / "output"),
            temp_root=str(root / "temp"),
            timeout_seconds=0.01,
            fail_fast=False,
        )
        with patch(
            "_experiments.security_comparison.run_all._live_anchor_verification",
            return_value={"passed": False, "verified": 0, "expected": 63, "checks": []},
        ), contextlib.redirect_stdout(io.StringIO()):
            code = execute_full_plan(args, DUMMY_CHAIN, executor=timeout_executor)
        summary = json.loads(
            (root / "output" / "unit-timeouts" / "summary.json").read_text(
                encoding="utf-8"
            )
        )

        self.assertEqual(1, code)
        self.assertEqual(63, calls)
        self.assertEqual(63, summary["executed"])
        self.assertEqual(63, summary["infra_errors"])
        self.assertFalse(summary["integrity_ok"])

    def test_fail_fast_stops_after_first_timeout(self) -> None:
        calls = 0

        def timeout_executor(command, **kwargs):
            nonlocal calls
            calls += 1
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])

        root = Path(".codex") / "test_runs" / f"runall-{uuid.uuid4().hex}"
        args = SimpleNamespace(
            run_id="unit-fail-fast",
            output_root=str(root / "output"),
            temp_root=str(root / "temp"),
            timeout_seconds=0.01,
            fail_fast=True,
        )
        with patch(
            "_experiments.security_comparison.run_all._live_anchor_verification",
            return_value={"passed": False, "verified": 0, "expected": 63, "checks": []},
        ), contextlib.redirect_stdout(io.StringIO()):
            code = execute_full_plan(args, DUMMY_CHAIN, executor=timeout_executor)

        self.assertEqual(1, code)
        self.assertEqual(1, calls)


if __name__ == "__main__":
    unittest.main()
