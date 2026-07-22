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
DUMMY_SEPOLIA_CHAIN = ChainConfig(
    backend="sepolia",
    rpc_url="https://rpc.example/v2/secret-token",
    chain_id=11155111,
    did_registry_address="0x03d5003bf0e79C5F5223588F347ebA39AfbC3818",
    lineage_registry_address="0xD08c036042dC2B71dCD59be3E8A58689fb346198",
    confirmations=2,
    rpc_timeout_seconds=37.0,
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
        self.assertIn("--confirmations 1", joined)
        self.assertIn("--rpc-timeout-seconds 15.0", joined)
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

    def test_failed_full_sepolia_preflight_never_executes_or_falls_back(self) -> None:
        output = io.StringIO()
        root = Path(".codex") / "test_runs" / f"sepolia-{uuid.uuid4().hex}"
        failed = {
            "schema_version": "agentdid-sepolia-full-preflight-v1",
            "status": "FAILED",
            "passed": False,
            "code": "SEPOLIA_RELAYER_BALANCE_INSUFFICIENT",
            "fallback": False,
        }
        with patch(
            "_experiments.security_comparison.run_all.sepolia_config",
            return_value=DUMMY_SEPOLIA_CHAIN,
        ), patch(
            "_experiments.security_comparison.run_all.run_sepolia_full_preflight",
            return_value=failed,
        ), patch(
            "_experiments.security_comparison.run_all.execute_full_plan"
        ) as execute, patch(
            "_experiments.security_comparison.run_all.HardhatNode"
        ) as hardhat, contextlib.redirect_stdout(output):
            code = main([
                "--chain",
                "sepolia",
                "--run-id",
                f"unit-sepolia-{uuid.uuid4().hex[:12]}",
                "--output-root",
                str(root / "output"),
                "--temp-root",
                str(root / "temp"),
            ])
        payload = json.loads(output.getvalue())

        self.assertEqual(1, code)
        self.assertEqual("SEPOLIA_RELAYER_BALANCE_INSUFFICIENT", payload["code"])
        self.assertFalse(payload["fallback"])
        execute.assert_not_called()
        hardhat.assert_not_called()

    def test_successful_full_sepolia_preflight_uses_remote_config(self) -> None:
        root = Path(".codex") / "test_runs" / f"sepolia-{uuid.uuid4().hex}"
        run_id = f"unit-sepolia-{uuid.uuid4().hex[:12]}"
        passed = {
            "schema_version": "agentdid-sepolia-full-preflight-v1",
            "status": "PASSED",
            "passed": True,
            "code": "SEPOLIA_FULL_PREFLIGHT_OK",
            "run_id": run_id,
            "fallback": False,
            "gas_budget": {"fee_upper_bound_wei": 123456789},
            "did_setup_plan": {"roles_requiring_setup": []},
        }
        did_setup = {"transactions": []}
        with patch(
            "_experiments.security_comparison.run_all.sepolia_config",
            return_value=DUMMY_SEPOLIA_CHAIN,
        ), patch(
            "_experiments.security_comparison.run_all.run_sepolia_full_preflight",
            return_value=passed,
        ) as preflight, patch(
            "_experiments.security_comparison.run_all.load_actor_keys"
        ) as actor_loader, patch(
            "_experiments.security_comparison.run_all.configure_did_registry",
            return_value=did_setup,
        ), patch(
            "_experiments.security_comparison.run_all.execute_full_plan",
            return_value=0,
        ) as execute, patch(
            "_experiments.security_comparison.run_all.HardhatNode"
        ) as hardhat, contextlib.redirect_stdout(io.StringIO()):
            actor_loader.return_value.identities.return_value = {}
            code = main([
                "--chain",
                "sepolia",
                "--run-id",
                run_id,
                "--output-root",
                str(root / "output"),
                "--temp-root",
                str(root / "temp"),
            ])

        self.assertEqual(0, code)
        self.assertEqual(900.0, preflight.call_args.kwargs["child_timeout_seconds"])
        self.assertIs(DUMMY_SEPOLIA_CHAIN, execute.call_args.args[1])
        self.assertEqual(passed, execute.call_args.kwargs["full_preflight"])
        hardhat.assert_not_called()

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

    def test_sepolia_infrastructure_failure_is_always_fail_fast(self) -> None:
        calls = 0

        def timeout_executor(command, **kwargs):
            nonlocal calls
            calls += 1
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])

        root = Path(".codex") / "test_runs" / f"runall-{uuid.uuid4().hex}"
        args = SimpleNamespace(
            run_id="unit-sepolia-fail-fast",
            output_root=str(root / "output"),
            temp_root=str(root / "temp"),
            timeout_seconds=900.0,
            fail_fast=False,
        )
        with patch(
            "_experiments.security_comparison.run_all._live_anchor_verification",
            return_value={"passed": False, "verified": 0, "expected": 63, "checks": []},
        ), contextlib.redirect_stdout(io.StringIO()):
            code = execute_full_plan(
                args,
                DUMMY_SEPOLIA_CHAIN,
                executor=timeout_executor,
            )

        self.assertEqual(1, code)
        self.assertEqual(1, calls)


if __name__ == "__main__":
    unittest.main()
