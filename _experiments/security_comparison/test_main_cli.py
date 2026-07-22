from __future__ import annotations

import contextlib
import io
import json
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import main as entrypoint


class MainCliTests(unittest.TestCase):
    def test_single_routes_normalized_scheme_and_case(self) -> None:
        with patch("main.run_single", return_value=0) as run_single, patch(
            "main.run_full"
        ) as run_full:
            code = entrypoint.main([
                "single",
                "--scheme",
                "Baseline-AgentDID",
                "--case",
                "a04",
                "--chain",
                "hardhat",
                "--run-id",
                "unit-single",
                "--experiment-id",
                "unit-experiment",
                "--lineage-epoch",
                "17",
                "--output-root",
                ".codex/unit-output",
                "--temp-root",
                ".codex/unit-temp",
            ])

        self.assertEqual(0, code)
        run_full.assert_not_called()
        args = run_single.call_args.args[0]
        self.assertEqual("baseline", args.scheme)
        self.assertEqual("A04", args.case_id)
        self.assertEqual("hardhat", args.chain)
        self.assertEqual("unit-single", args.run_id)
        self.assertEqual("unit-experiment", args.experiment_id)
        self.assertEqual(17, args.lineage_epoch)
        self.assertEqual(".codex/unit-output", args.output_root)
        self.assertEqual(".codex/unit-temp", args.temp_root)

    def test_all_routes_only_to_full_runner(self) -> None:
        with patch("main.run_full", return_value=0) as run_full, patch(
            "main.run_single"
        ) as run_single:
            code = entrypoint.main([
                "all",
                "--chain",
                "sepolia",
                "--run-id",
                "unit-full",
                "--timeout",
                "45",
                "--fail-fast",
                "--dry-run",
            ])

        self.assertEqual(0, code)
        run_single.assert_not_called()
        args = run_full.call_args.args[0]
        self.assertEqual("sepolia", args.chain)
        self.assertEqual("unit-full", args.run_id)
        self.assertEqual(45.0, args.timeout_seconds)
        self.assertTrue(args.fail_fast)
        self.assertTrue(args.dry_run)

    def test_delegate_exit_codes_are_preserved(self) -> None:
        for expected in (0, 1, 2):
            with self.subTest(exit_code=expected), patch(
                "main.run_single", return_value=expected
            ):
                self.assertEqual(
                    expected,
                    entrypoint.main([
                        "single",
                        "--scheme",
                        "original",
                        "--case",
                        "H00",
                    ]),
                )

    def test_single_requires_valid_scheme_and_case(self) -> None:
        invalid_commands = (
            ["single", "--case", "H00"],
            ["single", "--scheme", "baseline"],
            ["single", "--scheme", "unknown", "--case", "H00"],
            ["single", "--scheme", "baseline", "--case", "Z99"],
            ["single", "--scheme", "baseline", "--case", "H00", "--chain", "other"],
            ["single", "--scheme", "baseline", "--case", "H00", "--chain-id", "31337"],
        )
        for command in invalid_commands:
            with self.subTest(command=command), contextlib.redirect_stderr(
                io.StringIO()
            ), self.assertRaises(SystemExit) as raised:
                entrypoint.main(command)
            self.assertEqual(2, raised.exception.code)

    def test_run_id_rejects_path_traversal_and_absolute_paths(self) -> None:
        invalid_ids = ("../escape", r"..\escape", r"C:\escape", "/tmp/escape")
        for run_id in invalid_ids:
            with self.subTest(run_id=run_id), contextlib.redirect_stderr(
                io.StringIO()
            ), self.assertRaises(SystemExit) as raised:
                entrypoint.main([
                    "single",
                    "--scheme",
                    "baseline",
                    "--case",
                    "A04",
                    "--run-id",
                    run_id,
                ])
            self.assertEqual(2, raised.exception.code)

    def test_single_setup_value_error_is_infrastructure_exit_one(self) -> None:
        output = io.StringIO()
        with patch(
            "_experiments.security_comparison.run_one.main",
            side_effect=ValueError("missing RPC configuration"),
        ), contextlib.redirect_stdout(output):
            code = entrypoint.main([
                "single",
                "--scheme",
                "baseline",
                "--case",
                "A04",
            ])
        payload = json.loads(output.getvalue())

        self.assertEqual(1, code)
        self.assertEqual("INFRA_ERROR", payload["status"])
        self.assertEqual("SINGLE_RUN_SETUP_FAILED", payload["code"])
        self.assertEqual(1, payload["exit_code"])

    def test_standalone_hardhat_single_refuses_existing_run_id(self) -> None:
        root = Path(".codex") / "test_runs" / f"single-{uuid.uuid4().hex}"
        run_id = "existing-single"
        (root / "output" / run_id).mkdir(parents=True)
        output = io.StringIO()
        with patch("_experiments.security_comparison.run_one.main") as run_one, contextlib.redirect_stdout(output):
            code = entrypoint.main([
                "single",
                "--scheme",
                "original",
                "--case",
                "H00",
                "--run-id",
                run_id,
                "--output-root",
                str(root / "output"),
                "--temp-root",
                str(root / "temp"),
            ])
        payload = json.loads(output.getvalue())

        self.assertEqual(1, code)
        self.assertEqual("STANDALONE_RUN_ID_ALREADY_EXISTS", payload["code"])
        run_one.assert_not_called()

    def test_direct_run_one_also_refuses_stale_standalone_chain_state(self) -> None:
        from _experiments.security_comparison import run_one

        root = Path(".codex") / "test_runs" / f"run-one-{uuid.uuid4().hex}"
        run_id = "existing-direct-single"
        (root / "output" / run_id).mkdir(parents=True)
        output = io.StringIO()
        with patch.object(run_one, "HardhatNode") as hardhat, contextlib.redirect_stdout(output):
            code = run_one.main([
                "--scheme",
                "original",
                "--case",
                "H00",
                "--run-id",
                run_id,
                "--output-root",
                str(root / "output"),
                "--temp-root",
                str(root / "temp"),
            ])
        payload = json.loads(output.getvalue())

        self.assertEqual(1, code)
        self.assertEqual("STANDALONE_RUN_ID_ALREADY_EXISTS", payload["code"])
        hardhat.assert_not_called()

    def test_full_mode_does_not_accept_scheme_or_case_filters(self) -> None:
        for option in (("--scheme", "baseline"), ("--case", "A04")):
            with self.subTest(option=option), contextlib.redirect_stderr(
                io.StringIO()
            ), self.assertRaises(SystemExit) as raised:
                entrypoint.main(["all", *option])
            self.assertEqual(2, raised.exception.code)

    def test_list_json_reports_21_by_3_matrix(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = entrypoint.main(["list", "--json"])
        payload = json.loads(output.getvalue())

        self.assertEqual(0, code)
        self.assertEqual(3, len(payload["schemes"]))
        self.assertEqual(21, len(payload["cases"]))
        self.assertEqual(63, payload["full_experiment_count"])
        self.assertEqual(
            {"original", "baseline", "lineage"},
            {item["id"] for item in payload["schemes"]},
        )
        self.assertIn("H00", {item["id"] for item in payload["cases"]})


if __name__ == "__main__":
    unittest.main()
