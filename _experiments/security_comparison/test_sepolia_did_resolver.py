from __future__ import annotations

import io
import hashlib
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from eth_account import Account

from _experiments.security_comparison.chain import (
    ActorKeys,
    ChainConfig,
    DEFAULT_SEPOLIA_DID_REGISTRY,
    DEFAULT_SEPOLIA_LINEAGE_REGISTRY,
)
from _experiments.security_comparison.evidence import write_json
from _experiments.security_comparison.preflight import run_sepolia_did_preflight
from _experiments.security_comparison.run_all import build_full_plan
from _experiments.security_comparison.run_one import _run_with_config
from infrastructure.security import sha256_json


class _FakeEth:
    def __init__(self, *, chain_id: int = 11155111, code: bytes = b"\x60\x00"):
        self.chain_id = chain_id
        self.syncing = False
        self._code = code

    def get_block(self, block_identifier: str) -> dict:
        if block_identifier != "latest":
            raise AssertionError("preflight must inspect the latest remote block")
        return {"number": 123456, "hash": b"\x11" * 32}

    def get_code(self, address: str) -> bytes:
        return self._code


class _FakeWeb3:
    def __init__(
        self,
        *,
        chain_id: int = 11155111,
        code: bytes = b"\x60\x00",
        connection_error: BaseException | None = None,
    ):
        self.eth = _FakeEth(chain_id=chain_id, code=code)
        self.connection_error = connection_error

    def is_connected(self) -> bool:
        if self.connection_error:
            raise self.connection_error
        return True


def _config() -> ChainConfig:
    return ChainConfig(
        backend="sepolia",
        rpc_url="https://rpc.example/v2/secret-token",
        chain_id=11155111,
        did_registry_address=DEFAULT_SEPOLIA_DID_REGISTRY,
        lineage_registry_address=DEFAULT_SEPOLIA_LINEAGE_REGISTRY,
        confirmations=2,
    )


def _full_preflight_report(
    config: ChainConfig,
    *,
    run_id: str,
) -> dict:
    plan = build_full_plan(run_id)
    checks = (
        "static_configuration",
        "actor_configuration",
        "did_resolver_available",
        "rpc_connected",
        "chain_id",
        "node_synced",
        "fee_data",
        "registry_bytecode",
        "did_registry_interface",
        "did_setup_plan",
        "lineage_registry_interface",
        "run_namespace_unused",
        "payer_nonce_and_balance",
        "gas_cost_cap",
    )
    actors = _attestation_actor_keys()
    roles = {
        role: {
            "controller": Account.from_key(actors.controllers[role]).address,
            "operation": Account.from_key(actors.operations[role]).address,
        }
        for role in ("issuer", "holder", "verifier", "alternate", "evaluator")
    }
    return {
        "schema_version": "agentdid-sepolia-full-preflight-v1",
        "status": "PASSED",
        "passed": True,
        "code": "SEPOLIA_FULL_PREFLIGHT_OK",
        "run_id": run_id,
        "planned": 63,
        "started": 0,
        "fallback": False,
        "plan_hash": sha256_json(plan),
        "experiment_ids": [item["experiment_id"] for item in plan],
        "chain": config.public_dict(),
        "checks": [{"name": name, "passed": True} for name in checks],
        "actors": {
            "relayer": Account.from_key(actors.chain_private_key).address,
            "roles": roles,
        },
        "did_registry": {"code_sha256": hashlib.sha256(b"\x60\x00").hexdigest()},
        "lineage_registry": {"code_sha256": hashlib.sha256(b"\x60\x00").hexdigest()},
        "namespace": {"root_budget_ids_checked": 15, "collisions": 0},
        "gas_budget": {
            "lineage_transactions": 97,
            "anchor_transactions": 63,
            "did_setup_transactions_max": 0,
            "transaction_upper_bound": 160,
            "protocol_transaction_upper_bound": 164,
            "fee_upper_bound_wei": 1,
        },
    }


def _attestation_actor_keys() -> ActorKeys:
    private_key = "0x" + "11" * 32
    roles = ("issuer", "holder", "verifier", "alternate", "evaluator")
    return ActorKeys(
        chain_private_key=private_key,
        controllers={role: private_key for role in roles},
        operations={role: private_key for role in roles},
    )


class SepoliaDidPreflightTests(unittest.TestCase):
    def test_success_records_remote_chain_and_registry_code(self) -> None:
        report = run_sepolia_did_preflight(
            _config(),
            web3_factory=lambda config: _FakeWeb3(),
        )

        self.assertTrue(report["passed"])
        self.assertEqual("SEPOLIA_DID_PREFLIGHT_OK", report["code"])
        self.assertEqual(123456, report["latest_block_number"])
        self.assertGreater(report["did_registry"]["code_size"], 0)
        self.assertNotIn("secret-token", json.dumps(report))

    def test_wrong_chain_id_fails_without_fallback(self) -> None:
        report = run_sepolia_did_preflight(
            _config(),
            web3_factory=lambda config: _FakeWeb3(chain_id=31337),
        )

        self.assertFalse(report["passed"])
        self.assertEqual("SEPOLIA_CHAIN_ID_MISMATCH", report["code"])

    def test_registry_without_bytecode_is_rejected(self) -> None:
        report = run_sepolia_did_preflight(
            _config(),
            web3_factory=lambda config: _FakeWeb3(code=b""),
        )

        self.assertFalse(report["passed"])
        self.assertEqual("DID_REGISTRY_NO_CODE", report["code"])

    def test_rpc_timeout_has_stable_error_code(self) -> None:
        report = run_sepolia_did_preflight(
            _config(),
            web3_factory=lambda config: _FakeWeb3(
                connection_error=TimeoutError("RPC timed out")
            ),
        )

        self.assertFalse(report["passed"])
        self.assertEqual("SEPOLIA_RPC_TIMEOUT", report["code"])

    def test_failed_preflight_never_starts_an_experiment(self) -> None:
        failed = {
            "schema_version": "agentdid-sepolia-did-preflight-v1",
            "status": "FAILED",
            "passed": False,
            "code": "SEPOLIA_RPC_TIMEOUT",
        }
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(output_root=directory, run_id="strict-no-fallback")
            with patch(
                "_experiments.security_comparison.run_one.run_sepolia_did_preflight",
                return_value=failed,
            ), patch(
                "_experiments.security_comparison.run_one.execute_experiment"
            ) as execute:
                exit_code = _run_with_config(args, _config())

            self.assertEqual(1, exit_code)
            execute.assert_not_called()
            report_path = Path(directory) / "strict-no-fallback" / "preflight.json"
            self.assertEqual("SEPOLIA_RPC_TIMEOUT", json.loads(
                report_path.read_text(encoding="utf-8")
            )["code"])

    def test_valid_full_preflight_attestation_skips_single_preflight(self) -> None:
        config = _config()
        run_id = "full-sepolia"
        experiment_id = build_full_plan(run_id)[0]["experiment_id"]
        with tempfile.TemporaryDirectory() as directory:
            preflight_path = Path(directory) / run_id / "preflight.json"
            report = _full_preflight_report(
                config,
                run_id=run_id,
            )
            write_json(preflight_path, report)
            args = SimpleNamespace(
                output_root=directory,
                run_id=run_id,
                experiment_id=experiment_id,
                full_preflight=str(preflight_path),
                full_preflight_hash=sha256_json(report),
            )

            with patch(
                "_experiments.security_comparison.run_one.run_sepolia_did_preflight"
            ) as single_preflight, patch(
                "_experiments.security_comparison.run_one.execute_experiment",
                return_value=(0, Path(directory) / "result"),
            ) as execute, patch(
                "_experiments.security_comparison.preflight._default_web3",
                return_value=_FakeWeb3(),
            ), patch(
                "_experiments.security_comparison.preflight.load_actor_keys",
                return_value=_attestation_actor_keys(),
            ):
                exit_code = _run_with_config(args, config)

            self.assertEqual(0, exit_code)
            single_preflight.assert_not_called()
            execute.assert_called_once_with(args, config)

    def test_wrong_full_preflight_hash_is_rejected_without_execution(self) -> None:
        config = _config()
        run_id = "full-sepolia"
        experiment_id = build_full_plan(run_id)[4]["experiment_id"]
        with tempfile.TemporaryDirectory() as directory:
            preflight_path = Path(directory) / run_id / "preflight.json"
            report = _full_preflight_report(
                config,
                run_id=run_id,
            )
            write_json(preflight_path, report)
            args = SimpleNamespace(
                output_root=directory,
                run_id=run_id,
                experiment_id=experiment_id,
                full_preflight=str(preflight_path),
                full_preflight_hash="0" * 64,
            )

            output = io.StringIO()
            with redirect_stdout(output), patch(
                "_experiments.security_comparison.run_one.run_sepolia_did_preflight"
            ) as single_preflight, patch(
                "_experiments.security_comparison.run_one.execute_experiment"
            ) as execute:
                exit_code = _run_with_config(args, config)

            self.assertEqual(1, exit_code)
            self.assertEqual(
                "FULL_PREFLIGHT_ATTESTATION_INVALID",
                json.loads(output.getvalue())["code"],
            )
            single_preflight.assert_not_called()
            execute.assert_not_called()

    def test_live_registry_code_change_is_rejected_without_execution(self) -> None:
        config = _config()
        run_id = "full-sepolia"
        experiment_id = build_full_plan(run_id)[0]["experiment_id"]
        with tempfile.TemporaryDirectory() as directory:
            preflight_path = Path(directory) / run_id / "preflight.json"
            report = _full_preflight_report(config, run_id=run_id)
            write_json(preflight_path, report)
            args = SimpleNamespace(
                output_root=directory,
                run_id=run_id,
                experiment_id=experiment_id,
                full_preflight=str(preflight_path),
                full_preflight_hash=sha256_json(report),
            )

            output = io.StringIO()
            with redirect_stdout(output), patch(
                "_experiments.security_comparison.preflight._default_web3",
                return_value=_FakeWeb3(code=b"\x60\x01"),
            ), patch(
                "_experiments.security_comparison.preflight.load_actor_keys",
                return_value=_attestation_actor_keys(),
            ), patch(
                "_experiments.security_comparison.run_one.execute_experiment"
            ) as execute:
                exit_code = _run_with_config(args, config)

            self.assertEqual(1, exit_code)
            self.assertEqual(
                "FULL_PREFLIGHT_ATTESTATION_INVALID",
                json.loads(output.getvalue())["code"],
            )
            execute.assert_not_called()

    def test_wrong_full_preflight_path_is_rejected_without_execution(self) -> None:
        config = _config()
        run_id = "full-sepolia"
        experiment_id = build_full_plan(run_id)[23]["experiment_id"]
        with tempfile.TemporaryDirectory() as directory:
            wrong_path = Path(directory) / "other-run" / "preflight.json"
            report = _full_preflight_report(
                config,
                run_id=run_id,
            )
            write_json(wrong_path, report)
            args = SimpleNamespace(
                output_root=directory,
                run_id=run_id,
                experiment_id=experiment_id,
                full_preflight=str(wrong_path),
                full_preflight_hash=sha256_json(report),
            )

            output = io.StringIO()
            with redirect_stdout(output), patch(
                "_experiments.security_comparison.run_one.run_sepolia_did_preflight"
            ) as single_preflight, patch(
                "_experiments.security_comparison.run_one.execute_experiment"
            ) as execute:
                exit_code = _run_with_config(args, config)

            self.assertEqual(1, exit_code)
            self.assertEqual(
                "FULL_PREFLIGHT_ATTESTATION_INVALID",
                json.loads(output.getvalue())["code"],
            )
            single_preflight.assert_not_called()
            execute.assert_not_called()

    def test_unauthorized_experiment_id_is_rejected_without_execution(self) -> None:
        config = _config()
        run_id = "full-sepolia"
        experiment_id = "lineage-L14-0001"
        with tempfile.TemporaryDirectory() as directory:
            preflight_path = Path(directory) / run_id / "preflight.json"
            report = _full_preflight_report(
                config,
                run_id=run_id,
            )
            write_json(preflight_path, report)
            args = SimpleNamespace(
                output_root=directory,
                run_id=run_id,
                experiment_id=experiment_id,
                full_preflight=str(preflight_path),
                full_preflight_hash=sha256_json(report),
            )

            output = io.StringIO()
            with redirect_stdout(output), patch(
                "_experiments.security_comparison.run_one.run_sepolia_did_preflight"
            ) as single_preflight, patch(
                "_experiments.security_comparison.run_one.execute_experiment"
            ) as execute:
                exit_code = _run_with_config(args, config)

            self.assertEqual(1, exit_code)
            self.assertEqual(
                "FULL_PREFLIGHT_ATTESTATION_INVALID",
                json.loads(output.getvalue())["code"],
            )
            single_preflight.assert_not_called()
            execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
