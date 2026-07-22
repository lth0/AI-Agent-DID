from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from _experiments.security_comparison.chain import (
    ChainConfig,
    DEFAULT_SEPOLIA_DID_REGISTRY,
    DEFAULT_SEPOLIA_LINEAGE_REGISTRY,
)
from _experiments.security_comparison.preflight import run_sepolia_did_preflight
from _experiments.security_comparison.run_one import _run_with_config


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


if __name__ == "__main__":
    unittest.main()
