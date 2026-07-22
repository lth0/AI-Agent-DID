from __future__ import annotations

import threading
import unittest
from types import SimpleNamespace

from _experiments.security_comparison.chain import _tx_params
from _experiments.security_comparison.lineage_cases import LineageCase
from infrastructure.evidence_anchor import EthereumEvidenceAnchor
from infrastructure.lineage.registry_client import (
    LineageRegistryClient,
    RegistryTransactionError,
)


PRIVATE_KEY = "0x" + "11" * 32


class _FeeEth:
    chain_id = 11155111
    gas_price = 10
    max_priority_fee = 2

    def __init__(self, *, base_fee: int | None = 10):
        self.base_fee = base_fee
        self.broadcasts = 0

    def get_block(self, _identifier: str) -> dict[str, int | None]:
        return {"baseFeePerGas": self.base_fee}

    def get_transaction_count(self, _address: str, _state: str) -> int:
        return 0

    def send_raw_transaction(self, _raw: bytes) -> bytes:
        self.broadcasts += 1
        raise AssertionError("guard must reject before broadcast")


class _Function:
    def __init__(self, gas: int):
        self.gas = gas

    def build_transaction(self, params: dict[str, object]) -> dict[str, object]:
        return {**params, "gas": self.gas}


class TransactionFeeGuardTests(unittest.TestCase):
    def test_did_setup_fee_cap_rejects_before_transaction_build(self) -> None:
        w3 = SimpleNamespace(eth=_FeeEth())

        with self.assertRaisesRegex(RuntimeError, "TRANSACTION_FEE_CAP_EXCEEDED"):
            _tx_params(w3, "0xsender", 0, max_fee_per_gas_wei=20)

    def test_lineage_fee_cap_rejects_before_broadcast(self) -> None:
        eth = _FeeEth()
        client = object.__new__(LineageRegistryClient)
        client.w3 = SimpleNamespace(eth=eth)
        client.relayer_private_key = PRIVATE_KEY
        client.confirmations = 1
        client.receipt_timeout_seconds = 30
        client.priority_fee_wei = 2
        client.max_fee_per_gas_wei = 20
        client.gas_limit_cap = 450_000
        client._nonce_lock = threading.Lock()

        with self.assertRaisesRegex(
            RegistryTransactionError,
            "TRANSACTION_FEE_CAP_EXCEEDED",
        ):
            client._send(_Function(100_000))

        self.assertEqual(0, eth.broadcasts)

    def test_lineage_gas_cap_rejects_before_broadcast(self) -> None:
        eth = _FeeEth(base_fee=None)
        client = object.__new__(LineageRegistryClient)
        client.w3 = SimpleNamespace(eth=eth)
        client.relayer_private_key = PRIVATE_KEY
        client.confirmations = 1
        client.receipt_timeout_seconds = 30
        client.priority_fee_wei = 2
        client.max_fee_per_gas_wei = None
        client.gas_limit_cap = 450_000
        client._nonce_lock = threading.Lock()

        with self.assertRaisesRegex(
            RegistryTransactionError,
            "TRANSACTION_GAS_LIMIT_CAP_EXCEEDED",
        ):
            client._send(_Function(450_001))

        self.assertEqual(0, eth.broadcasts)

    def test_anchor_fee_cap_rejects_before_nonce_or_broadcast(self) -> None:
        anchor = object.__new__(EthereumEvidenceAnchor)
        anchor.w3 = SimpleNamespace(eth=_FeeEth())
        anchor.account = SimpleNamespace(address="0xsender", key=PRIVATE_KEY)
        anchor.max_fee_per_gas_wei = 9

        with self.assertRaisesRegex(RuntimeError, "TRANSACTION_FEE_CAP_EXCEEDED"):
            anchor.submit("ab" * 32)

    def test_materialization_retains_completed_and_uncertain_transactions(self) -> None:
        class BroadcastFailure(RuntimeError):
            transaction_hash = "0x" + "ab" * 32

        lineage = object.__new__(LineageCase)
        lineage.transactions = []
        lineage.activation_started = False
        lineage.onchain_materialized = False
        lineage.activation_steps = [
            ("completed", lambda: {"transaction_hash": "0x" + "cd" * 32}),
            ("uncertain", lambda: (_ for _ in ()).throw(BroadcastFailure("timeout"))),
        ]

        with self.assertRaises(BroadcastFailure):
            lineage.materialize()

        self.assertEqual("completed", lineage.transactions[0]["operation"])
        self.assertEqual("UNCERTAIN", lineage.transactions[1]["status"])
        self.assertEqual(BroadcastFailure.transaction_hash, lineage.transactions[1]["transaction_hash"])


if __name__ == "__main__":
    unittest.main()
