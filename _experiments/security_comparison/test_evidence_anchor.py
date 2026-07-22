from __future__ import annotations

import unittest
from types import SimpleNamespace

from infrastructure.evidence_anchor import EthereumEvidenceAnchor, encode_anchor_data


class _FakeEth:
    def __init__(self, transaction: dict[str, object], chain_id: int = 31337):
        self.chain_id = chain_id
        self._transaction = transaction

    def get_transaction(self, _tx_hash: str) -> dict[str, object]:
        return self._transaction


class EvidenceAnchorVerificationTests(unittest.TestCase):
    def _anchor(self, transaction: dict[str, object]) -> EthereumEvidenceAnchor:
        anchor = object.__new__(EthereumEvidenceAnchor)
        anchor.w3 = SimpleNamespace(eth=_FakeEth(transaction))
        return anchor

    def test_provider_chain_id_is_used_when_transaction_omits_optional_field(self) -> None:
        digest = "ab" * 32
        anchor = self._anchor({
            "input": encode_anchor_data(digest),
            "blockNumber": 7,
            "from": "0xsender",
            "to": "0xrecipient",
        })

        result = anchor.verify_transaction("0xtx", digest)

        self.assertTrue(result["matches"])
        self.assertEqual(result["chain_id"], 31337)
        self.assertIsNone(result["transaction_chain_id"])

    def test_optional_transaction_chain_id_is_preserved_for_diagnostics(self) -> None:
        digest = "cd" * 32
        anchor = self._anchor({
            "input": encode_anchor_data(digest),
            "chainId": 11155111,
            "blockNumber": 9,
            "from": "0xsender",
            "to": "0xrecipient",
        })

        result = anchor.verify_transaction("0xtx", digest)

        self.assertEqual(result["chain_id"], 31337)
        self.assertEqual(result["transaction_chain_id"], 11155111)


if __name__ == "__main__":
    unittest.main()
