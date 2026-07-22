"""Anchor AgentDID evidence hashes in a zero-value Ethereum transaction."""

from __future__ import annotations

import os
import re
from typing import Any

ANCHOR_PREFIX = b"AgentDID-Audit-v1:"
HASH_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


def encode_anchor_data(evidence_hash: str) -> bytes:
    if not isinstance(evidence_hash, str) or not HASH_PATTERN.fullmatch(evidence_hash):
        raise ValueError("evidence_hash must be a 64-character SHA-256 hex string")
    return ANCHOR_PREFIX + bytes.fromhex(evidence_hash)


def decode_anchor_data(data: bytes | bytearray | str) -> str:
    if isinstance(data, str):
        value = data[2:] if data.startswith("0x") else data
        data = bytes.fromhex(value)
    raw = bytes(data)
    if not raw.startswith(ANCHOR_PREFIX):
        raise ValueError("Transaction data is not an AgentDID audit anchor")
    digest = raw[len(ANCHOR_PREFIX):]
    if len(digest) != 32:
        raise ValueError("AgentDID audit anchor must contain exactly one SHA-256 hash")
    return digest.hex()


class EthereumEvidenceAnchor:
    """Broadcast and inspect audit anchors without deploying a contract."""

    def __init__(
        self,
        rpc_url: str,
        private_key: str,
        *,
        request_timeout_seconds: float = 15.0,
        receipt_timeout_seconds: float = 600.0,
        max_fee_per_gas_wei: int | None = None,
    ):
        try:
            from web3 import Web3
        except ImportError as exc:
            raise RuntimeError(
                "web3 is required for blockchain anchoring; install requirements.txt"
            ) from exc
        self.w3 = Web3(Web3.HTTPProvider(
            rpc_url,
            request_kwargs={"timeout": max(1.0, float(request_timeout_seconds))},
        ))
        if not self.w3.is_connected():
            raise ConnectionError("Unable to connect to the configured Ethereum RPC")
        self.account = self.w3.eth.account.from_key(private_key)
        self.receipt_timeout_seconds = max(30.0, float(receipt_timeout_seconds))
        configured_fee_cap = str(
            os.environ.get("AGENTDID_EXPERIMENT_MAX_FEE_PER_GAS_WEI", "")
        ).strip()
        self.max_fee_per_gas_wei = (
            int(max_fee_per_gas_wei)
            if max_fee_per_gas_wei is not None
            else (int(configured_fee_cap) if configured_fee_cap else None)
        )
        if self.max_fee_per_gas_wei is not None and self.max_fee_per_gas_wei <= 0:
            raise ValueError("max_fee_per_gas_wei must be positive")

    def submit(self, evidence_hash: str, wait: bool = True) -> dict[str, Any]:
        gas_price = int(self.w3.eth.gas_price)
        if self.max_fee_per_gas_wei is not None and gas_price > self.max_fee_per_gas_wei:
            raise RuntimeError("TRANSACTION_FEE_CAP_EXCEEDED")
        transaction = {
            "chainId": self.w3.eth.chain_id,
            "nonce": self.w3.eth.get_transaction_count(self.account.address, "pending"),
            "to": self.account.address,
            "value": 0,
            "data": encode_anchor_data(evidence_hash),
            "gas": 70_000,
            "gasPrice": gas_price,
        }
        signed = self.w3.eth.account.sign_transaction(transaction, self.account.key)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        result = {
            "evidence_hash": evidence_hash,
            "tx_hash": self.w3.to_hex(tx_hash),
            "chain_id": transaction["chainId"],
            "anchor_address": self.account.address,
        }
        if wait:
            receipt = self.w3.eth.wait_for_transaction_receipt(
                tx_hash,
                timeout=self.receipt_timeout_seconds,
            )
            result.update({
                "status": receipt.status,
                "block_number": receipt.blockNumber,
                "block_hash": receipt.blockHash.hex(),
                "gas_used": receipt.gasUsed,
                "effective_gas_price": int(receipt.get("effectiveGasPrice") or 0),
            })
        return result

    def verify_transaction(self, tx_hash: str, expected_hash: str | None = None) -> dict[str, Any]:
        transaction = self.w3.eth.get_transaction(tx_hash)
        anchored_hash = decode_anchor_data(transaction["input"])
        transaction_chain_id = transaction.get("chainId")
        return {
            "tx_hash": tx_hash,
            "anchored_hash": anchored_hash,
            "matches": expected_hash is None or anchored_hash == expected_hash,
            # Some JSON-RPC implementations (including Hardhat) omit the
            # optional chainId field from eth_getTransactionByHash.  The RPC
            # network ID is still authoritative because the transaction was
            # fetched from that chain.  Preserve the optional transaction
            # value separately for diagnostics when a provider exposes it.
            "chain_id": int(self.w3.eth.chain_id),
            "transaction_chain_id": (
                int(transaction_chain_id) if transaction_chain_id is not None else None
            ),
            "block_number": transaction.get("blockNumber"),
            "from": transaction.get("from"),
            "to": transaction.get("to"),
        }
