from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from eth_abi import encode
from eth_account import Account
from hexbytes import HexBytes
from web3 import Web3
from web3.exceptions import TimeExhausted, TransactionNotFound

from infrastructure.security import sha256_json
from .credentials import credential_hash
from .crypto import ZERO_ADDRESS, sign_envelope_hash
from .models import BudgetLimits, DelegationCredential, EpochKeyCertificate, LineageInvocation
from .verifier import InMemoryStateProvider


ZERO_BYTES32 = bytes(32)


def bytes32_id(value: str) -> bytes:
    if value.startswith("0x") and len(value) == 66:
        return bytes.fromhex(value[2:])
    return hashlib.sha256(value.encode("utf-8")).digest()


def bytes32_hex(value: str) -> str:
    return "0x" + bytes32_id(value).hex()


def edge_id(parent_did: str, child_did: str) -> bytes:
    return bytes.fromhex(InMemoryStateProvider.edge_id(parent_did, child_did))


def abi_payload_hash(types: list[str], values: list[Any]) -> str:
    return Web3.keccak(encode(types, values)).hex()


def signature_bytes(value: str) -> bytes:
    raw = value.removeprefix("0x")
    if len(raw) != 130:
        raise ValueError("secp256k1 signature must contain 65 bytes")
    return bytes.fromhex(raw)


def load_registry_abi() -> list[dict[str, Any]]:
    path = Path(__file__).resolve().parents[2] / "contracts" / "abi" / "AgentLineageRegistry.json"
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)["abi"]


class RegistryTransactionError(RuntimeError):
    pass


class LineageRegistryClient:
    def __init__(
        self,
        w3: Web3,
        contract_address: str,
        *,
        relayer_private_key: str | None = None,
        confirmations: int = 1,
        receipt_timeout_seconds: int = 600,
        priority_fee_gwei: str = "0.1",
    ):
        if not w3.is_connected():
            raise ConnectionError("lineage registry RPC is not connected")
        self.w3 = w3
        self.address = Web3.to_checksum_address(contract_address)
        self.contract = w3.eth.contract(address=self.address, abi=load_registry_abi())
        self.relayer_private_key = relayer_private_key
        self.confirmations = max(1, int(confirmations))
        self.receipt_timeout_seconds = max(30, int(receipt_timeout_seconds))
        self.priority_fee_wei = int(Web3.to_wei(priority_fee_gwei, "gwei"))
        self._nonce_lock = threading.Lock()

    @classmethod
    def from_config(cls, config_path: str = "config/lineage.json") -> "LineageRegistryClient":
        with open(config_path, "r", encoding="utf-8") as handle:
            config = json.load(handle)
        rpc_url = os.environ.get("AGENTLINEAGE_RPC_URL", config.get("rpc_url", ""))
        relayer_key = os.environ.get("AGENTLINEAGE_RELAYER_KEY", "") or None
        return cls(
            Web3(Web3.HTTPProvider(rpc_url)),
            config["registry_address"],
            relayer_private_key=relayer_key,
            confirmations=int(config.get("confirmations", 1)),
            receipt_timeout_seconds=int(config.get("transaction_timeout_seconds", 600)),
            priority_fee_gwei=str(config.get("priority_fee_gwei", "0.1")),
        )

    def _send(self, function: Any, private_key: str | None = None) -> dict[str, Any]:
        key = private_key or self.relayer_private_key
        if not key:
            raise ValueError("a transaction private key is required")
        account = Account.from_key(key)
        with self._nonce_lock:
            nonce = self.w3.eth.get_transaction_count(account.address, "pending")
            tx_params = {
                "from": account.address,
                "nonce": nonce,
                "chainId": self.w3.eth.chain_id,
            }
            latest_block = self.w3.eth.get_block("latest")
            base_fee = latest_block.get("baseFeePerGas")
            if base_fee is None:
                tx_params["gasPrice"] = int(self.w3.eth.gas_price * 1.2)
            else:
                priority_fee = max(int(self.w3.eth.max_priority_fee), self.priority_fee_wei)
                tx_params["maxPriorityFeePerGas"] = priority_fee
                tx_params["maxFeePerGas"] = int(base_fee) * 2 + priority_fee
                tx_params["type"] = 2
            tx = function.build_transaction(tx_params)
            if "gas" not in tx:
                tx["gas"] = int(self.w3.eth.estimate_gas(tx) * 1.2)
            signed = self.w3.eth.account.sign_transaction(tx, key)
            tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        try:
            receipt = self.w3.eth.wait_for_transaction_receipt(
                tx_hash, timeout=self.receipt_timeout_seconds
            )
        except TimeExhausted as exc:
            try:
                receipt = self.w3.eth.get_transaction_receipt(tx_hash)
            except TransactionNotFound:
                raise RegistryTransactionError(
                    f"transaction still pending after timeout: {tx_hash.hex()}"
                ) from exc
        if receipt.status != 1:
            raise RegistryTransactionError(f"transaction reverted: {tx_hash.hex()}")
        target_block = receipt.blockNumber + self.confirmations - 1
        if target_block > receipt.blockNumber:
            deadline = time.time() + self.receipt_timeout_seconds
            while self.w3.eth.block_number < target_block:
                if time.time() >= deadline:
                    raise TimeoutError("transaction confirmation wait timed out")
                time.sleep(1)
        return {
            "transaction_hash": tx_hash.hex(),
            "block_number": receipt.blockNumber,
            "gas_used": receipt.gasUsed,
            "confirmations": self.confirmations,
        }

    def latest_block_number(self) -> int:
        return int(self.w3.eth.block_number)

    def register_root(
        self,
        epoch: EpochKeyCertificate,
        governance_private_key: str,
    ) -> dict[str, Any]:
        return self._send(
            self.contract.functions.registerRoot(
                bytes32_id(epoch.root_did),
                epoch.epoch,
                Web3.to_checksum_address(epoch.delegation_key),
                bytes.fromhex(credential_hash(epoch)),
            ),
            governance_private_key,
        )

    def rotate_epoch(
        self,
        epoch: EpochKeyCertificate,
        governance_private_key: str,
        *,
        revoke_previous: bool = True,
    ) -> dict[str, Any]:
        return self._send(
            self.contract.functions.rotateEpoch(
                bytes32_id(epoch.root_did), epoch.epoch,
                Web3.to_checksum_address(epoch.delegation_key),
                bytes.fromhex(credential_hash(epoch)), revoke_previous,
            ),
            governance_private_key,
        )

    def register_delegation(
        self,
        credential: DelegationCredential,
        issuer_delegation_private_key: str,
        *,
        parent: DelegationCredential | None = None,
    ) -> dict[str, Any]:
        credential_id = bytes32_id(credential.jti)
        parent_id = bytes32_id(parent.jti) if parent else ZERO_BYTES32
        values = [
            credential_id, parent_id, bytes.fromhex(credential_hash(credential)),
            bytes.fromhex(credential.parent_credential_hash), bytes32_id(credential.root_did),
            bytes32_id(credential.parent_did), bytes32_id(credential.child_did),
            edge_id(credential.parent_did, credential.child_did),
            bytes.fromhex(credential.lineage_commitment),
            bytes.fromhex(sha256_json(credential.permission.to_dict())),
            bytes32_id(credential.budget_id),
            bytes32_id(credential.replica_group_id) if credential.replica_group_id else ZERO_BYTES32,
            Web3.to_checksum_address(credential.operation_key),
            Web3.to_checksum_address(credential.delegation_key or ZERO_ADDRESS),
            credential.permission.expires_at,
        ]
        types = [
            "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32",
            "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "address", "address", "uint64",
        ]
        authorization = sign_envelope_hash(
            issuer_delegation_private_key,
            abi_payload_hash(types, values),
            purpose="AgentLineage/REGISTER_DELEGATION/v1",
            chain_id=self.w3.eth.chain_id,
            verifying_contract=self.address,
        )
        return self._send(
            self.contract.functions.registerDelegation(*values, signature_bytes(authorization))
        )

    def create_root_budget(
        self,
        root_did: str,
        budget_id: str,
        limits: BudgetLimits,
        governance_private_key: str,
    ) -> dict[str, Any]:
        return self._send(
            self.contract.functions.createRootBudget(
                bytes32_id(budget_id), bytes32_id(root_did),
                limits.calls, limits.cost_units, limits.concurrency,
            ),
            governance_private_key,
        )

    def reserve_child_budget(
        self,
        parent_budget_id: str,
        credential: DelegationCredential,
        authority_private_key: str,
    ) -> dict[str, Any]:
        values = [
            bytes32_id(parent_budget_id), bytes32_id(credential.budget_id),
            bytes32_id(credential.jti), credential.reservation.calls,
            credential.reservation.cost_units, credential.reservation.concurrency,
        ]
        types = ["bytes32", "bytes32", "bytes32", "uint64", "uint64", "uint32"]
        authorization = sign_envelope_hash(
            authority_private_key, abi_payload_hash(types, values),
            purpose="AgentLineage/RESERVE_BUDGET/v1", chain_id=self.w3.eth.chain_id,
            verifying_contract=self.address,
        )
        return self._send(
            self.contract.functions.reserveChildBudget(*values, signature_bytes(authorization))
        )

    def ensure_replica_group_budget(
        self,
        parent_budget_id: str,
        replica_group_id: str,
        group_budget_id: str,
        limits: BudgetLimits,
        authority_private_key: str,
    ) -> dict[str, Any]:
        group_key = bytes32_id(replica_group_id)
        existing = self.contract.functions.replicaGroups(group_key).call()
        if existing[3]:
            if HexBytes(existing[2]) != HexBytes(bytes32_id(group_budget_id)) or existing[4]:
                raise ValueError("replica group exists with another or closed budget")
            budget = self.contract.functions.budgets(bytes32_id(group_budget_id)).call()
            actual = (int(budget[3]), int(budget[4]), int(budget[5]))
            expected = (limits.calls, limits.cost_units, limits.concurrency)
            if actual != expected:
                raise ValueError("replica group budget limits do not match existing group")
            return {
                "transaction_hash": None,
                "block_number": self.w3.eth.block_number,
                "existing": True,
            }
        values = [
            bytes32_id(parent_budget_id), group_key, bytes32_id(group_budget_id),
            limits.calls, limits.cost_units, limits.concurrency,
        ]
        types = ["bytes32", "bytes32", "bytes32", "uint64", "uint64", "uint32"]
        authorization = sign_envelope_hash(
            authority_private_key,
            abi_payload_hash(types, values),
            purpose="AgentLineage/CREATE_REPLICA_GROUP/v1",
            chain_id=self.w3.eth.chain_id,
            verifying_contract=self.address,
        )
        return self._send(
            self.contract.functions.createReplicaGroupBudget(
                *values, signature_bytes(authorization)
            )
        )

    def begin_invocation(
        self,
        credential: DelegationCredential,
        invocation: LineageInvocation,
    ) -> dict[str, Any]:
        request_hash = bytes.fromhex(sha256_json(invocation.unsigned_dict()))
        return self._send(self.contract.functions.beginInvocation(
            bytes32_id(credential.jti), bytes32_id(invocation.budget_id), request_hash,
            invocation.cost_units, invocation.lease_seconds, signature_bytes(invocation.signature),
        ))

    def finish_invocation(self, invocation: LineageInvocation) -> dict[str, Any]:
        request_hash = bytes.fromhex(sha256_json(invocation.unsigned_dict()))
        return self._send(self.contract.functions.finishInvocation(request_hash))

    def revoke(self, root_did: str, kind: str, subject: str, governance_private_key: str) -> dict[str, Any]:
        root_id = bytes32_id(root_did)
        if kind == "credential":
            function = self.contract.functions.revokeCredential(root_id, bytes32_id(subject))
        elif kind == "edge":
            parent, child = subject.split("->", 1)
            function = self.contract.functions.revokeEdge(root_id, edge_id(parent, child))
        elif kind in {"node", "subtree"}:
            function = self.contract.functions.revokeNode(root_id, bytes32_id(subject))
        elif kind == "epoch":
            function = self.contract.functions.revokeEpoch(root_id, int(subject))
        else:
            raise ValueError(f"unsupported revocation kind: {kind}")
        return self._send(function, governance_private_key)

    def validate_chain_state(
        self, epoch: EpochKeyCertificate, credentials: list[DelegationCredential]
    ) -> tuple[bool, str, int | None]:
        checked_block = int(self.w3.eth.block_number)
        for credential in credentials:
            record = self.contract.functions.delegations(
                bytes32_id(credential.jti)
            ).call(block_identifier=checked_block)
            if not bool(record[14]):
                return False, "CREDENTIAL_INACTIVE", checked_block
            registered_hash = HexBytes(record[2])
            presented_hash = HexBytes("0x" + credential_hash(credential))
            if registered_hash != presented_hash:
                return False, "CREDENTIAL_HASH_MISMATCH", checked_block
        credential_ids = [bytes32_id(item.jti) for item in credentials]
        edge_ids = [edge_id(item.parent_did, item.child_did) for item in credentials]
        node_ids = [bytes32_id(item.child_did) for item in credentials]
        active, reason, block_number = self.contract.functions.getValidationState(
            bytes32_id(epoch.root_did), epoch.epoch, credential_ids, edge_ids, node_ids
        ).call(block_identifier=checked_block)
        reason_text = bytes(reason).rstrip(b"\0").decode("ascii", errors="replace")
        return bool(active), reason_text or "chain state active", int(block_number)

    def get_status(self, identifier: str) -> dict[str, Any]:
        budget = self.contract.functions.budgets(bytes32_id(identifier)).call()
        return {
            "identifier": identifier,
            "budget": {
                "root_id": HexBytes(budget[0]).hex(),
                "owner_credential_id": HexBytes(budget[1]).hex(),
                "parent_budget_id": HexBytes(budget[2]).hex(),
                "limit_calls": budget[3], "limit_cost": budget[4],
                "limit_concurrency": budget[5], "spent_calls": budget[6],
                "spent_cost": budget[7], "active_concurrency": budget[8],
                "reserved_calls": budget[9], "reserved_cost": budget[10],
                "reserved_concurrency": budget[11], "exists": budget[12], "closed": budget[13],
            },
            "block_number": self.w3.eth.block_number,
        }
