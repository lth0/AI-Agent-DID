from __future__ import annotations

import json
import hashlib
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from eth_account import Account
from web3 import Web3
from web3.logs import DISCARD

from infrastructure.agentdid_protocol import (
    ProtocolIdentity,
    did_network,
    relationship_addresses,
)
from infrastructure.evidence_anchor import EthereumEvidenceAnchor
from infrastructure.lineage.registry_client import bytes32_id, load_registry_abi
from infrastructure.load_config import load_key_config


PROJECT_ROOT = Path(__file__).resolve().parents[2]
HARDHAT_RPC_URL = "http://127.0.0.1:8545"
HARDHAT_CHAIN_ID = 31337
HARDHAT_MNEMONIC = "test test test test test test test test test test test junk"
DEFAULT_SEPOLIA_DID_REGISTRY = "0x03d5003bf0e79C5F5223588F347ebA39AfbC3818"
DEFAULT_SEPOLIA_LINEAGE_REGISTRY = "0xD08c036042dC2B71dCD59be3E8A58689fb346198"

# Minimal ERC-1056 ABI used by the comparison runner. Keeping this local avoids
# depending on a test artifact inside node_modules for transaction creation.
DID_REGISTRY_ABI = [
    {
        "inputs": [
            {"internalType": "address", "name": "identity", "type": "address"},
            {"internalType": "bytes32", "name": "name", "type": "bytes32"},
            {"internalType": "bytes", "name": "value", "type": "bytes"},
            {"internalType": "uint256", "name": "validity", "type": "uint256"},
        ],
        "name": "setAttribute",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "address", "name": "identity", "type": "address"},
            {"indexed": False, "internalType": "bytes32", "name": "name", "type": "bytes32"},
            {"indexed": False, "internalType": "bytes", "name": "value", "type": "bytes"},
            {"indexed": False, "internalType": "uint256", "name": "validTo", "type": "uint256"},
            {"indexed": False, "internalType": "uint256", "name": "previousChange", "type": "uint256"},
        ],
        "name": "DIDAttributeChanged",
        "type": "event",
    },
]


@dataclass(frozen=True)
class ChainConfig:
    backend: str
    rpc_url: str
    chain_id: int
    did_registry_address: str
    lineage_registry_address: str
    confirmations: int = 1
    rpc_timeout_seconds: float = 15.0

    def public_dict(self) -> dict[str, Any]:
        parsed = urlsplit(self.rpc_url)
        endpoint = f"{parsed.scheme}://{parsed.hostname or ''}"
        if parsed.port:
            endpoint += f":{parsed.port}"
        return {
            "backend": self.backend,
            "chain_id": self.chain_id,
            "rpc_endpoint": endpoint,
            "did_registry_address": self.did_registry_address,
            "lineage_registry_address": self.lineage_registry_address,
            "confirmations": self.confirmations,
            "rpc_timeout_seconds": self.rpc_timeout_seconds,
        }


@dataclass(frozen=True)
class ActorKeys:
    chain_private_key: str
    controllers: dict[str, str]
    operations: dict[str, str]

    def identities(self, chain_id: int) -> dict[str, ProtocolIdentity]:
        return {
            role: ProtocolIdentity.from_keys(
                role,
                self.controllers[role],
                self.operations.get(role),
                chain_id,
            )
            for role in self.controllers
        }


def _hardhat_account(index: int) -> str:
    Account.enable_unaudited_hdwallet_features()
    account = Account.from_mnemonic(
        HARDHAT_MNEMONIC,
        account_path=f"m/44'/60'/0'/0/{index}",
    )
    return account.key.hex()


def load_actor_keys(backend: str) -> ActorKeys:
    if backend == "hardhat":
        keys = [_hardhat_account(index) for index in range(10)]
        return ActorKeys(
            chain_private_key=keys[0],
            controllers={
                "issuer": keys[1],
                "holder": keys[2],
                "verifier": keys[4],
                "alternate": keys[6],
                "evaluator": keys[8],
            },
            operations={
                "issuer": keys[1],
                "holder": keys[3],
                "verifier": keys[5],
                "alternate": keys[7],
                "evaluator": keys[9],
            },
        )

    config = load_key_config()
    accounts = config["accounts"]

    def key(role: str) -> str:
        value = str(accounts[role]["private_key"])
        if not value.startswith("0x"):
            value = "0x" + value
        Account.from_key(value)
        return value

    required = (
        "issuer", "agent_a_admin", "agent_a_op", "agent_b_admin", "agent_b_op",
        "agent_c_admin", "agent_c_op", "agent_d_admin", "agent_d_op",
    )
    missing = [role for role in required if role not in accounts]
    if missing:
        raise ValueError(f"Sepolia actor configuration is missing: {', '.join(missing)}")
    chain_key = os.environ.get("AGENTDID_EXPERIMENT_CHAIN_KEY", "").strip()
    if not chain_key:
        chain_key = key("issuer")
    if not chain_key.startswith("0x"):
        chain_key = "0x" + chain_key
    Account.from_key(chain_key)
    return ActorKeys(
        chain_private_key=chain_key,
        controllers={
            "issuer": key("issuer"),
            "holder": key("agent_a_admin"),
            "verifier": key("agent_b_admin"),
            "alternate": key("agent_c_admin"),
            "evaluator": key("agent_d_admin"),
        },
        operations={
            "issuer": key("issuer"),
            "holder": key("agent_a_op"),
            "verifier": key("agent_b_op"),
            "alternate": key("agent_c_op"),
            "evaluator": key("agent_d_op"),
        },
    )


def sepolia_config() -> ChainConfig:
    config = load_key_config()
    rpc_url = os.environ.get("AGENTDID_EXPERIMENT_RPC_URL", "").strip() or str(config["api_url"])
    if not rpc_url:
        raise ValueError("AGENTDID_EXPERIMENT_RPC_URL is required for Sepolia mode")
    return ChainConfig(
        backend="sepolia",
        rpc_url=rpc_url,
        chain_id=11155111,
        did_registry_address=Web3.to_checksum_address(
            os.environ.get("AGENTDID_DID_REGISTRY_ADDRESS", DEFAULT_SEPOLIA_DID_REGISTRY)
        ),
        lineage_registry_address=Web3.to_checksum_address(
            os.environ.get("AGENTDID_LINEAGE_REGISTRY_ADDRESS", DEFAULT_SEPOLIA_LINEAGE_REGISTRY)
        ),
        confirmations=max(1, int(os.environ.get("AGENTDID_EXPERIMENT_CONFIRMATIONS", "1"))),
        rpc_timeout_seconds=max(
            1.0,
            float(os.environ.get("AGENTDID_EXPERIMENT_RPC_TIMEOUT_SECONDS", "15")),
        ),
    )


class HardhatNode:
    def __init__(self, log_directory: Path):
        self.log_directory = log_directory
        self.process: subprocess.Popen[str] | None = None
        self._stdout = None
        self._stderr = None
        self.owned = False

    @staticmethod
    def connected() -> bool:
        try:
            return Web3(Web3.HTTPProvider(HARDHAT_RPC_URL, request_kwargs={"timeout": 1})).is_connected()
        except Exception:
            return False

    def start(self) -> None:
        if self.connected():
            return
        executable = shutil.which("npx.cmd") or shutil.which("npx")
        if not executable:
            raise FileNotFoundError("npx is required to start the Hardhat node")
        self.log_directory.mkdir(parents=True, exist_ok=True)
        self._stdout = (self.log_directory / "hardhat-node.stdout.log").open("w", encoding="utf-8")
        self._stderr = (self.log_directory / "hardhat-node.stderr.log").open("w", encoding="utf-8")
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self.process = subprocess.Popen(
            [executable, "hardhat", "node", "--hostname", "127.0.0.1", "--port", "8545"],
            cwd=PROJECT_ROOT,
            stdout=self._stdout,
            stderr=self._stderr,
            text=True,
            creationflags=creationflags,
        )
        self.owned = True
        deadline = time.time() + 45
        while time.time() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("Hardhat node exited before becoming ready")
            if self.connected():
                return
            time.sleep(0.5)
        raise TimeoutError("Hardhat node did not become ready")

    def stop(self) -> None:
        if self.process is not None and self.owned and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        for handle in (self._stdout, self._stderr):
            if handle is not None:
                handle.close()

    def __enter__(self) -> "HardhatNode":
        self.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.stop()


def deploy_local_contracts() -> dict[str, Any]:
    executable = shutil.which("npx.cmd") or shutil.which("npx")
    if not executable:
        raise FileNotFoundError("npx is required to deploy comparison contracts")
    completed = subprocess.run(
        [executable, "hardhat", "run", "contracts/scripts/deploy-comparison.js", "--network", "localhost"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=True,
    )
    for line in reversed(completed.stdout.splitlines()):
        try:
            result = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "lineageRegistry" in result and "didRegistry" in result:
            return result
    raise RuntimeError(f"deployment output did not contain contract addresses: {completed.stdout}")


def local_config(deployment: dict[str, Any]) -> ChainConfig:
    return ChainConfig(
        backend="hardhat",
        rpc_url=HARDHAT_RPC_URL,
        chain_id=HARDHAT_CHAIN_ID,
        did_registry_address=Web3.to_checksum_address(deployment["didRegistry"]["address"]),
        lineage_registry_address=Web3.to_checksum_address(deployment["lineageRegistry"]["address"]),
    )


def _tx_params(w3: Web3, address: str, nonce: int) -> dict[str, Any]:
    params: dict[str, Any] = {"from": address, "nonce": nonce, "chainId": w3.eth.chain_id}
    latest = w3.eth.get_block("latest")
    base_fee = latest.get("baseFeePerGas")
    if base_fee is None:
        params["gasPrice"] = int(w3.eth.gas_price * 1.2)
    else:
        priority = max(int(w3.eth.max_priority_fee), int(Web3.to_wei("0.1", "gwei")))
        params.update({
            "type": 2,
            "maxPriorityFeePerGas": priority,
            "maxFeePerGas": int(base_fee) * 2 + priority,
        })
    return params


def _wait_for_confirmations(
    w3: Web3,
    receipt: Any,
    confirmations: int,
    *,
    timeout: float = 600,
) -> int:
    required = max(1, int(confirmations))
    target_block = int(receipt.blockNumber) + required - 1
    deadline = time.monotonic() + timeout
    while int(w3.eth.block_number) < target_block:
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"DID_SETUP_CONFIRMATION_TIMEOUT: transaction did not reach {required} confirmations"
            )
        time.sleep(3)
    confirmed = w3.eth.get_transaction_receipt(receipt.transactionHash)
    if int(confirmed.status) != 1 or confirmed.blockHash != receipt.blockHash:
        raise RuntimeError("DID_SETUP_RECEIPT_REORG: confirmed receipt changed")
    return int(w3.eth.block_number)


def _send_function(
    w3: Web3,
    function: Any,
    private_key: str,
    *,
    confirmations: int = 1,
) -> tuple[dict[str, Any], Any]:
    account = Account.from_key(private_key)
    params = _tx_params(w3, account.address, w3.eth.get_transaction_count(account.address, "pending"))
    transaction = function.build_transaction(params)
    if "gas" not in transaction:
        transaction["gas"] = int(w3.eth.estimate_gas(transaction) * 1.2)
    signed = w3.eth.account.sign_transaction(transaction, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=600)
    if receipt.status != 1:
        raise RuntimeError(f"transaction reverted: {tx_hash.hex()}")
    confirmation_block = _wait_for_confirmations(w3, receipt, confirmations)
    result = receipt_dict(receipt)
    result.update({
        "confirmations_required": max(1, int(confirmations)),
        "confirmation_block_number": confirmation_block,
    })
    return result, receipt


def receipt_dict(receipt: Any) -> dict[str, Any]:
    return {
        "transaction_hash": receipt.transactionHash.hex(),
        "block_number": int(receipt.blockNumber),
        "transaction_index": int(receipt.transactionIndex),
        "status": int(receipt.status),
        "gas_used": int(receipt.gasUsed),
        "contract_address": receipt.contractAddress,
        "log_count": len(receipt.logs),
    }


def configure_did_registry(
    config: ChainConfig,
    identities: dict[str, ProtocolIdentity],
    actor_keys: ActorKeys,
) -> dict[str, Any]:
    w3 = Web3(Web3.HTTPProvider(
        config.rpc_url,
        request_kwargs={"timeout": config.rpc_timeout_seconds},
    ))
    if not w3.is_connected():
        raise ConnectionError("DID registry RPC is unavailable")
    if int(w3.eth.chain_id) != config.chain_id:
        raise RuntimeError("DID_REGISTRY_CHAIN_ID_MISMATCH")
    if not bytes(w3.eth.get_code(config.did_registry_address)):
        raise RuntimeError("DID_REGISTRY_NO_CODE")
    contract = w3.eth.contract(address=config.did_registry_address, abi=DID_REGISTRY_ABI)
    key_name = b"did/pub/Secp256k1/sigAuth/hex"[:32].ljust(32, b"\0")
    transactions = []
    for role, identity in identities.items():
        if identity.operation_address.lower() == identity.controller_address.lower():
            transactions.append({
                "role": role,
                "relationship": "controller",
                "transaction": None,
                "reason": "operation key is the DID controller",
            })
            continue
        existing = resolve_did_document(config, identity.did)
        existing_authentication = relationship_addresses(
            existing["document"], "authentication"
        )
        if identity.operation_address.lower() in existing_authentication:
            transactions.append({
                "role": role,
                "relationship": "authentication",
                "operation_address": identity.operation_address,
                "transaction": None,
                "reason": "operation key is already active in the DID Registry",
                "resolution_source": existing["source"],
            })
            continue
        function = contract.functions.setAttribute(
            identity.controller_address,
            key_name,
            bytes.fromhex(identity.operation_address[2:]),
            365 * 24 * 60 * 60,
        )
        receipt, raw_receipt = _send_function(
            w3,
            function,
            actor_keys.controllers[role],
            confirmations=config.confirmations,
        )
        decoded = contract.events.DIDAttributeChanged().process_receipt(
            raw_receipt,
            errors=DISCARD,
        )
        events = []
        for event in decoded:
            args = dict(event["args"])
            events.append({
                "event": "DIDAttributeChanged",
                "identity": args["identity"],
                "name": Web3.to_hex(args["name"]),
                "value": Web3.to_hex(args["value"]),
                "valid_to": int(args["validTo"]),
                "previous_change": int(args["previousChange"]),
                "block_number": int(event["blockNumber"]),
                "log_index": int(event["logIndex"]),
            })
        expected_events = [
            event for event in events
            if event["identity"].lower() == identity.controller_address.lower()
            and event["name"].lower() == Web3.to_hex(key_name).lower()
            and event["value"].lower() == identity.operation_address.lower()
        ]
        if not expected_events:
            raise RuntimeError("DID_REGISTRY_EVENT_MISSING")
        resolved = resolve_did_document(config, identity.did)
        authentication = relationship_addresses(resolved["document"], "authentication")
        if identity.operation_address.lower() not in authentication:
            raise RuntimeError("DID_RELATIONSHIP_MISMATCH")
        transactions.append({
            "role": role,
            "relationship": "authentication",
            "operation_address": identity.operation_address,
            "transaction": receipt,
            "events": events,
            "resolution_source": resolved["source"],
        })
    return {
        "schema_version": "agentdid-did-registry-setup-v1",
        "backend": config.backend,
        "registry_address": config.did_registry_address,
        "chain_id": config.chain_id,
        "confirmations": config.confirmations,
        "identities": {role: identity.public_dict() for role, identity in identities.items()},
        "transactions": transactions,
    }


def resolve_did_document(config: ChainConfig, did: str) -> dict[str, Any]:
    """Resolve one ``did:ethr`` document against the configured registry.

    The Node helper uses the official ``did-resolver`` and
    ``ethr-did-resolver`` dependencies already bundled with this repository.
    No in-memory fallback is attempted: a resolution error is infrastructure
    failure for both Hardhat and Sepolia modes.
    """

    executable = shutil.which("node.exe") or shutil.which("node")
    if not executable:
        raise FileNotFoundError("node is required for did:ethr resolution")
    helper = PROJECT_ROOT / "infrastructure" / "real_resolve.js"
    completed = subprocess.run(
        [
            executable,
            str(helper),
            did,
            config.rpc_url,
            did_network(config.chain_id),
            str(config.chain_id),
            config.did_registry_address,
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    if completed.returncode != 0:
        diagnostic = "\n".join(
            part for part in (completed.stderr, completed.stdout) if part
        ).replace(config.rpc_url, "<redacted-rpc>").strip()
        raise RuntimeError(
            "did:ethr resolution failed "
            f"(exit={completed.returncode}): {diagnostic[-1000:]}"
        )
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("did:ethr resolver returned invalid JSON") from exc
    metadata = result.get("didResolutionMetadata") or {}
    if metadata.get("error"):
        raise RuntimeError(
            f"did:ethr resolution failed with {metadata.get('error')}: "
            f"{metadata.get('message', '')}"
        )
    document = result.get("didDocument")
    if not isinstance(document, dict) or document.get("id") != did:
        raise RuntimeError("did:ethr resolver returned a missing or mismatched document")
    w3 = Web3(Web3.HTTPProvider(
        config.rpc_url,
        request_kwargs={"timeout": config.rpc_timeout_seconds},
    ))
    if not w3.is_connected():
        raise ConnectionError("DID registry RPC is unavailable after resolution")
    actual_chain_id = int(w3.eth.chain_id)
    if actual_chain_id != config.chain_id:
        raise RuntimeError(
            f"DID registry chain mismatch: expected {config.chain_id}, got {actual_chain_id}"
        )
    registry_code = bytes(w3.eth.get_code(config.did_registry_address))
    if not registry_code:
        raise RuntimeError("DID_REGISTRY_NO_CODE")
    resolved_at_block = int(w3.eth.block_number)
    return {
        "document": document,
        "resolution_metadata": metadata,
        "document_metadata": result.get("didDocumentMetadata") or {},
        "source": {
            "backend": config.backend,
            "chain_id": config.chain_id,
            "registry_address": config.did_registry_address,
            "resolved_at_block": resolved_at_block,
            "registry_code_sha256": hashlib.sha256(registry_code).hexdigest(),
        },
    }


def resolve_and_verify_dids(
    config: ChainConfig,
    identities: dict[str, ProtocolIdentity],
) -> dict[str, Any]:
    """Resolve experiment identities and check both DID relationships."""

    documents: dict[str, dict[str, Any]] = {}
    resolutions: dict[str, dict[str, Any]] = {}
    for role, identity in identities.items():
        resolved = resolve_did_document(config, identity.did)
        document = resolved["document"]
        authentication = relationship_addresses(document, "authentication")
        assertion = relationship_addresses(document, "assertionMethod")
        if identity.operation_address.lower() not in authentication:
            raise RuntimeError(
                f"resolved authentication relationship does not contain the {role} operation key"
            )
        if identity.controller_address.lower() not in assertion:
            raise RuntimeError(
                f"resolved assertionMethod relationship does not contain the {role} controller key"
            )
        documents[identity.did] = document
        resolutions[role] = {
            "did": identity.did,
            "authentication_addresses": sorted(authentication),
            "assertion_addresses": sorted(assertion),
            **resolved,
        }
    return {"documents": documents, "resolutions": resolutions}


def anchor_evidence(config: ChainConfig, private_key: str, evidence_hash: str) -> dict[str, Any]:
    anchor = EthereumEvidenceAnchor(config.rpc_url, private_key)
    result = anchor.submit(evidence_hash, wait=True)
    result["verification"] = anchor.verify_transaction(result["tx_hash"], evidence_hash)
    result["backend"] = config.backend
    return result


def decode_lineage_events(config: ChainConfig, transaction_hashes: list[str]) -> list[dict[str, Any]]:
    if not transaction_hashes:
        return []
    w3 = Web3(Web3.HTTPProvider(config.rpc_url))
    contract = w3.eth.contract(address=config.lineage_registry_address, abi=load_registry_abi())
    event_names = [item["name"] for item in load_registry_abi() if item.get("type") == "event"]
    decoded: list[dict[str, Any]] = []
    for tx_hash in transaction_hashes:
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        for name in event_names:
            event_type = getattr(contract.events, name)
            try:
                events = event_type().process_receipt(receipt, errors=DISCARD)
            except TypeError:
                events = event_type().process_receipt(receipt)
            for event in events:
                args = {
                    key: (value.hex() if isinstance(value, (bytes, bytearray)) else value)
                    for key, value in dict(event["args"]).items()
                }
                decoded.append({
                    "transaction_hash": tx_hash,
                    "block_number": int(event["blockNumber"]),
                    "log_index": int(event["logIndex"]),
                    "event": name,
                    "args": args,
                })
    decoded.sort(key=lambda item: (item["block_number"], item["log_index"]))
    return decoded


def query_root_state(config: ChainConfig, root_did: str) -> dict[str, Any]:
    w3 = Web3(Web3.HTTPProvider(config.rpc_url))
    contract = w3.eth.contract(address=config.lineage_registry_address, abi=load_registry_abi())
    governance, epoch, delegation_key, certificate_hash, active = contract.functions.roots(
        bytes32_id(root_did)
    ).call()
    return {
        "governance": governance,
        "current_epoch": int(epoch),
        "delegation_key": delegation_key,
        "certificate_hash": certificate_hash.hex(),
        "active": bool(active),
    }
