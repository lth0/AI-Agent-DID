from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from typing import Any

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import to_checksum_address

from infrastructure.security import canonical_json, sha256_json
from .models import AgentType, LineageInvocation


SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


def hkdf_sha256(ikm: bytes, *, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()
    result = b""
    previous = b""
    counter = 1
    while len(result) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        result += previous
        counter += 1
    return result[:length]


def derive_secp256k1_key(seed: bytes, *, root_did: str, epoch: int, role: str) -> str:
    material = hkdf_sha256(
        seed,
        salt=hashlib.sha256(f"{root_did}|{epoch}".encode()).digest(),
        info=f"AgentLineage-DID/{role}".encode(),
    )
    scalar = (int.from_bytes(material, "big") % (SECP256K1_ORDER - 1)) + 1
    return "0x" + scalar.to_bytes(32, "big").hex()


def did_from_address(address: str, network: str = "sepolia") -> str:
    return f"did:ethr:{network}:{to_checksum_address(address)}"


def address_from_did(did: str) -> str:
    value = did.rsplit(":", 1)[-1]
    if not value.startswith("0x") or len(value) != 42:
        raise ValueError(f"unsupported DID address: {did}")
    return to_checksum_address(value)


def typed_message(
    payload: dict[str, Any], *, purpose: str, chain_id: int, verifying_contract: str
) -> dict[str, Any]:
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "AgentLineageEnvelope": [
                {"name": "purpose", "type": "string"},
                {"name": "payloadHash", "type": "bytes32"},
            ],
        },
        "primaryType": "AgentLineageEnvelope",
        "domain": {
            "name": "AgentLineage-DID",
            "version": "1",
            "chainId": int(chain_id),
            "verifyingContract": to_checksum_address(verifying_contract),
        },
        "message": {"purpose": purpose, "payloadHash": "0x" + sha256_json(payload)},
    }


def typed_hash_message(
    payload_hash: str, *, purpose: str, chain_id: int, verifying_contract: str
) -> dict[str, Any]:
    if not payload_hash.startswith("0x"):
        payload_hash = "0x" + payload_hash
    if len(payload_hash) != 66:
        raise ValueError("payload_hash must be bytes32")
    message = typed_message(
        {}, purpose=purpose, chain_id=chain_id, verifying_contract=verifying_contract
    )
    message["message"]["payloadHash"] = payload_hash
    return message


def sign_envelope_hash(
    private_key: str,
    payload_hash: str,
    *,
    purpose: str,
    chain_id: int,
    verifying_contract: str,
) -> str:
    message = encode_typed_data(
        full_message=typed_hash_message(
            payload_hash,
            purpose=purpose,
            chain_id=chain_id,
            verifying_contract=verifying_contract,
        )
    )
    return "0x" + Account.sign_message(message, private_key=private_key).signature.hex()


def sign_typed_payload(
    private_key: str,
    payload: dict[str, Any],
    *,
    purpose: str,
    chain_id: int,
    verifying_contract: str = ZERO_ADDRESS,
) -> str:
    message = encode_typed_data(
        full_message=typed_message(
            payload, purpose=purpose, chain_id=chain_id, verifying_contract=verifying_contract
        )
    )
    return "0x" + Account.sign_message(message, private_key=private_key).signature.hex()


def recover_typed_signer(
    payload: dict[str, Any],
    signature: str,
    *,
    purpose: str,
    chain_id: int,
    verifying_contract: str = ZERO_ADDRESS,
) -> str:
    message = encode_typed_data(
        full_message=typed_message(
            payload, purpose=purpose, chain_id=chain_id, verifying_contract=verifying_contract
        )
    )
    return to_checksum_address(Account.recover_message(message, signature=signature))


@dataclass
class LineageWallet:
    agent_type: AgentType
    operation_private_key: str
    delegation_private_key: str | None = None
    network: str = "sepolia"

    @classmethod
    def generate(cls, agent_type: AgentType, *, delegable: bool = False) -> "LineageWallet":
        op = Account.create(os.urandom(32))
        delegation = Account.create(os.urandom(32)) if delegable else None
        return cls(
            agent_type=agent_type,
            operation_private_key=op.key.hex(),
            delegation_private_key=delegation.key.hex() if delegation else None,
        )

    @property
    def operation_address(self) -> str:
        return Account.from_key(self.operation_private_key).address

    @property
    def delegation_address(self) -> str | None:
        if not self.delegation_private_key:
            return None
        return Account.from_key(self.delegation_private_key).address

    @property
    def did(self) -> str:
        return did_from_address(self.operation_address, self.network)

    def enrollment_payload(
        self, *, root_did: str, parent_did: str, nonce: str, timestamp: int
    ) -> dict[str, Any]:
        return {
            "schema": "agentlineage-enrollment-v1",
            "root_did": root_did,
            "parent_did": parent_did,
            "child_did": self.did,
            "agent_type": self.agent_type.value,
            "operation_key": self.operation_address,
            "delegation_key": self.delegation_address,
            "nonce": nonce,
            "timestamp": timestamp,
        }

    def create_enrollment_proof(
        self,
        *,
        root_did: str,
        parent_did: str,
        nonce: str,
        timestamp: int,
        chain_id: int,
        verifying_contract: str = ZERO_ADDRESS,
    ) -> dict[str, Any]:
        payload = self.enrollment_payload(
            root_did=root_did, parent_did=parent_did, nonce=nonce, timestamp=timestamp
        )
        proof = {
            **payload,
            "signature": sign_typed_payload(
                self.operation_private_key,
                payload,
                purpose="AgentLineage/ENROLL/v1",
                chain_id=chain_id,
                verifying_contract=verifying_contract,
            ),
        }
        if self.delegation_private_key:
            proof["delegation_signature"] = sign_typed_payload(
                self.delegation_private_key,
                payload,
                purpose="AgentLineage/ENROLL_DELEGATION_KEY/v1",
                chain_id=chain_id,
                verifying_contract=verifying_contract,
            )
        return proof

    def sign_invocation(
        self,
        invocation: LineageInvocation,
        *,
        chain_id: int,
        verifying_contract: str = ZERO_ADDRESS,
    ) -> LineageInvocation:
        if invocation.leaf_did != self.did:
            raise ValueError("invocation leaf DID does not match wallet")
        signature = sign_typed_payload(
            self.operation_private_key,
            invocation.unsigned_dict(),
            purpose="AgentLineage/REQUEST/v1",
            chain_id=chain_id,
            verifying_contract=verifying_contract,
        )
        return LineageInvocation(**{**invocation.__dict__, "signature": signature})

    def save_keystore(self, directory: str, password: str) -> str:
        if not password:
            raise ValueError("keystore password is required")
        os.makedirs(directory, exist_ok=True)
        payload = {
            "schema": "agentlineage-keystore-v1",
            "agent_type": self.agent_type.value,
            "did": self.did,
            "operation": Account.encrypt(self.operation_private_key, password),
            "delegation": (
                Account.encrypt(self.delegation_private_key, password)
                if self.delegation_private_key else None
            ),
        }
        path = os.path.join(directory, self.operation_address.lower() + ".json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        return path

    @classmethod
    def load_keystore(cls, path: str, password: str) -> "LineageWallet":
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        op_key = "0x" + Account.decrypt(payload["operation"], password).hex()
        delegation = payload.get("delegation")
        del_key = "0x" + Account.decrypt(delegation, password).hex() if delegation else None
        return cls(AgentType(payload["agent_type"]), op_key, del_key)


@dataclass(frozen=True)
class RootKeyManager:
    root_did: str
    master_seed: bytes

    @classmethod
    def from_environment(cls, root_did: str, variable: str = "AGENTLINEAGE_ROOT_SEED") -> "RootKeyManager":
        raw = os.environ.get(variable, "")
        if not raw:
            raise ValueError(f"{variable} is required")
        try:
            seed = bytes.fromhex(raw.removeprefix("0x"))
        except ValueError as exc:
            raise ValueError(f"{variable} must be hex encoded") from exc
        if len(seed) < 32:
            raise ValueError(f"{variable} must contain at least 32 bytes")
        return cls(root_did, seed)

    def derive(self, epoch: int, role: str = "delegation") -> str:
        return derive_secp256k1_key(
            self.master_seed, root_did=self.root_did, epoch=epoch, role=role
        )
