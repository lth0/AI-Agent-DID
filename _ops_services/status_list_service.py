"""Issuer-signed Bitstring Status List support for local experiments.

The registry intentionally stores only public revocation metadata.  Issuer
private keys remain owned by ``issuer_server`` and are supplied through a
signing callback when a status-list credential is rendered.
"""

from __future__ import annotations

import base64
import datetime as dt
import gzip
import json
import os
import threading
from dataclasses import dataclass
from typing import Any, Callable

from infrastructure.security import canonical_json


DEFAULT_LIST_SIZE_BITS = 131_072


def _iso_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def encode_status_bits(
    revoked_indices: set[int] | list[int],
    *,
    size_bits: int = DEFAULT_LIST_SIZE_BITS,
) -> str:
    """Encode revocation bits as deterministic gzip + base64url without padding."""

    if size_bits <= 0 or size_bits % 8:
        raise ValueError("size_bits must be a positive multiple of 8")
    bitstring = bytearray(size_bits // 8)
    for index in revoked_indices:
        if not isinstance(index, int) or isinstance(index, bool):
            raise TypeError("status-list indices must be integers")
        if index < 0 or index >= size_bits:
            raise ValueError(f"status-list index {index} is out of range")
        bitstring[index // 8] |= 1 << (index % 8)
    compressed = gzip.compress(bytes(bitstring), mtime=0)
    return base64.urlsafe_b64encode(compressed).decode("ascii").rstrip("=")


def decode_status_bits(encoded_list: str, *, size_bits: int = DEFAULT_LIST_SIZE_BITS) -> bytes:
    """Decode an encoded list, validating the expected uncompressed length."""

    padding = "=" * (-len(encoded_list) % 4)
    raw = gzip.decompress(base64.urlsafe_b64decode(encoded_list + padding))
    expected_length = size_bits // 8
    if len(raw) != expected_length:
        raise ValueError(
            f"decoded status list has {len(raw)} bytes; expected {expected_length}"
        )
    return raw


def status_bit_is_set(encoded_list: str, index: int, *, size_bits: int = DEFAULT_LIST_SIZE_BITS) -> bool:
    if index < 0 or index >= size_bits:
        raise ValueError(f"status-list index {index} is out of range")
    raw = decode_status_bits(encoded_list, size_bits=size_bits)
    return bool(raw[index // 8] & (1 << (index % 8)))


@dataclass(frozen=True)
class StatusListEntry:
    list_id: str
    index: int
    credential_url: str

    def as_credential_status(self) -> dict[str, str]:
        return {
            "id": f"{self.credential_url}#{self.index}",
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": str(self.index),
            "statusListCredential": self.credential_url,
        }


class BitstringStatusListRegistry:
    """Thread-safe, file-backed status registry under the workspace ``.codex`` tree."""

    def __init__(
        self,
        *,
        issuer_did: str,
        public_base_url: str,
        storage_dir: str,
        list_id: str = "agentdid-capability-revocation",
        size_bits: int = DEFAULT_LIST_SIZE_BITS,
    ) -> None:
        self.issuer_did = issuer_did
        self.public_base_url = public_base_url.rstrip("/")
        self.storage_dir = os.path.abspath(storage_dir)
        self.list_id = list_id
        self.size_bits = size_bits
        self._lock = threading.RLock()
        self._state_path = os.path.join(self.storage_dir, f"{self.list_id}.json")
        self._state: dict[str, Any] = {
            "schemaVersion": "agentdid-bitstring-status-v1",
            "listId": self.list_id,
            "nextIndex": 0,
            "revokedIndices": [],
            "updatedAt": _iso_now(),
        }
        os.makedirs(self.storage_dir, exist_ok=True)
        self._load()

    @property
    def credential_url(self) -> str:
        return f"{self.public_base_url}/status-lists/{self.list_id}"

    def _load(self) -> None:
        if not os.path.exists(self._state_path):
            self._persist()
            return
        with open(self._state_path, "r", encoding="utf-8") as handle:
            stored = json.load(handle)
        if stored.get("listId") != self.list_id:
            raise ValueError("stored status-list id does not match registry")
        next_index = int(stored.get("nextIndex", 0))
        revoked = sorted({int(item) for item in stored.get("revokedIndices", [])})
        if not 0 <= next_index <= self.size_bits:
            raise ValueError("stored nextIndex is out of range")
        if any(item < 0 or item >= self.size_bits for item in revoked):
            raise ValueError("stored revoked index is out of range")
        self._state = {
            "schemaVersion": "agentdid-bitstring-status-v1",
            "listId": self.list_id,
            "nextIndex": next_index,
            "revokedIndices": revoked,
            "updatedAt": stored.get("updatedAt", _iso_now()),
        }

    def _persist(self) -> None:
        self._state["updatedAt"] = _iso_now()
        temporary_path = self._state_path + ".tmp"
        with open(temporary_path, "w", encoding="utf-8") as handle:
            handle.write(canonical_json(self._state))
            handle.write("\n")
        os.replace(temporary_path, self._state_path)

    def allocate(self) -> StatusListEntry:
        with self._lock:
            index = int(self._state["nextIndex"])
            if index >= self.size_bits:
                raise RuntimeError("status list has no remaining entries")
            self._state["nextIndex"] = index + 1
            self._persist()
            return StatusListEntry(self.list_id, index, self.credential_url)

    def set_revoked(self, index: int, revoked: bool = True) -> bool:
        """Set one entry and return its resulting revoked state."""

        if not isinstance(index, int) or isinstance(index, bool):
            raise TypeError("status-list index must be an integer")
        with self._lock:
            if index < 0 or index >= int(self._state["nextIndex"]):
                raise ValueError("status-list index has not been allocated")
            revoked_indices = set(self._state["revokedIndices"])
            if revoked:
                revoked_indices.add(index)
            else:
                revoked_indices.discard(index)
            self._state["revokedIndices"] = sorted(revoked_indices)
            self._persist()
            return index in revoked_indices

    def is_revoked(self, index: int) -> bool:
        with self._lock:
            return index in set(self._state["revokedIndices"])

    def render_credential(
        self,
        signer: Callable[[dict[str, Any]], str],
        *,
        verification_method: str,
    ) -> dict[str, Any]:
        """Create and sign the current Bitstring Status List credential."""

        with self._lock:
            encoded_list = encode_status_bits(
                set(self._state["revokedIndices"]), size_bits=self.size_bits
            )
            valid_from = self._state["updatedAt"]
        payload: dict[str, Any] = {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/status/v1",
            ],
            "id": self.credential_url,
            "type": ["VerifiableCredential", "BitstringStatusListCredential"],
            "issuer": self.issuer_did,
            "validFrom": valid_from,
            "credentialSubject": {
                "id": f"{self.credential_url}#list",
                "type": "BitstringStatusList",
                "statusPurpose": "revocation",
                "encodedList": encoded_list,
            },
        }
        signature = signer(payload)
        result = dict(payload)
        result["proof"] = {
            "type": "EcdsaSecp256k1Signature2019",
            "created": _iso_now(),
            "proofPurpose": "assertionMethod",
            "verificationMethod": verification_method,
            "jws": signature,
        }
        return result
