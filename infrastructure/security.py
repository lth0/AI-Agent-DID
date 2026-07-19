"""Security primitives shared by AgentDID runtimes and experiments.

The module deliberately contains no network setup so its canonicalisation,
replay protection, and evidence generation can be tested offline.
"""

from __future__ import annotations

import copy
import dataclasses
import datetime
import hashlib
import json
import os
import threading
import time
import uuid
from typing import Any, Iterable


def canonical_json(value: Any) -> str:
    """Return the JSON representation used by every AgentDID signature."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def verify_evidence_event(event: dict[str, Any]) -> tuple[bool, str]:
    """Recompute an audit event hash before it is anchored or analysed."""

    if not isinstance(event, dict) or not event.get("evidence_hash"):
        return False, "Missing evidence_hash"
    body = copy.deepcopy(event)
    claimed_hash = body.pop("evidence_hash")
    computed_hash = sha256_json(body)
    if claimed_hash != computed_hash:
        return False, f"Evidence hash mismatch: expected {computed_hash}"
    return True, "Evidence hash valid"


def unsigned_payload(payload: dict[str, Any], signature_field: str = "signature") -> dict[str, Any]:
    result = copy.deepcopy(payload)
    result.pop(signature_field, None)
    return result


@dataclasses.dataclass(frozen=True)
class SignedPayloadCheck:
    valid: bool
    reason: str


def verify_signed_payload(
    validator: Any,
    payload: dict[str, Any],
    claimed_did: str,
    *,
    signature_field: str = "signature",
    expected_nonce: str | None = None,
    expected_task_id: str | None = None,
    max_age_seconds: float | None = 120.0,
    now: float | None = None,
    required_fields: Iterable[str] = (),
) -> SignedPayloadCheck:
    """Validate binding, freshness and DID signature of a JSON response."""

    if not isinstance(payload, dict):
        return SignedPayloadCheck(False, "Payload must be a JSON object")

    missing = [field for field in required_fields if payload.get(field) is None]
    if missing:
        return SignedPayloadCheck(False, f"Missing fields: {', '.join(missing)}")

    if payload.get("holder_did") != claimed_did:
        return SignedPayloadCheck(False, "Holder DID mismatch")

    if expected_nonce is not None and payload.get("nonce") != expected_nonce:
        return SignedPayloadCheck(False, "Nonce mismatch")

    if expected_task_id is not None and payload.get("task_id") != expected_task_id:
        return SignedPayloadCheck(False, "Task ID mismatch")

    if max_age_seconds is not None:
        timestamp = payload.get("timestamp")
        if not isinstance(timestamp, (int, float)):
            return SignedPayloadCheck(False, "Missing or invalid timestamp")
        current_time = time.time() if now is None else now
        if abs(current_time - float(timestamp)) > max_age_seconds:
            return SignedPayloadCheck(False, "Stale response")

    signature = payload.get(signature_field)
    if not signature:
        return SignedPayloadCheck(False, "Missing holder signature")

    body = unsigned_payload(payload, signature_field)
    valid, reason = validator.verify_request_signature(
        canonical_json(body), signature, claimed_did
    )
    if not valid:
        return SignedPayloadCheck(False, f"Invalid holder signature: {reason}")
    return SignedPayloadCheck(True, "Signed payload valid")


class ReplayGuard:
    """Thread-safe, bounded in-memory one-time token store."""

    def __init__(self, ttl_seconds: float = 600.0, max_entries: int = 10_000):
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def consume(self, namespace: str, token: str | None, now: float | None = None) -> bool:
        """Return True once for a token; return False while it remains live."""

        if not token:
            return False
        current_time = time.time() if now is None else now
        key = f"{namespace}:{token}"
        with self._lock:
            cutoff = current_time - self.ttl_seconds
            self._seen = {item: ts for item, ts in self._seen.items() if ts >= cutoff}
            if key in self._seen:
                return False
            if len(self._seen) >= self.max_entries:
                oldest = min(self._seen, key=self._seen.get)
                self._seen.pop(oldest, None)
            self._seen[key] = current_time
            return True


class SecurityAuditRecorder:
    """Append hash-based experiment evidence to a JSON Lines file."""

    def __init__(self, output_file: str):
        self.output_file = output_file
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

    def record(
        self,
        event_type: str,
        subject_did: str | None,
        request_payload: dict[str, Any],
        response_payload: dict[str, Any] | None,
        accepted: bool,
        reason: str,
        **metadata: Any,
    ) -> dict[str, Any]:
        response_payload = response_payload or {}
        event = {
            "schema_version": "agentdid-security-v1",
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "subject_did": subject_did,
            "request_hash": sha256_json(request_payload),
            "response_hash": sha256_json(response_payload),
            "accepted": bool(accepted),
            "reason": reason,
            "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "metadata": metadata,
        }
        event["evidence_hash"] = sha256_json(event)
        line = canonical_json(event) + "\n"
        with self._lock:
            with open(self.output_file, "a", encoding="utf-8") as handle:
                handle.write(line)
        return event
