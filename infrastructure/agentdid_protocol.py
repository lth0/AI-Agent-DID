from __future__ import annotations

import base64
import copy
import datetime as dt
import gzip
import uuid
from dataclasses import dataclass
from typing import Any, Iterable

from eth_account import Account
from eth_account.messages import encode_defunct

from infrastructure.security import ReplayGuard, canonical_json, sha256_json
from infrastructure.semantic_benchmark import artifact_digest as benchmark_artifact_digest


DID_CONTEXT = "https://www.w3.org/ns/did/v1"
VC_CONTEXT = "https://www.w3.org/ns/credentials/v2"
BITSTRING_STATUS_CONTEXT = "https://www.w3.org/ns/credentials/status/v1"
RECOVERY_CONTEXT = "https://w3id.org/security/suites/secp256k1recovery-2020/v2"
PROOF_TYPE = "EcdsaSecp256k1RecoverySignature2020"
PROOF_VERSION = "agentdid-v2"
STATUS_LIST_SIZE = 16_384


def utc_iso(value: dt.datetime | None = None) -> str:
    current = value or dt.datetime.now(dt.timezone.utc)
    return current.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_utc(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def did_network(chain_id: int) -> str:
    return "sepolia" if int(chain_id) == 11155111 else f"0x{int(chain_id):x}"


def did_from_address(address: str, chain_id: int) -> str:
    return f"did:ethr:{did_network(chain_id)}:{_checksum(address)}"


def _checksum(address: str) -> str:
    from web3 import Web3

    return Web3.to_checksum_address(address)


def sign_json(body: dict[str, Any], private_key: str) -> str:
    message = encode_defunct(text=canonical_json(body))
    return "0x" + Account.sign_message(message, private_key=private_key).signature.hex()


def recover_json(body: dict[str, Any], signature: str) -> str:
    message = encode_defunct(text=canonical_json(body))
    return _checksum(Account.recover_message(message, signature=signature))


@dataclass(frozen=True)
class ProtocolIdentity:
    role: str
    did: str
    controller_address: str
    controller_private_key: str
    operation_address: str
    operation_private_key: str

    @classmethod
    def from_keys(
        cls,
        role: str,
        controller_private_key: str,
        operation_private_key: str | None,
        chain_id: int,
    ) -> "ProtocolIdentity":
        controller = Account.from_key(controller_private_key)
        operation = Account.from_key(operation_private_key or controller_private_key)
        return cls(
            role=role,
            did=did_from_address(controller.address, chain_id),
            controller_address=_checksum(controller.address),
            controller_private_key=controller.key.hex(),
            operation_address=_checksum(operation.address),
            operation_private_key=operation.key.hex(),
        )

    def public_dict(self) -> dict[str, str]:
        return {
            "role": self.role,
            "did": self.did,
            "controller_address": self.controller_address,
            "operation_address": self.operation_address,
        }


def make_did_document(
    identity: ProtocolIdentity,
    *,
    assertion_address: str | None = None,
) -> dict[str, Any]:
    controller_id = f"{identity.did}#controller"
    methods = [{
        "id": controller_id,
        "type": "EcdsaSecp256k1RecoveryMethod2020",
        "controller": identity.did,
        "blockchainAccountId": f"eip155:{_chain_id_from_did(identity.did)}:{identity.controller_address}",
    }]
    authentication_id = controller_id
    if identity.operation_address.lower() != identity.controller_address.lower():
        authentication_id = f"{identity.did}#delegate"
        methods.append({
            "id": authentication_id,
            "type": "EcdsaSecp256k1RecoveryMethod2020",
            "controller": identity.did,
            "blockchainAccountId": (
                f"eip155:{_chain_id_from_did(identity.did)}:{identity.operation_address}"
            ),
        })
    assertion = _checksum(assertion_address or identity.controller_address)
    assertion_id = controller_id
    if assertion.lower() != identity.controller_address.lower():
        assertion_id = f"{identity.did}#assertion"
        methods.append({
            "id": assertion_id,
            "type": "EcdsaSecp256k1RecoveryMethod2020",
            "controller": identity.did,
            "blockchainAccountId": f"eip155:{_chain_id_from_did(identity.did)}:{assertion}",
        })
    return {
        "@context": [DID_CONTEXT, RECOVERY_CONTEXT],
        "id": identity.did,
        "verificationMethod": methods,
        "authentication": [authentication_id],
        "assertionMethod": [assertion_id],
    }


def _chain_id_from_did(did: str) -> int:
    network = did.split(":")[-2]
    if network == "sepolia":
        return 11155111
    return int(network, 16) if network.startswith("0x") else int(network)


def relationship_addresses(document: dict[str, Any], relationship: str) -> set[str]:
    methods = {
        item.get("id"): item
        for item in document.get("verificationMethod", [])
        if isinstance(item, dict)
    }
    addresses: set[str] = set()
    for entry in document.get(relationship, []):
        method = methods.get(entry) if isinstance(entry, str) else entry
        if not isinstance(method, dict):
            continue
        account_id = method.get("blockchainAccountId")
        if isinstance(account_id, str) and account_id:
            addresses.add(account_id.rsplit(":", 1)[-1].lower())
        public_key = method.get("publicKeyHex")
        if isinstance(public_key, str) and len(public_key.removeprefix("0x")) == 40:
            addresses.add("0x" + public_key.removeprefix("0x").lower())
    return addresses


def relationship_method_ids(document: dict[str, Any], relationship: str) -> set[str]:
    return {
        str(entry if isinstance(entry, str) else entry.get("id"))
        for entry in document.get(relationship, [])
        if isinstance(entry, str) or isinstance(entry, dict)
    }


def relationship_method_for_address(
    document: dict[str, Any],
    relationship: str,
    address: str,
) -> str:
    """Return the relationship method id bound to an Ethereum address."""

    target = _checksum(address).lower()
    methods = {
        item.get("id"): item
        for item in document.get("verificationMethod", [])
        if isinstance(item, dict) and item.get("id")
    }
    for entry in document.get(relationship, []):
        method = methods.get(entry) if isinstance(entry, str) else entry
        if not isinstance(method, dict) or not method.get("id"):
            continue
        if target in relationship_addresses(
            {"verificationMethod": [method], relationship: [method]}, relationship
        ):
            return str(method["id"])
    raise ValueError(
        f"{relationship} has no verification method for address {_checksum(address)}"
    )


def verify_relationship_signature(
    document: dict[str, Any],
    relationship: str,
    body: dict[str, Any],
    signature: str,
) -> bool:
    try:
        recovered = recover_json(body, signature).lower()
    except Exception:
        return False
    return recovered in relationship_addresses(document, relationship)


def verify_document_proof(
    did_document: dict[str, Any],
    relationship: str,
    document: dict[str, Any],
    proof: dict[str, Any],
) -> bool:
    if (
        proof.get("type") != PROOF_TYPE
        or proof.get("proofPurpose") != relationship
        or proof.get("verificationMethod") not in relationship_method_ids(
            did_document, relationship
        )
    ):
        return False
    try:
        parse_utc(str(proof.get("created", "")))
    except Exception:
        return False
    proof_options = copy.deepcopy(proof)
    signature = str(proof_options.pop("jws", ""))
    return verify_relationship_signature(
        did_document,
        relationship,
        {"document": document, "proofOptions": proof_options},
        signature,
    )


def with_proof(
    body: dict[str, Any],
    signer: ProtocolIdentity,
    *,
    proof_purpose: str,
    verification_method: str,
) -> dict[str, Any]:
    value = copy.deepcopy(body)
    proof_options = {
        "type": PROOF_TYPE,
        "created": utc_iso(),
        "proofPurpose": proof_purpose,
        "verificationMethod": verification_method,
    }
    signing_key = (
        signer.controller_private_key
        if proof_purpose == "assertionMethod"
        else signer.operation_private_key
    )
    value["proof"] = {
        **proof_options,
        "jws": sign_json(
            {"document": body, "proofOptions": proof_options},
            signing_key,
        ),
    }
    return value


def _encode_status_list(revoked_indices: Iterable[int]) -> str:
    bits = bytearray(STATUS_LIST_SIZE)
    for index in revoked_indices:
        if not 0 <= int(index) < STATUS_LIST_SIZE * 8:
            raise ValueError("status list index is out of range")
        # Bitstring Status List defines index zero as the left-most (most
        # significant) bit of the first byte.
        bits[int(index) // 8] |= 1 << (7 - (int(index) % 8))
    compressed = gzip.compress(bytes(bits), mtime=0)
    # Multibase base64url without padding uses the ``u`` identifier prefix.
    return "u" + base64.urlsafe_b64encode(compressed).decode("ascii").rstrip("=")


def _status_is_revoked(encoded: str, index: int) -> bool:
    if not encoded.startswith("u"):
        raise ValueError("encoded status list must use multibase base64url")
    payload = encoded[1:]
    padded = payload + "=" * (-len(payload) % 4)
    bits = gzip.decompress(base64.urlsafe_b64decode(padded))
    if not 0 <= int(index) < len(bits) * 8:
        raise ValueError("status list index is out of range")
    return bool(bits[int(index) // 8] & (1 << (7 - (int(index) % 8))))


def issue_status_list(
    issuer: ProtocolIdentity,
    *,
    list_id: str,
    revoked_indices: Iterable[int] = (),
) -> dict[str, Any]:
    body = {
        "@context": [VC_CONTEXT, BITSTRING_STATUS_CONTEXT],
        "id": list_id,
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "issuer": issuer.did,
        "validFrom": utc_iso(dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)),
        "credentialSubject": {
            "id": f"{list_id}#list",
            "type": "BitstringStatusList",
            "statusPurpose": "revocation",
            "encodedList": _encode_status_list(revoked_indices),
        },
    }
    return with_proof(
        body,
        issuer,
        proof_purpose="assertionMethod",
        verification_method=f"{issuer.did}#controller",
    )


def issue_credential(
    issuer: ProtocolIdentity,
    holder_did: str,
    *,
    credential_type: str,
    claims: dict[str, Any],
    status_list_id: str,
    status_index: int,
    credential_id: str | None = None,
) -> dict[str, Any]:
    now = dt.datetime.now(dt.timezone.utc)
    body = {
        "@context": [VC_CONTEXT, BITSTRING_STATUS_CONTEXT, "https://schema.org"],
        "id": credential_id or f"urn:uuid:{uuid.uuid4()}",
        "type": ["VerifiableCredential", credential_type],
        "issuer": issuer.did,
        "validFrom": utc_iso(now - dt.timedelta(minutes=1)),
        "validUntil": utc_iso(now + dt.timedelta(days=1)),
        "credentialSubject": {"id": holder_did, **copy.deepcopy(claims)},
        "credentialStatus": {
            "id": f"{status_list_id}#{status_index}",
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": str(status_index),
            "statusListCredential": status_list_id,
        },
    }
    return with_proof(
        body,
        issuer,
        proof_purpose="assertionMethod",
        verification_method=f"{issuer.did}#controller",
    )


def create_presentation(
    credentials: list[dict[str, Any]],
    holder: ProtocolIdentity,
    *,
    challenge: str,
    audience: str,
    verification_method: str | None = None,
) -> dict[str, Any]:
    presentation = {
        "@context": [VC_CONTEXT],
        "type": ["VerifiablePresentation"],
        "holder": holder.did,
        "verifiableCredential": copy.deepcopy(credentials),
    }
    proof_options = {
        "version": PROOF_VERSION,
        "type": PROOF_TYPE,
        "created": utc_iso(),
        "verificationMethod": verification_method or f"{holder.did}#delegate",
        "proofPurpose": "authentication",
        "challenge": challenge,
        "audience": audience,
    }
    if (
        verification_method is None
        and holder.operation_address.lower() == holder.controller_address.lower()
    ):
        proof_options["verificationMethod"] = f"{holder.did}#controller"
    signed_body = {"presentation": presentation, "proofOptions": proof_options}
    result = copy.deepcopy(presentation)
    result["proof"] = {**proof_options, "jws": sign_json(signed_body, holder.operation_private_key)}
    return result


@dataclass(frozen=True)
class ProtocolDecision:
    accepted: bool
    code: str
    reason: str
    trace: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "code": self.code,
            "reason": self.reason,
            "trace": self.trace,
        }


class DidVcVpVerifier:
    def __init__(
        self,
        documents: dict[str, dict[str, Any]],
        *,
        trusted_issuers: Iterable[str],
        status_lists: dict[str, dict[str, Any]],
        replay_guard: ReplayGuard | None = None,
        max_age_seconds: int = 120,
    ):
        self.documents = documents
        self.trusted_issuers = set(trusted_issuers)
        self.status_lists = status_lists
        self.replay_guard = replay_guard or ReplayGuard(ttl_seconds=3600)
        self.max_age_seconds = int(max_age_seconds)

    @staticmethod
    def _reject(code: str, reason: str, trace: dict[str, Any]) -> ProtocolDecision:
        trace["accepted"] = False
        trace["code"] = code
        return ProtocolDecision(False, code, reason, trace)

    def verify(
        self,
        presentation: dict[str, Any],
        *,
        expected_holder: str,
        expected_challenge: str,
        expected_audience: str,
        now: dt.datetime | None = None,
    ) -> ProtocolDecision:
        trace: dict[str, Any] = {"layer": "did-vc-vp", "checks": []}
        current = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
        if not isinstance(presentation, dict):
            return self._reject("VP_MALFORMED", "presentation must be an object", trace)
        if VC_CONTEXT not in presentation.get("@context", []):
            return self._reject("VP_CONTEXT_INVALID", "VC Data Model 2.0 context is required", trace)
        if "VerifiablePresentation" not in presentation.get("type", []):
            return self._reject("VP_TYPE_INVALID", "VerifiablePresentation type is required", trace)
        holder = presentation.get("holder")
        if holder != expected_holder:
            return self._reject("VP_HOLDER_MISMATCH", "presentation holder does not match request", trace)
        holder_document = self.documents.get(holder)
        if not holder_document:
            return self._reject("DID_RESOLUTION_FAILED", "holder DID document is unavailable", trace)

        proof = presentation.get("proof")
        if not isinstance(proof, dict):
            return self._reject("VP_PROOF_MISSING", "presentation proof is required", trace)
        if (
            proof.get("version") != PROOF_VERSION
            or proof.get("type") != PROOF_TYPE
            or proof.get("proofPurpose") != "authentication"
            or proof.get("verificationMethod") not in relationship_method_ids(
                holder_document, "authentication"
            )
        ):
            return self._reject("VP_PROOF_OPTIONS_INVALID", "VP proof version or purpose is invalid", trace)
        if not isinstance(proof.get("challenge"), str) or not proof.get("challenge"):
            return self._reject("VP_CHALLENGE_INVALID", "VP challenge is required", trace)
        if not isinstance(proof.get("audience"), str) or not proof.get("audience"):
            return self._reject("VP_AUDIENCE_INVALID", "VP audience is required", trace)
        if proof.get("challenge") != expected_challenge:
            return self._reject("VP_CHALLENGE_MISMATCH", "VP challenge does not match", trace)
        if proof.get("audience") != expected_audience:
            return self._reject("VP_AUDIENCE_MISMATCH", "VP audience does not match", trace)
        try:
            created = parse_utc(str(proof.get("created", "")))
        except Exception:
            return self._reject("VP_CREATED_INVALID", "VP created timestamp is invalid", trace)
        if abs((current - created).total_seconds()) > self.max_age_seconds:
            return self._reject("VP_STALE", "VP proof is stale", trace)
        proof_options = copy.deepcopy(proof)
        signature = str(proof_options.pop("jws", ""))
        body = copy.deepcopy(presentation)
        body.pop("proof", None)
        if not verify_relationship_signature(
            holder_document,
            "authentication",
            {"presentation": body, "proofOptions": proof_options},
            signature,
        ):
            return self._reject("VP_SIGNATURE_INVALID", "VP is not signed by an authentication key", trace)
        trace["checks"].extend(["holder", "challenge", "audience", "freshness", "vp_signature"])

        vcs = presentation.get("verifiableCredential")
        if not isinstance(vcs, list) or not vcs:
            return self._reject("VC_MISSING", "at least one credential is required", trace)
        seen: set[str] = set()
        seen_ids: set[str] = set()
        credential_types: list[str] = []
        for vc in vcs:
            if not isinstance(vc, dict):
                return self._reject("VC_MALFORMED", "credential must be an object", trace)
            fingerprint = sha256_json(vc)
            if fingerprint in seen:
                return self._reject("VC_DUPLICATE", "duplicate credential in presentation", trace)
            seen.add(fingerprint)
            credential_id = vc.get("id")
            if not isinstance(credential_id, str) or not credential_id:
                return self._reject("VC_ID_INVALID", "credential id is required", trace)
            if credential_id in seen_ids:
                return self._reject("VC_ID_DUPLICATE", "credential id is repeated", trace)
            seen_ids.add(credential_id)
            decision = self._verify_credential(vc, holder, current)
            if decision is not None:
                code, reason = decision
                return self._reject(code, reason, trace)
            credential_types.extend(
                item for item in vc.get("type", []) if item != "VerifiableCredential"
            )
        trace["checks"].append("credentials")

        presentation_hash = sha256_json(presentation)
        challenge_token = sha256_json({
            "holder": holder,
            "audience": expected_audience,
            "challenge": expected_challenge,
        })
        if not self.replay_guard.consume(
            "vp-challenge", challenge_token, now=current.timestamp()
        ):
            return self._reject("VP_REPLAY", "VP challenge has already been consumed", trace)
        if not self.replay_guard.consume("vp", presentation_hash, now=current.timestamp()):
            return self._reject("VP_REPLAY", "presentation has already been consumed", trace)
        trace.update({
            "accepted": True,
            "code": "PROTOCOL_ACCEPTED",
            "holder": holder,
            "credential_types": sorted(set(credential_types)),
            "presentation_hash": presentation_hash,
        })
        return ProtocolDecision(True, "PROTOCOL_ACCEPTED", "DID, VC and VP verified", trace)

    def _verify_credential(
        self,
        credential: dict[str, Any],
        holder: str,
        now: dt.datetime,
    ) -> tuple[str, str] | None:
        if VC_CONTEXT not in credential.get("@context", []):
            return "VC_CONTEXT_INVALID", "VC Data Model 2.0 context is required"
        if "VerifiableCredential" not in credential.get("type", []):
            return "VC_TYPE_INVALID", "VerifiableCredential type is required"
        subject = credential.get("credentialSubject")
        if not isinstance(subject, dict) or subject.get("id") != holder:
            return "VC_SUBJECT_HOLDER_MISMATCH", "credential subject is not the VP holder"
        issuer = credential.get("issuer")
        if issuer not in self.trusted_issuers:
            return "VC_ISSUER_UNTRUSTED", "credential issuer is not trusted"
        issuer_document = self.documents.get(str(issuer))
        if not issuer_document:
            return "DID_RESOLUTION_FAILED", "issuer DID document is unavailable"
        try:
            if parse_utc(str(credential["validFrom"])) > now:
                return "VC_NOT_YET_VALID", "credential is not yet valid"
            if parse_utc(str(credential["validUntil"])) < now:
                return "VC_EXPIRED", "credential has expired"
        except Exception:
            return "VC_TIME_INVALID", "credential validity timestamps are invalid"
        proof = credential.get("proof")
        if not isinstance(proof, dict):
            return "VC_PROOF_INVALID", "credential assertion proof is missing"
        vc_body = copy.deepcopy(credential)
        vc_body.pop("proof", None)
        if not verify_document_proof(
            issuer_document, "assertionMethod", vc_body, proof
        ):
            return "VC_SIGNATURE_INVALID", "credential assertion signature is invalid"

        status = credential.get("credentialStatus")
        if not isinstance(status, dict):
            return "VC_STATUS_MISSING", "credential status entry is required"
        if (
            status.get("type") != "BitstringStatusListEntry"
            or status.get("statusPurpose") != "revocation"
        ):
            return "VC_STATUS_INVALID", "credential status type or purpose is invalid"
        list_id = status.get("statusListCredential")
        status_list = self.status_lists.get(str(list_id))
        if not status_list:
            return "VC_STATUS_UNAVAILABLE", "credential status list is unavailable"
        status_body = copy.deepcopy(status_list)
        status_proof = status_body.pop("proof", {})
        status_issuer = status_list.get("issuer")
        status_document = self.documents.get(str(status_issuer))
        status_subject = status_list.get("credentialSubject")
        if (
            status_issuer not in self.trusted_issuers
            or not status_document
            or "BitstringStatusListCredential" not in status_list.get("type", [])
            or status_list.get("id") != list_id
            or not isinstance(status_subject, dict)
            or status_subject.get("statusPurpose") != "revocation"
            or not isinstance(status_proof, dict)
            or not verify_document_proof(
                status_document,
                "assertionMethod",
                status_body,
                status_proof,
            )
        ):
            return "VC_STATUS_PROOF_INVALID", "status-list credential signature is invalid"
        try:
            encoded = status_list["credentialSubject"]["encodedList"]
            index = int(status["statusListIndex"])
            if status.get("id") != f"{list_id}#{index}":
                return "VC_STATUS_INVALID", "credential status id does not match its list index"
            if _status_is_revoked(encoded, index):
                return "VC_STATUS_REVOKED", "credential is revoked"
        except Exception:
            return "VC_STATUS_INVALID", "credential status entry is malformed"
        return None


def artifact_digest(profile: str) -> str:
    """Return the canonical digest used by the independent semantic benchmark.

    This compatibility wrapper keeps older imports working while ensuring that
    credentials, state reports, and benchmark evidence identify the same
    artifact bytes.
    """

    return benchmark_artifact_digest(profile)
