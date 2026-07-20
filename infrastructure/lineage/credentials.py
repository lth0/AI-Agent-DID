from __future__ import annotations

import dataclasses
import time
import uuid
from typing import Any

from eth_account import Account

from infrastructure.security import sha256_json
from .crypto import (
    ZERO_ADDRESS,
    address_from_did,
    recover_typed_signer,
    sign_typed_payload,
)
from .models import (
    AgentType,
    BudgetLimits,
    DelegationCredential,
    EpochKeyCertificate,
    PermissionEnvelope,
)


def credential_hash(value: EpochKeyCertificate | DelegationCredential | dict[str, Any]) -> str:
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    return sha256_json(value)


def lineage_commitment(
    parent_commitment: str,
    *,
    child_did: str,
    operation_key: str,
    permission: PermissionEnvelope,
    jti: str,
) -> str:
    return sha256_json({
        "domain": "AgentLineage/LC/v1",
        "parent": parent_commitment,
        "child_did": child_did,
        "operation_key": operation_key.lower(),
        "permission_hash": sha256_json(permission.to_dict()),
        "jti": jti,
    })


def create_epoch_certificate(
    *,
    root_did: str,
    epoch: int,
    delegation_key: str,
    not_before: int,
    expires_at: int,
    status_ref: dict[str, Any],
    root_identity_private_key: str,
    chain_id: int,
    verifying_contract: str = ZERO_ADDRESS,
) -> EpochKeyCertificate:
    certificate = EpochKeyCertificate(
        root_did=root_did,
        epoch=epoch,
        purpose="capabilityDelegation",
        delegation_key=delegation_key,
        not_before=not_before,
        expires_at=expires_at,
        status_ref=status_ref,
    )
    signature = sign_typed_payload(
        root_identity_private_key,
        certificate.unsigned_dict(),
        purpose="AgentLineage/EPOCH/v1",
        chain_id=chain_id,
        verifying_contract=verifying_contract,
    )
    return dataclasses.replace(certificate, signature=signature)


def verify_epoch_certificate(
    certificate: EpochKeyCertificate,
    *,
    chain_id: int,
    verifying_contract: str,
    now: int,
) -> tuple[bool, str]:
    if certificate.purpose != "capabilityDelegation":
        return False, "epoch key purpose mismatch"
    if not certificate.not_before <= now <= certificate.expires_at:
        return False, "epoch certificate is not active"
    try:
        signer = recover_typed_signer(
            certificate.unsigned_dict(), certificate.signature,
            purpose="AgentLineage/EPOCH/v1", chain_id=chain_id,
            verifying_contract=verifying_contract,
        )
        if signer.lower() != address_from_did(certificate.root_did).lower():
            return False, "epoch certificate root signature mismatch"
    except Exception as exc:
        return False, f"invalid epoch signature: {exc}"
    return True, "epoch certificate valid"


def verify_enrollment_proof(
    proof: dict[str, Any],
    *,
    expected_root_did: str,
    expected_parent_did: str,
    expected_nonce: str,
    chain_id: int,
    verifying_contract: str = ZERO_ADDRESS,
    now: int | None = None,
    max_age_seconds: int = 120,
) -> tuple[bool, str]:
    signature = proof.get("signature", "")
    delegation_signature = proof.get("delegation_signature", "")
    payload = dict(proof)
    payload.pop("signature", None)
    payload.pop("delegation_signature", None)
    if payload.get("schema") != "agentlineage-enrollment-v1":
        return False, "invalid enrollment schema"
    if payload.get("root_did") != expected_root_did or payload.get("parent_did") != expected_parent_did:
        return False, "enrollment lineage binding mismatch"
    if payload.get("nonce") != expected_nonce:
        return False, "enrollment nonce mismatch"
    current = int(time.time()) if now is None else int(now)
    if abs(current - int(payload.get("timestamp", 0))) > max_age_seconds:
        return False, "stale enrollment proof"
    try:
        signer = recover_typed_signer(
            payload, signature, purpose="AgentLineage/ENROLL/v1",
            chain_id=chain_id, verifying_contract=verifying_contract,
        )
        if signer.lower() != str(payload.get("operation_key", "")).lower():
            return False, "enrollment proof is not signed by operation key"
        if address_from_did(payload["child_did"]).lower() != signer.lower():
            return False, "child DID is not bound to operation key"
        delegation_key = payload.get("delegation_key")
        if delegation_key:
            if str(delegation_key).lower() == signer.lower():
                return False, "operation and delegation keys must be independent"
            if not delegation_signature:
                return False, "delegation key possession proof is required"
            delegation_signer = recover_typed_signer(
                payload,
                delegation_signature,
                purpose="AgentLineage/ENROLL_DELEGATION_KEY/v1",
                chain_id=chain_id,
                verifying_contract=verifying_contract,
            )
            if delegation_signer.lower() != str(delegation_key).lower():
                return False, "delegation key possession proof does not match"
        elif delegation_signature:
            return False, "unexpected delegation key possession proof"
    except Exception as exc:
        return False, f"invalid enrollment proof: {exc}"
    return True, "enrollment proof valid"


def create_delegation_credential(
    *,
    root_did: str,
    parent_did: str,
    parent_credential_hash: str,
    parent_lineage_commitment: str,
    child_did: str,
    child_operation_key: str,
    child_delegation_key: str | None,
    agent_type: AgentType,
    version_id: str,
    replica_group_id: str | None,
    permission: PermissionEnvelope,
    budget_id: str,
    reservation: BudgetLimits,
    epoch: int,
    status_ref: dict[str, Any],
    issuer_delegation_private_key: str,
    chain_id: int,
    verifying_contract: str = ZERO_ADDRESS,
    policy_version: str = "agentlineage-policy-v1",
    jti: str | None = None,
) -> DelegationCredential:
    identifier = jti or str(uuid.uuid4())
    issuer_key = Account.from_key(issuer_delegation_private_key).address
    commitment = lineage_commitment(
        parent_lineage_commitment,
        child_did=child_did,
        operation_key=child_operation_key,
        permission=permission,
        jti=identifier,
    )
    credential = DelegationCredential(
        jti=identifier,
        root_did=root_did,
        parent_did=parent_did,
        child_did=child_did,
        parent_credential_hash=parent_credential_hash,
        agent_type=agent_type,
        version_id=version_id,
        replica_group_id=replica_group_id,
        operation_key=child_operation_key,
        delegation_key=child_delegation_key,
        permission=permission,
        budget_id=budget_id,
        reservation=reservation,
        epoch=epoch,
        status_ref=status_ref,
        policy_version=policy_version,
        lineage_commitment=commitment,
        issuer_key=issuer_key,
    )
    signature = sign_typed_payload(
        issuer_delegation_private_key,
        credential.unsigned_dict(),
        purpose="AgentLineage/DELEGATION/v1",
        chain_id=chain_id,
        verifying_contract=verifying_contract,
    )
    return dataclasses.replace(credential, signature=signature)


def verify_delegation_signature(
    credential: DelegationCredential,
    expected_issuer_key: str,
    *,
    chain_id: int,
    verifying_contract: str,
) -> tuple[bool, str]:
    if credential.proof_purpose != "capabilityDelegation":
        return False, "delegation key purpose mismatch"
    if credential.issuer_key.lower() != expected_issuer_key.lower():
        return False, "delegation issuer key mismatch"
    try:
        signer = recover_typed_signer(
            credential.unsigned_dict(), credential.signature,
            purpose="AgentLineage/DELEGATION/v1", chain_id=chain_id,
            verifying_contract=verifying_contract,
        )
    except Exception as exc:
        return False, f"invalid delegation signature: {exc}"
    if signer.lower() != expected_issuer_key.lower():
        return False, "delegation signature does not match issuer key"
    return True, "delegation signature valid"
