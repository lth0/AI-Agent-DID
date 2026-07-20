from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from infrastructure.security import sha256_json
from .credentials import (
    credential_hash,
    lineage_commitment,
    verify_delegation_signature,
    verify_epoch_certificate,
)
from .crypto import address_from_did, recover_typed_signer
from .models import (
    DelegationCredential,
    EpochKeyCertificate,
    LineageInvocation,
    VerificationDecision,
)
from .policy import PolicyEngine


class StateProvider(Protocol):
    def validate_chain_state(
        self, epoch: EpochKeyCertificate, credentials: list[DelegationCredential]
    ) -> tuple[bool, str, int | None]: ...


@dataclass
class InMemoryStateProvider:
    revoked_credentials: set[str] = field(default_factory=set)
    revoked_edges: set[str] = field(default_factory=set)
    revoked_nodes: set[str] = field(default_factory=set)
    revoked_epochs: set[tuple[str, int]] = field(default_factory=set)
    block_number: int = 0

    @staticmethod
    def edge_id(parent_did: str, child_did: str) -> str:
        return sha256_json({"parent": parent_did, "child": child_did})

    def validate_chain_state(
        self, epoch: EpochKeyCertificate, credentials: list[DelegationCredential]
    ) -> tuple[bool, str, int | None]:
        if (epoch.root_did, epoch.epoch) in self.revoked_epochs:
            return False, "epoch revoked", self.block_number
        for credential in credentials:
            if credential.jti in self.revoked_credentials:
                return False, f"credential revoked: {credential.jti}", self.block_number
            if credential.child_did in self.revoked_nodes or credential.parent_did in self.revoked_nodes:
                return False, "ancestor node revoked", self.block_number
            edge = self.edge_id(credential.parent_did, credential.child_did)
            if edge in self.revoked_edges:
                return False, "delegation edge revoked", self.block_number
        return True, "chain state active", self.block_number


class LineageVerifier:
    def __init__(
        self,
        *,
        chain_id: int,
        verifying_contract: str,
        state_provider: StateProvider,
        max_request_age_seconds: int = 120,
        max_state_block_lag: int | None = None,
    ):
        self.chain_id = chain_id
        self.verifying_contract = verifying_contract
        self.state_provider = state_provider
        self.max_request_age_seconds = max_request_age_seconds
        self.max_state_block_lag = max_state_block_lag
        self.policy_engine = PolicyEngine()

    @staticmethod
    def _reject(code: str, reason: str, depth: int = 0) -> VerificationDecision:
        return VerificationDecision(False, code, reason, chain_depth=depth)

    def verify(
        self,
        epoch: EpochKeyCertificate,
        credentials: list[DelegationCredential],
        invocation: LineageInvocation,
        *,
        expected_audience: str,
        expected_body_hash: str,
        now: int | None = None,
    ) -> VerificationDecision:
        current = int(time.time()) if now is None else int(now)
        if not credentials:
            return self._reject("CHAIN_EMPTY", "delegation chain is empty")
        if len(credentials) > self.policy_engine.max_depth:
            return self._reject("CHAIN_TOO_DEEP", "delegation chain exceeds protocol maximum")
        epoch_valid, reason = verify_epoch_certificate(
            epoch, chain_id=self.chain_id, verifying_contract=self.verifying_contract, now=current
        )
        if not epoch_valid:
            return self._reject("EPOCH_INVALID", reason)

        expected_parent_did = epoch.root_did
        expected_parent_hash = credential_hash(epoch)
        expected_parent_commitment = expected_parent_hash
        expected_issuer_key = epoch.delegation_key
        parent_permission = None

        for depth, credential in enumerate(credentials, start=1):
            if credential.root_did != epoch.root_did or credential.epoch != epoch.epoch:
                return self._reject("ROOT_OR_EPOCH_MISMATCH", "credential root or epoch mismatch", depth)
            if credential.parent_did != expected_parent_did:
                return self._reject("PARENT_MISMATCH", "credential parent DID mismatch", depth)
            if credential.parent_credential_hash != expected_parent_hash:
                return self._reject("PARENT_HASH_MISMATCH", "parent credential hash mismatch", depth)
            valid, reason = verify_delegation_signature(
                credential, expected_issuer_key,
                chain_id=self.chain_id, verifying_contract=self.verifying_contract,
            )
            if not valid:
                return self._reject("DELEGATION_SIGNATURE_INVALID", reason, depth)
            expected_commitment = lineage_commitment(
                expected_parent_commitment,
                child_did=credential.child_did,
                operation_key=credential.operation_key,
                permission=credential.permission,
                jti=credential.jti,
            )
            if credential.lineage_commitment != expected_commitment:
                return self._reject("LINEAGE_COMMITMENT_MISMATCH", "lineage commitment mismatch", depth)
            if address_from_did(credential.child_did).lower() != credential.operation_key.lower():
                return self._reject("OPERATION_KEY_MISMATCH", "child DID is not bound to operation key", depth)
            if credential.version_id not in credential.permission.versions and credential.permission.versions != ("*",):
                return self._reject("VERSION_NOT_ALLOWED", "credential version is outside permission", depth)
            policy_valid, reason = self.policy_engine.validate_identity_policy(
                credential.permission, credential.agent_type, credential.replica_group_id
            )
            if not policy_valid:
                return self._reject("IDENTITY_POLICY_INVALID", reason, depth)
            if parent_permission is not None:
                attenuated, reason = self.policy_engine.is_attenuation(
                    credential.permission, parent_permission,
                    credential.agent_type, credential.replica_group_id,
                )
                if not attenuated:
                    return self._reject("POLICY_ESCALATION", reason, depth)
            if credential.permission.delegable != bool(credential.delegation_key):
                return self._reject(
                    "KEY_PURPOSE_MISMATCH",
                    "delegation key presence must match delegable permission",
                    depth,
                )
            expected_parent_did = credential.child_did
            expected_parent_hash = credential_hash(credential)
            expected_parent_commitment = credential.lineage_commitment
            expected_issuer_key = credential.delegation_key or ""
            parent_permission = credential.permission

        try:
            state_valid, reason, block_number = self.state_provider.validate_chain_state(epoch, credentials)
        except Exception as exc:
            return self._reject("STATE_UNAVAILABLE", f"chain state lookup failed: {exc}", len(credentials))
        if not state_valid:
            return self._reject("STATUS_REVOKED", reason, len(credentials))
        if self.max_state_block_lag is not None:
            if block_number is None:
                return self._reject("STATE_UNAVAILABLE", "chain state block is unavailable", len(credentials))
            try:
                latest_block = int(self.state_provider.latest_block_number())
            except Exception as exc:
                return self._reject("STATE_UNAVAILABLE", f"latest block lookup failed: {exc}", len(credentials))
            if latest_block - int(block_number) > self.max_state_block_lag:
                return self._reject("STATE_STALE", "chain state exceeds allowed confirmation window", len(credentials))

        leaf = credentials[-1]
        if invocation.leaf_did != leaf.child_did or invocation.credential_jti != leaf.jti:
            return self._reject("LEAF_BINDING_MISMATCH", "request is not bound to leaf credential", len(credentials))
        if invocation.origin_did != leaf.child_did:
            return self._reject("ORIGIN_MISMATCH", "request origin must be the leaf DID", len(credentials))
        if invocation.on_behalf_of != epoch.root_did:
            return self._reject("ON_BEHALF_OF_MISMATCH", "request principal must be the root DID", len(credentials))
        if invocation.version_id != leaf.version_id:
            return self._reject("VERSION_MISMATCH", "request version differs from leaf version", len(credentials))
        if invocation.budget_id != leaf.budget_id:
            return self._reject("BUDGET_BINDING_MISMATCH", "request budget differs from credential", len(credentials))
        if invocation.audience != expected_audience:
            return self._reject("AUDIENCE_MISMATCH", "request audience mismatch", len(credentials))
        if invocation.body_hash != expected_body_hash:
            return self._reject("BODY_HASH_MISMATCH", "request body hash mismatch", len(credentials))
        if not invocation.challenge or invocation.sequence < 0:
            return self._reject("REPLAY_BINDING_INVALID", "challenge and sequence are required", len(credentials))
        if abs(current - invocation.timestamp) > self.max_request_age_seconds:
            return self._reject("REQUEST_STALE", "request timestamp is stale", len(credentials))
        if invocation.cost_units < 0 or invocation.lease_seconds <= 0:
            return self._reject("BUDGET_REQUEST_INVALID", "cost and lease values are invalid", len(credentials))
        if not leaf.permission.allows(
            action=invocation.action, resource=invocation.resource, task=invocation.task_id,
            audience=invocation.audience, version=invocation.version_id, now=current,
        ):
            return self._reject("PERMISSION_DENIED", "request is outside leaf permission", len(credentials))
        try:
            signer = recover_typed_signer(
                invocation.unsigned_dict(), invocation.signature,
                purpose="AgentLineage/REQUEST/v1", chain_id=self.chain_id,
                verifying_contract=self.verifying_contract,
            )
        except Exception as exc:
            return self._reject("REQUEST_SIGNATURE_INVALID", str(exc), len(credentials))
        if signer.lower() != leaf.operation_key.lower():
            return self._reject("REQUEST_SIGNATURE_INVALID", "request not signed by leaf operation key", len(credentials))
        return VerificationDecision(
            True,
            "ACCEPTED",
            "lineage and permission verified",
            chain_depth=len(credentials),
            effective_permission=leaf.permission.to_dict(),
            budget_tx_hash=None,
        )
