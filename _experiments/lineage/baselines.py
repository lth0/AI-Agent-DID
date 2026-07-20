from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable

import requests

from infrastructure.lineage.credentials import (
    credential_hash,
    verify_delegation_signature,
    verify_epoch_certificate,
)
from infrastructure.lineage.crypto import recover_typed_signer
from infrastructure.lineage.models import (
    DelegationCredential,
    EpochKeyCertificate,
    LineageInvocation,
)
from infrastructure.lineage.service import LineageGateway
from infrastructure.lineage.verifier import LineageVerifier
from infrastructure.security import sha256_json


@dataclass(frozen=True)
class AuthorizationCase:
    name: str
    epoch: EpochKeyCertificate
    chain: tuple[DelegationCredential, ...]
    invocation: LineageInvocation
    body: Any
    expected_authorized: bool
    shared_root_authenticated: bool = True


@dataclass(frozen=True)
class AdapterDecision:
    accepted: bool
    code: str
    latency_ms: float


class BaselineAdapter:
    name = "baseline"

    def evaluate(self, case: AuthorizationCase) -> AdapterDecision:
        started = time.perf_counter()
        try:
            accepted, code = self._evaluate(case)
        except Exception as exc:
            accepted, code = False, f"ERROR_{type(exc).__name__.upper()}"
        return AdapterDecision(accepted, code, (time.perf_counter() - started) * 1000)

    def _evaluate(self, case: AuthorizationCase) -> tuple[bool, str]:
        raise NotImplementedError


class SharedRootAdapter(BaselineAdapter):
    name = "Shared-Root"

    def _evaluate(self, case: AuthorizationCase) -> tuple[bool, str]:
        return case.shared_root_authenticated, "SHARED_ROOT_AUTH"


class IndependentDidAclAdapter(BaselineAdapter):
    name = "Independent-DID+ACL"

    def __init__(self, acl: dict[str, set[tuple[str, str]]], *, chain_id: int, contract: str):
        self.acl = acl
        self.chain_id = chain_id
        self.contract = contract

    def _evaluate(self, case: AuthorizationCase) -> tuple[bool, str]:
        leaf = case.chain[-1]
        signer = recover_typed_signer(
            case.invocation.unsigned_dict(), case.invocation.signature,
            purpose="AgentLineage/REQUEST/v1", chain_id=self.chain_id,
            verifying_contract=self.contract,
        )
        allowed = (case.invocation.action, case.invocation.resource) in self.acl.get(
            leaf.child_did, set()
        )
        accepted = signer.lower() == leaf.operation_key.lower() and allowed
        return accepted, "ACL_ALLOW" if accepted else "ACL_DENY"


class OriginalAgentDidAdapter(BaselineAdapter):
    name = "Original-AgentDID"

    def __init__(self, *, chain_id: int, contract: str):
        self.chain_id = chain_id
        self.contract = contract

    def _evaluate(self, case: AuthorizationCase) -> tuple[bool, str]:
        signer = recover_typed_signer(
            case.invocation.unsigned_dict(), case.invocation.signature,
            purpose="AgentLineage/REQUEST/v1", chain_id=self.chain_id,
            verifying_contract=self.contract,
        )
        accepted = signer.lower() == case.chain[-1].operation_key.lower()
        return accepted, "IDENTITY_VALID" if accepted else "IDENTITY_INVALID"


class PlainDelegationAdapter(BaselineAdapter):
    name = "Plain-Delegation"

    def __init__(self, *, chain_id: int, contract: str):
        self.chain_id = chain_id
        self.contract = contract

    def _evaluate(self, case: AuthorizationCase) -> tuple[bool, str]:
        now = int(time.time())
        valid, _ = verify_epoch_certificate(
            case.epoch, chain_id=self.chain_id, verifying_contract=self.contract, now=now
        )
        if not valid:
            return False, "EPOCH_INVALID"
        expected_parent = case.epoch.root_did
        expected_hash = credential_hash(case.epoch)
        issuer = case.epoch.delegation_key
        for credential in case.chain:
            if credential.parent_did != expected_parent or credential.parent_credential_hash != expected_hash:
                return False, "CHAIN_INVALID"
            valid, _ = verify_delegation_signature(
                credential, issuer, chain_id=self.chain_id, verifying_contract=self.contract
            )
            if not valid:
                return False, "CHAIN_SIGNATURE_INVALID"
            expected_parent = credential.child_did
            expected_hash = credential_hash(credential)
            issuer = credential.delegation_key or ""
        signer = recover_typed_signer(
            case.invocation.unsigned_dict(), case.invocation.signature,
            purpose="AgentLineage/REQUEST/v1", chain_id=self.chain_id,
            verifying_contract=self.contract,
        )
        accepted = signer.lower() == case.chain[-1].operation_key.lower()
        return accepted, "PLAIN_DELEGATION_ALLOW" if accepted else "REQUEST_SIGNATURE_INVALID"


class OpenFgaOverlayAdapter(BaselineAdapter):
    name = "OpenFGA-Overlay"

    def __init__(
        self,
        checker: Callable[[str, str, str], bool] | None = None,
        *,
        endpoint: str | None = None,
        store_id: str | None = None,
        model_id: str | None = None,
    ):
        self.checker = checker
        self.endpoint = endpoint
        self.store_id = store_id
        self.model_id = model_id

    def _evaluate(self, case: AuthorizationCase) -> tuple[bool, str]:
        user = f"agent:{case.invocation.leaf_did}"
        relation = case.invocation.action
        obj = f"resource:{case.invocation.resource}"
        if self.checker:
            accepted = bool(self.checker(user, relation, obj))
        elif self.endpoint and self.store_id:
            response = requests.post(
                f"{self.endpoint.rstrip('/')}/stores/{self.store_id}/check",
                json={
                    "authorization_model_id": self.model_id,
                    "tuple_key": {"user": user, "relation": relation, "object": obj},
                },
                timeout=10,
            )
            response.raise_for_status()
            accepted = bool(response.json().get("allowed"))
        else:
            return False, "OPENFGA_UNAVAILABLE"
        return accepted, "OPENFGA_ALLOW" if accepted else "OPENFGA_DENY"


class LineageNoBudgetAdapter(BaselineAdapter):
    name = "Lineage-no-budget"

    def __init__(self, verifier: LineageVerifier, *, audience: str):
        self.verifier = verifier
        self.audience = audience

    def _evaluate(self, case: AuthorizationCase) -> tuple[bool, str]:
        decision = self.verifier.verify(
            case.epoch, list(case.chain), case.invocation,
            expected_audience=self.audience,
            expected_body_hash=sha256_json(case.body),
        )
        return decision.accepted, decision.code


class FullLineageAdapter(BaselineAdapter):
    name = "Lineage"

    def __init__(self, gateway: LineageGateway):
        self.gateway = gateway

    def _evaluate(self, case: AuthorizationCase) -> tuple[bool, str]:
        result = self.gateway.invoke({
            "epoch_certificate": case.epoch.to_dict(),
            "delegation_chain": [item.to_dict() for item in case.chain],
            "invocation": case.invocation.to_dict(),
            "body": case.body,
        })
        decision = result["decision"]
        return bool(decision["accepted"]), str(decision["code"])
