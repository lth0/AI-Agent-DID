from __future__ import annotations

import dataclasses
import enum
import hashlib
import re
from typing import Any


VERSION_PREFIX = "urn:agentlineage:version:sha256:"
REPLICA_PREFIX = "urn:agentlineage:replica:sha256:"
_HEX_256 = re.compile(r"^[0-9a-f]{64}$")


def version_did(content: bytes | str) -> str:
    payload = content if isinstance(content, bytes) else content.encode("utf-8")
    return VERSION_PREFIX + hashlib.sha256(payload).hexdigest()


def replica_group_id(value: bytes | str) -> str:
    payload = value if isinstance(value, bytes) else value.encode("utf-8")
    return REPLICA_PREFIX + hashlib.sha256(payload).hexdigest()


def is_version_did(value: str) -> bool:
    return value.startswith(VERSION_PREFIX) and bool(_HEX_256.fullmatch(value[len(VERSION_PREFIX):]))


def is_replica_group_id(value: str) -> bool:
    return value.startswith(REPLICA_PREFIX) and bool(_HEX_256.fullmatch(value[len(REPLICA_PREFIX):]))


class AgentType(str, enum.Enum):
    PERSISTENT = "persistent"
    SESSION = "session"
    INSTANCE = "instance"
    CHILD = "child"


def _normalized_set(value: Any, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple, set)):
        raise ValueError(f"{field_name} must be a list of strings")
    if any(not isinstance(item, str) for item in value):
        raise ValueError(f"{field_name} must contain only strings")
    items = tuple(sorted({item.strip() for item in value if item.strip()}))
    if not items:
        raise ValueError(f"{field_name} must not be empty")
    if "*" in items and items != ("*",):
        raise ValueError(f"{field_name} cannot combine '*' with other values")
    return items


@dataclasses.dataclass(frozen=True)
class BudgetLimits:
    calls: int
    cost_units: int
    concurrency: int

    def __post_init__(self) -> None:
        for name in ("calls", "cost_units", "concurrency"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")

    def to_dict(self) -> dict[str, int]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "BudgetLimits":
        return cls(
            calls=value.get("calls", 0),
            cost_units=value.get("cost_units", 0),
            concurrency=value.get("concurrency", 0),
        )


@dataclasses.dataclass(frozen=True)
class PermissionEnvelope:
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    tasks: tuple[str, ...]
    audiences: tuple[str, ...]
    versions: tuple[str, ...]
    not_before: int
    expires_at: int
    remaining_depth: int
    delegable: bool

    def __post_init__(self) -> None:
        for name in ("actions", "resources", "tasks", "audiences", "versions"):
            object.__setattr__(self, name, _normalized_set(getattr(self, name), name))
        for name in ("not_before", "expires_at", "remaining_depth"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an integer")
        if not isinstance(self.delegable, bool):
            raise ValueError("delegable must be a boolean")
        if self.not_before < 0 or self.expires_at <= self.not_before:
            raise ValueError("permission validity interval is invalid")
        if self.remaining_depth < 0:
            raise ValueError("remaining_depth must be non-negative")
        if self.delegable and self.remaining_depth == 0:
            raise ValueError("delegable permission requires remaining_depth > 0")

    def to_dict(self) -> dict[str, Any]:
        return {
            "actions": list(self.actions),
            "resources": list(self.resources),
            "tasks": list(self.tasks),
            "audiences": list(self.audiences),
            "versions": list(self.versions),
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "remaining_depth": self.remaining_depth,
            "delegable": self.delegable,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "PermissionEnvelope":
        return cls(
            actions=value["actions"],
            resources=value["resources"],
            tasks=value["tasks"],
            audiences=value["audiences"],
            versions=value["versions"],
            not_before=value["not_before"],
            expires_at=value["expires_at"],
            remaining_depth=value["remaining_depth"],
            delegable=value["delegable"],
        )

    @staticmethod
    def _contains(values: tuple[str, ...], item: str) -> bool:
        return values == ("*",) or item in values

    def allows(
        self, *, action: str, resource: str, task: str, audience: str, version: str, now: int
    ) -> bool:
        return (
            self.not_before <= now <= self.expires_at
            and self._contains(self.actions, action)
            and self._contains(self.resources, resource)
            and self._contains(self.tasks, task)
            and self._contains(self.audiences, audience)
            and self._contains(self.versions, version)
        )


@dataclasses.dataclass(frozen=True)
class EpochKeyCertificate:
    root_did: str
    epoch: int
    purpose: str
    delegation_key: str
    not_before: int
    expires_at: int
    status_ref: dict[str, Any]
    signature: str = ""

    def unsigned_dict(self) -> dict[str, Any]:
        value = dataclasses.asdict(self)
        value.pop("signature", None)
        value["schema"] = "agentlineage-epoch-v1"
        return value

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "EpochKeyCertificate":
        return cls(**{key: value[key] for key in cls.__dataclass_fields__})


@dataclasses.dataclass(frozen=True)
class DelegationCredential:
    jti: str
    root_did: str
    parent_did: str
    child_did: str
    parent_credential_hash: str
    agent_type: AgentType
    version_id: str
    replica_group_id: str | None
    operation_key: str
    delegation_key: str | None
    permission: PermissionEnvelope
    budget_id: str
    reservation: BudgetLimits
    epoch: int
    status_ref: dict[str, Any]
    policy_version: str
    lineage_commitment: str
    issuer_key: str
    proof_purpose: str = "capabilityDelegation"
    signature: str = ""

    def __post_init__(self) -> None:
        if not self.jti:
            raise ValueError("credential jti is required")
        if not is_version_did(self.version_id):
            raise ValueError("version_id must be a sha256 AgentLineage VersionDID")
        if self.replica_group_id and not is_replica_group_id(self.replica_group_id):
            raise ValueError("replica_group_id must be a sha256 AgentLineage replica identifier")
        if self.delegation_key and self.delegation_key.lower() == self.operation_key.lower():
            raise ValueError("operation and delegation keys must be independent")

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": "agentlineage-dc-v1",
            "jti": self.jti,
            "root_did": self.root_did,
            "parent_did": self.parent_did,
            "child_did": self.child_did,
            "parent_credential_hash": self.parent_credential_hash,
            "agent_type": self.agent_type.value,
            "version_id": self.version_id,
            "replica_group_id": self.replica_group_id,
            "operation_key": self.operation_key,
            "delegation_key": self.delegation_key,
            "permission": self.permission.to_dict(),
            "budget_id": self.budget_id,
            "reservation": self.reservation.to_dict(),
            "epoch": self.epoch,
            "status_ref": self.status_ref,
            "policy_version": self.policy_version,
            "lineage_commitment": self.lineage_commitment,
            "issuer_key": self.issuer_key,
            "proof_purpose": self.proof_purpose,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "DelegationCredential":
        return cls(
            jti=value["jti"], root_did=value["root_did"], parent_did=value["parent_did"],
            child_did=value["child_did"], parent_credential_hash=value["parent_credential_hash"],
            agent_type=AgentType(value["agent_type"]), version_id=value["version_id"],
            replica_group_id=value.get("replica_group_id"), operation_key=value["operation_key"],
            delegation_key=value.get("delegation_key"), permission=PermissionEnvelope.from_dict(value["permission"]),
            budget_id=value["budget_id"], reservation=BudgetLimits.from_dict(value["reservation"]),
            epoch=int(value["epoch"]), status_ref=dict(value["status_ref"]),
            policy_version=value["policy_version"], lineage_commitment=value["lineage_commitment"],
            issuer_key=value["issuer_key"], proof_purpose=value.get("proof_purpose", "capabilityDelegation"),
            signature=value.get("signature", ""),
        )


@dataclasses.dataclass(frozen=True)
class LineageInvocation:
    leaf_did: str
    credential_jti: str
    origin_did: str
    on_behalf_of: str
    audience: str
    task_id: str
    action: str
    resource: str
    version_id: str
    body_hash: str
    challenge: str
    sequence: int
    timestamp: int
    budget_id: str
    cost_units: int
    lease_seconds: int
    signature: str = ""

    def __post_init__(self) -> None:
        if not is_version_did(self.version_id):
            raise ValueError("version_id must be a sha256 AgentLineage VersionDID")
        for name in ("sequence", "timestamp", "cost_units", "lease_seconds"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an integer")
        if self.sequence < 0:
            raise ValueError("sequence must be non-negative")
        if self.cost_units < 0 or self.lease_seconds <= 0:
            raise ValueError("invocation budget values are invalid")

    def unsigned_dict(self) -> dict[str, Any]:
        value = dataclasses.asdict(self)
        value.pop("signature", None)
        value["schema"] = "agentlineage-request-v1"
        return value

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "LineageInvocation":
        return cls(**{key: value[key] for key in cls.__dataclass_fields__})


@dataclasses.dataclass(frozen=True)
class VerificationDecision:
    accepted: bool
    code: str
    reason: str
    chain_depth: int = 0
    effective_permission: dict[str, Any] | None = None
    budget_tx_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)
