from __future__ import annotations

import time
from typing import Any

from .models import AgentType, PermissionEnvelope


class PolicyViolation(ValueError):
    pass


TYPE_MAX_TTL = {
    AgentType.PERSISTENT: 30 * 24 * 60 * 60,
    AgentType.SESSION: 60 * 60,
    AgentType.INSTANCE: 24 * 60 * 60,
    AgentType.CHILD: 7 * 24 * 60 * 60,
}

PERMISSION_FIELDS = {
    "actions", "resources", "tasks", "audiences", "versions",
    "not_before", "expires_at", "remaining_depth", "delegable",
}


def _is_subset(child: tuple[str, ...], parent: tuple[str, ...]) -> bool:
    if parent == ("*",):
        return True
    if child == ("*",):
        return parent == ("*",)
    return set(child).issubset(parent)


def _intersection(parent: tuple[str, ...], requested: Any, field: str) -> tuple[str, ...]:
    if requested is None:
        return parent
    requested_values = PermissionEnvelope.from_dict({
        "actions": requested if field == "actions" else ["placeholder"],
        "resources": requested if field == "resources" else ["placeholder"],
        "tasks": requested if field == "tasks" else ["placeholder"],
        "audiences": requested if field == "audiences" else ["placeholder"],
        "versions": requested if field == "versions" else ["placeholder"],
        "not_before": 0, "expires_at": 1, "remaining_depth": 0, "delegable": False,
    })
    values = getattr(requested_values, field)
    if parent == ("*",):
        return values
    if values == ("*",):
        raise PolicyViolation(f"{field} wildcard exceeds finite parent permission")
    result = tuple(sorted(set(parent).intersection(values)))
    if not result:
        raise PolicyViolation(f"{field} intersection is empty")
    return result


class PolicyEngine:
    def __init__(self, *, max_depth: int = 8):
        self.max_depth = max_depth

    def attenuate(
        self,
        parent: PermissionEnvelope,
        requested: dict[str, Any],
        agent_type: AgentType,
        *,
        replica_group_id: str | None = None,
        now: int | None = None,
    ) -> PermissionEnvelope:
        current = int(time.time()) if now is None else int(now)
        unknown_fields = set(requested).difference(PERMISSION_FIELDS)
        if unknown_fields:
            raise PolicyViolation(
                f"unsupported permission fields: {', '.join(sorted(unknown_fields))}"
            )
        for field in ("not_before", "expires_at", "remaining_depth"):
            if field in requested:
                value = requested[field]
                if isinstance(value, bool) or not isinstance(value, int):
                    raise PolicyViolation(f"{field} must be an integer")
        if "delegable" in requested and not isinstance(requested["delegable"], bool):
            raise PolicyViolation("delegable must be a boolean")
        if not parent.delegable or parent.remaining_depth < 1:
            raise PolicyViolation("parent is not allowed to delegate")
        if agent_type is AgentType.INSTANCE and not replica_group_id:
            raise PolicyViolation("instance identity requires replica_group_id")

        not_before = max(parent.not_before, requested.get("not_before", current))
        ttl_cap = TYPE_MAX_TTL[agent_type]
        expires_at = min(
            parent.expires_at,
            requested.get("expires_at", min(parent.expires_at, not_before + ttl_cap)),
            not_before + ttl_cap,
        )
        requested_depth = requested.get("remaining_depth", parent.remaining_depth - 1)
        remaining_depth = min(requested_depth, parent.remaining_depth - 1, self.max_depth)
        type_can_delegate = agent_type not in {AgentType.SESSION, AgentType.INSTANCE}
        delegable = requested.get("delegable", False) and type_can_delegate and remaining_depth > 0

        child = PermissionEnvelope(
            actions=_intersection(parent.actions, requested.get("actions"), "actions"),
            resources=_intersection(parent.resources, requested.get("resources"), "resources"),
            tasks=_intersection(parent.tasks, requested.get("tasks"), "tasks"),
            audiences=_intersection(parent.audiences, requested.get("audiences"), "audiences"),
            versions=_intersection(parent.versions, requested.get("versions"), "versions"),
            not_before=not_before,
            expires_at=expires_at,
            remaining_depth=remaining_depth,
            delegable=delegable,
        )
        valid, reason = self.is_attenuation(child, parent, agent_type, replica_group_id)
        if not valid:
            raise PolicyViolation(reason)
        return child

    def validate_identity_policy(
        self,
        permission: PermissionEnvelope,
        agent_type: AgentType,
        replica_group_id: str | None = None,
    ) -> tuple[bool, str]:
        if permission.remaining_depth > self.max_depth:
            return False, "delegation depth exceeds protocol maximum"
        if permission.expires_at - permission.not_before > TYPE_MAX_TTL[agent_type]:
            return False, "identity TTL exceeds type maximum"
        if agent_type in {AgentType.SESSION, AgentType.INSTANCE} and permission.delegable:
            return False, f"{agent_type.value} identity cannot delegate"
        if agent_type is AgentType.INSTANCE and not replica_group_id:
            return False, "instance identity requires replica group"
        if agent_type is not AgentType.INSTANCE and replica_group_id:
            return False, "replica group is only valid for instance identities"
        return True, "identity policy is valid"

    def is_attenuation(
        self,
        child: PermissionEnvelope,
        parent: PermissionEnvelope,
        agent_type: AgentType,
        replica_group_id: str | None = None,
    ) -> tuple[bool, str]:
        for field in ("actions", "resources", "tasks", "audiences", "versions"):
            if not _is_subset(getattr(child, field), getattr(parent, field)):
                return False, f"{field} exceeds parent permission"
        if child.not_before < parent.not_before or child.expires_at > parent.expires_at:
            return False, "validity interval exceeds parent"
        valid, reason = self.validate_identity_policy(child, agent_type, replica_group_id)
        if not valid:
            return False, reason
        if child.remaining_depth > parent.remaining_depth - 1:
            return False, "delegation depth did not decrease"
        if child.delegable and not parent.delegable:
            return False, "delegable flag exceeds parent"
        return True, "permission is attenuated"
