from __future__ import annotations

import copy
import hashlib
import json
import time
import uuid
from typing import Any

from eth_account import Account

from infrastructure.agentdid_protocol import did_from_address, sign_json
from infrastructure.security import canonical_json, sha256_json

from .cases import CASE_BY_ID


SCENARIO_SCHEMA = "agentdid-lineage-control-scenario-v1"
DELEGATION_SCHEMA = "agentdid-lineage-control-delegation-v1"
REGISTRY_SCHEMA = "agentdid-lineage-control-registry-v1"
SEMANTICS_SCHEMA = "agentdid-attack-semantics-v1"

REQUEST_BODY: dict[str, Any] = {
    "operation": "integer-addition",
    "left": 17,
    "right": 25,
}


def _version_id(label: str) -> str:
    return "urn:agentlineage:version:sha256:" + hashlib.sha256(
        label.encode("utf-8")
    ).hexdigest()


VERSION_ID = _version_id("agentdid-comparison-v1")
OTHER_VERSION_ID = _version_id("agentdid-comparison-unauthorized")


_LINEAGE_ATTACK_SEMANTICS: dict[str, dict[str, Any]] = {
    "L01": {
        "family": "lineage",
        "mutation": "leaf_action_escalation",
        "target": "invocation.action",
        "baseline_value": "read",
        "mutated_value": "write",
        "constraint": "invocation_action_must_be_within_leaf_permission",
        "changed_paths": ["invocation.action"],
    },
    "L02": {
        "family": "lineage",
        "mutation": "leaf_resource_escalation",
        "target": "invocation.resource",
        "baseline_value": "urn:tool:a",
        "mutated_value": "urn:tool:b",
        "constraint": "invocation_resource_must_be_within_leaf_permission",
        "changed_paths": ["invocation.resource"],
    },
    "L03": {
        "family": "lineage",
        "mutation": "delegation_scope_escalation",
        "target": "delegation.presented_chain.leaf.permission.actions",
        "baseline_value": ["read"],
        "mutated_value": ["delete", "read"],
        "constraint": "child_permission_must_be_subset_of_parent_permission",
        "changed_paths": [
            "delegation.presented_chain[1].permission.actions",
            "invocation.action",
        ],
    },
    "L04": {
        "family": "lineage",
        "mutation": "validity_extension",
        "target": "delegation.presented_chain.leaf.permission.expires_at",
        "baseline_value": "before_parent_expiry",
        "mutated_value": "after_parent_expiry",
        "constraint": "child_validity_must_not_exceed_parent_validity",
        "changed_paths": [
            "delegation.presented_chain[1].permission.expires_at"
        ],
    },
    "L05": {
        "family": "lineage",
        "mutation": "depth_reset",
        "target": "delegation.presented_chain.leaf.permission.remaining_depth",
        "baseline_value": 0,
        "mutated_value": "equal_to_parent_remaining_depth",
        "constraint": "child_remaining_depth_must_strictly_decrease",
        "changed_paths": [
            "delegation.presented_chain[1].permission.remaining_depth"
        ],
    },
    "L06": {
        "family": "lineage",
        "mutation": "forbidden_session_delegation",
        "target": "delegation.presented_chain.leaf.permission.delegable",
        "baseline_value": False,
        "mutated_value": True,
        "constraint": "session_identity_must_not_be_delegable",
        "changed_paths": [
            "delegation.presented_chain[1].permission.delegable",
            "delegation.presented_chain[1].permission.remaining_depth",
            "delegation.presented_chain[1].delegation_key",
        ],
    },
    "L07": {
        "family": "lineage",
        "mutation": "operation_key_signed_delegation",
        "target": "delegation.presented_chain.leaf.proof.verification_method",
        "baseline_value": "parent_delegation_key",
        "mutated_value": "parent_operation_key",
        "constraint": "delegation_must_be_signed_by_authorized_delegation_key",
        "changed_paths": [
            "delegation.presented_chain[1].issuer_key",
            "delegation.presented_chain[1].issuer_key_purpose",
            "delegation.presented_chain[1].proof",
        ],
    },
    "L08": {
        "family": "lineage",
        "mutation": "sibling_credential_impersonation",
        "target": "invocation.leaf_did",
        "baseline_value": "credential_subject_leaf_did",
        "mutated_value": "sibling_leaf_did",
        "constraint": "invocation_signer_and_leaf_must_match_credential_subject",
        "changed_paths": [
            "invocation.leaf_did",
            "invocation.origin_did",
            "leaf_did",
            "leaf_operation_address",
        ],
    },
    "L09": {
        "family": "lineage",
        "mutation": "branch_splice",
        "target": "delegation.presented_chain.parent_child_link",
        "baseline_value": "continuous_registered_branch",
        "mutated_value": "parent_from_branch_one_leaf_from_branch_two",
        "constraint": "presented_delegation_chain_must_be_continuous",
        "changed_paths": [
            "delegation.registered_chains",
            "delegation.presented_chain",
            "invocation.leaf_did",
            "invocation.credential_jti",
        ],
    },
    "L10": {
        "family": "lineage",
        "mutation": "cross_task_replay",
        "target": "invocation.task_id",
        "baseline_value": "task-1",
        "mutated_value": "task-2",
        "constraint": "invocation_task_must_be_within_leaf_permission",
        "changed_paths": ["invocation.task_id"],
    },
    "L11": {
        "family": "lineage",
        "mutation": "cross_audience_replay",
        "target": "invocation.audience",
        "baseline_value": "expected_audience",
        "mutated_value": "different_audience",
        "constraint": "invocation_audience_must_be_within_leaf_permission",
        "changed_paths": ["invocation.audience"],
    },
    "L12": {
        "family": "lineage",
        "mutation": "ancestor_revocation",
        "target": "registry_state.nodes.parent.revoked",
        "baseline_value": False,
        "mutated_value": True,
        "constraint": "active_descendant_must_not_bypass_ancestor_revocation",
        "changed_paths": [
            "registry_state.nodes[parent_did].active",
            "registry_state.nodes[parent_did].revoked",
            "registry_state.revocations.nodes",
        ],
    },
    "L13": {
        "family": "lineage",
        "mutation": "confused_deputy",
        "target": "invocation.origin_did",
        "baseline_value": "leaf_did",
        "mutated_value": "parent_did",
        "constraint": "declared_origin_must_match_authenticated_request_origin",
        "changed_paths": ["invocation.origin_did"],
    },
    "L14": {
        "family": "lineage",
        "mutation": "version_substitution",
        "target": "invocation.version_id",
        "baseline_value": "delegated_version",
        "mutated_value": "unauthorized_version",
        "constraint": "invocation_version_must_be_within_leaf_permission",
        "changed_paths": ["invocation.version_id"],
    },
}


def _stable_uuid(experiment_id: str, role: str) -> str:
    value = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"urn:agentdid:comparison:{experiment_id}:{role}",
    )
    return f"urn:uuid:{value}"


def _bytes32_id(experiment_id: str, role: str) -> str:
    return "0x" + hashlib.sha256(
        f"{experiment_id}:{role}".encode("utf-8")
    ).hexdigest()


def _epoch_for(experiment_id: str) -> int:
    digest = hashlib.sha256(
        f"{experiment_id}:control-epoch".encode("utf-8")
    ).digest()
    return (int.from_bytes(digest[:4], "big") % 2_147_483_646) + 1


def _normalized_semantics(case_id: str) -> dict[str, Any]:
    if case_id in _LINEAGE_ATTACK_SEMANTICS:
        details = _LINEAGE_ATTACK_SEMANTICS[case_id]
    else:
        details = {
            "family": "control",
            "mutation": "legitimate",
            "target": "none",
            "baseline_value": "legitimate",
            "mutated_value": "legitimate",
            "constraint": "no_lineage_attack_injected",
            "changed_paths": [],
        }
    value = {
        "schema": SEMANTICS_SCHEMA,
        "case_id": case_id,
        **details,
    }
    # A canonical JSON round trip removes tuple/order accidents from the
    # semantics object before its stable hash is calculated.
    return json.loads(canonical_json(value))


def _permission(
    *,
    actions: list[str],
    resources: list[str],
    tasks: list[str],
    audiences: list[str],
    versions: list[str],
    not_before: int,
    expires_at: int,
    remaining_depth: int,
    delegable: bool,
) -> dict[str, Any]:
    return {
        "actions": sorted(set(actions)),
        "resources": sorted(set(resources)),
        "tasks": sorted(set(tasks)),
        "audiences": sorted(set(audiences)),
        "versions": sorted(set(versions)),
        "not_before": int(not_before),
        "expires_at": int(expires_at),
        "remaining_depth": int(remaining_depth),
        "delegable": bool(delegable),
    }


def _signed_delegation(
    *,
    credential_jti: str,
    branch_id: str,
    root_did: str,
    parent_did: str,
    child_did: str,
    parent_credential_jti: str,
    parent_credential_hash: str,
    operation_key: str,
    delegation_key: str | None,
    agent_type: str,
    version_id: str,
    permission: dict[str, Any],
    budget_id: str,
    epoch: int,
    issuer_did: str,
    issuer_key_purpose: str,
    issuer_account: Any,
) -> dict[str, Any]:
    body = {
        "schema": "agentdid-lineage-control-credential-v1",
        "credential_jti": credential_jti,
        "branch_id": branch_id,
        "root_did": root_did,
        "parent_did": parent_did,
        "child_did": child_did,
        "parent_credential_jti": parent_credential_jti,
        "parent_credential_hash": parent_credential_hash,
        "operation_key": operation_key,
        "delegation_key": delegation_key,
        "agent_type": agent_type,
        "version_id": version_id,
        "permission": copy.deepcopy(permission),
        "budget_id": budget_id,
        "epoch": int(epoch),
        "issuer_did": issuer_did,
        "issuer_key": issuer_account.address,
        "issuer_key_purpose": issuer_key_purpose,
    }
    proof_options = {
        "type": "EcdsaSecp256k1RecoverySignature2020",
        "proof_purpose": "capabilityDelegation",
        "verification_method": f"{issuer_did}#{issuer_key_purpose}",
        "canonicalization": "JCS",
    }
    signed_body = {**body, "proof_options": proof_options}
    return {
        **body,
        "proof": {
            **proof_options,
            "jws": sign_json(signed_body, issuer_account.key.hex()),
        },
    }


def _registry_record(credential: dict[str, Any]) -> dict[str, Any]:
    return {
        "credential_hash": sha256_json(credential),
        "parent_did": credential["parent_did"],
        "child_did": credential["child_did"],
        "active": True,
        "revoked": False,
    }


def _add_registered_chain(
    registry_state: dict[str, Any],
    parent: dict[str, Any],
    leaf: dict[str, Any],
) -> None:
    registry_state["nodes"][parent["child_did"]] = {
        "active": True,
        "revoked": False,
        "agent_type": parent["agent_type"],
        "credential_jti": parent["credential_jti"],
    }
    registry_state["nodes"][leaf["child_did"]] = {
        "active": True,
        "revoked": False,
        "agent_type": leaf["agent_type"],
        "credential_jti": leaf["credential_jti"],
    }
    registry_state["credentials"][parent["credential_jti"]] = _registry_record(parent)
    registry_state["credentials"][leaf["credential_jti"]] = _registry_record(leaf)


def _replace_presented_leaf(
    delegation: dict[str, Any],
    leaf: dict[str, Any],
) -> None:
    delegation["presented_chain"][1] = leaf


def _validate_inputs(
    case_id: str,
    experiment_id: str,
    chain_id: int,
    audience: str,
) -> tuple[str, int]:
    normalized_case = str(case_id).upper()
    if normalized_case not in CASE_BY_ID:
        raise ValueError(f"unsupported case_id: {case_id}")
    if not isinstance(experiment_id, str) or not experiment_id.strip():
        raise ValueError("experiment_id must be a non-empty string")
    if isinstance(chain_id, bool) or not isinstance(chain_id, int) or chain_id <= 0:
        raise ValueError("chain_id must be a positive integer")
    if not isinstance(audience, str) or not audience.strip():
        raise ValueError("audience must be a non-empty string")
    return normalized_case, int(chain_id)


def build_control_scenario(
    case_id: str,
    experiment_id: str,
    chain_id: int,
    audience: str,
) -> dict[str, Any]:
    """Build a signed, public-only Original/Baseline lineage control scenario.

    The function is deliberately chain-free.  ``baseline`` always contains a
    legitimate invocation, delegation chain and registry snapshot.  For L01 to
    L14, the top-level artifacts contain the concrete attack mutation; H00 and
    all A cases remain byte-for-byte equivalent to the legitimate artifacts.

    The returned top-level ``signature`` authenticates the canonical JSON of
    every other top-level field.  No private key is returned or persisted.
    """

    case_id, chain_id = _validate_inputs(
        case_id,
        experiment_id,
        chain_id,
        audience,
    )
    now = int(time.time())
    epoch = _epoch_for(experiment_id)

    root_operation = Account.create(extra_entropy=f"{experiment_id}:root-operation")
    root_delegation = Account.create(extra_entropy=f"{experiment_id}:root-delegation")
    parent_operation = Account.create(extra_entropy=f"{experiment_id}:parent-operation")
    parent_delegation = Account.create(extra_entropy=f"{experiment_id}:parent-delegation")
    leaf_operation = Account.create(extra_entropy=f"{experiment_id}:leaf-operation")

    root_did = did_from_address(root_operation.address, chain_id)
    parent_did = did_from_address(parent_operation.address, chain_id)
    leaf_did = did_from_address(leaf_operation.address, chain_id)

    parent_jti = _stable_uuid(experiment_id, "parent-credential")
    leaf_jti = _stable_uuid(experiment_id, "leaf-credential")
    parent_budget_id = _bytes32_id(experiment_id, "parent-budget")
    leaf_budget_id = _bytes32_id(experiment_id, "leaf-budget")
    branch_id = _bytes32_id(experiment_id, "branch-one")

    parent_permission = _permission(
        actions=["read", "write"],
        resources=["urn:tool:a", "urn:tool:b"],
        tasks=["task-1", "task-2"],
        audiences=[audience],
        versions=[VERSION_ID],
        not_before=now - 60,
        expires_at=now + 7_200,
        remaining_depth=3,
        delegable=True,
    )
    leaf_permission = _permission(
        actions=["read"],
        resources=["urn:tool:a"],
        tasks=["task-1"],
        audiences=[audience],
        versions=[VERSION_ID],
        not_before=now - 30,
        expires_at=now + 1_800,
        remaining_depth=0,
        delegable=False,
    )

    parent_credential = _signed_delegation(
        credential_jti=parent_jti,
        branch_id=branch_id,
        root_did=root_did,
        parent_did=root_did,
        child_did=parent_did,
        parent_credential_jti=f"urn:agentdid:epoch:{epoch}",
        parent_credential_hash=_bytes32_id(experiment_id, "epoch-certificate"),
        operation_key=parent_operation.address,
        delegation_key=parent_delegation.address,
        agent_type="persistent",
        version_id=VERSION_ID,
        permission=parent_permission,
        budget_id=parent_budget_id,
        epoch=epoch,
        issuer_did=root_did,
        issuer_key_purpose="delegation",
        issuer_account=root_delegation,
    )
    leaf_credential = _signed_delegation(
        credential_jti=leaf_jti,
        branch_id=branch_id,
        root_did=root_did,
        parent_did=parent_did,
        child_did=leaf_did,
        parent_credential_jti=parent_jti,
        parent_credential_hash=sha256_json(parent_credential),
        operation_key=leaf_operation.address,
        delegation_key=None,
        agent_type="session",
        version_id=VERSION_ID,
        permission=leaf_permission,
        budget_id=leaf_budget_id,
        epoch=epoch,
        issuer_did=parent_did,
        issuer_key_purpose="delegation",
        issuer_account=parent_delegation,
    )

    baseline_invocation = {
        "schema": "agentlineage-request-v1",
        "leaf_did": leaf_did,
        "credential_jti": leaf_jti,
        "origin_did": leaf_did,
        "on_behalf_of": root_did,
        "audience": audience,
        "task_id": "task-1",
        "action": "read",
        "resource": "urn:tool:a",
        "version_id": VERSION_ID,
        "body_hash": sha256_json(REQUEST_BODY),
        "challenge": f"lineage-{experiment_id}",
        "sequence": 1,
        "timestamp": now,
        "budget_id": leaf_budget_id,
        "cost_units": 2,
        "lease_seconds": 30,
    }
    baseline_delegation = {
        "schema": DELEGATION_SCHEMA,
        "registered_chains": [[parent_credential, leaf_credential]],
        "presented_chain": [parent_credential, leaf_credential],
    }
    baseline_registry_state: dict[str, Any] = {
        "schema": REGISTRY_SCHEMA,
        "chain_id": chain_id,
        "epoch": epoch,
        "root": {
            "did": root_did,
            "active": True,
            "revoked": False,
            "current_epoch": epoch,
            "delegation_key": root_delegation.address,
        },
        "nodes": {},
        "credentials": {},
        "revocations": {
            "roots": [],
            "nodes": [],
            "credentials": [],
            "epochs": [],
        },
    }
    _add_registered_chain(
        baseline_registry_state,
        parent_credential,
        leaf_credential,
    )

    baseline = {
        "invocation": copy.deepcopy(baseline_invocation),
        "delegation": copy.deepcopy(baseline_delegation),
        "registry_state": copy.deepcopy(baseline_registry_state),
    }
    invocation = copy.deepcopy(baseline_invocation)
    delegation = copy.deepcopy(baseline_delegation)
    registry_state = copy.deepcopy(baseline_registry_state)
    request_signer = leaf_operation

    if case_id == "L01":
        invocation["action"] = "write"
    elif case_id == "L02":
        invocation["resource"] = "urn:tool:b"
    elif case_id == "L03":
        escalated_permission = copy.deepcopy(leaf_permission)
        escalated_permission["actions"] = ["delete", "read"]
        escalated_leaf = _signed_delegation(
            credential_jti=leaf_jti,
            branch_id=branch_id,
            root_did=root_did,
            parent_did=parent_did,
            child_did=leaf_did,
            parent_credential_jti=parent_jti,
            parent_credential_hash=sha256_json(parent_credential),
            operation_key=leaf_operation.address,
            delegation_key=None,
            agent_type="session",
            version_id=VERSION_ID,
            permission=escalated_permission,
            budget_id=leaf_budget_id,
            epoch=epoch,
            issuer_did=parent_did,
            issuer_key_purpose="delegation",
            issuer_account=parent_delegation,
        )
        _replace_presented_leaf(delegation, escalated_leaf)
        invocation["action"] = "delete"
    elif case_id == "L04":
        extended_permission = copy.deepcopy(leaf_permission)
        extended_permission["expires_at"] = parent_permission["expires_at"] + 60
        extended_leaf = _signed_delegation(
            credential_jti=leaf_jti,
            branch_id=branch_id,
            root_did=root_did,
            parent_did=parent_did,
            child_did=leaf_did,
            parent_credential_jti=parent_jti,
            parent_credential_hash=sha256_json(parent_credential),
            operation_key=leaf_operation.address,
            delegation_key=None,
            agent_type="session",
            version_id=VERSION_ID,
            permission=extended_permission,
            budget_id=leaf_budget_id,
            epoch=epoch,
            issuer_did=parent_did,
            issuer_key_purpose="delegation",
            issuer_account=parent_delegation,
        )
        _replace_presented_leaf(delegation, extended_leaf)
    elif case_id == "L05":
        reset_permission = copy.deepcopy(leaf_permission)
        reset_permission["remaining_depth"] = parent_permission["remaining_depth"]
        reset_leaf = _signed_delegation(
            credential_jti=leaf_jti,
            branch_id=branch_id,
            root_did=root_did,
            parent_did=parent_did,
            child_did=leaf_did,
            parent_credential_jti=parent_jti,
            parent_credential_hash=sha256_json(parent_credential),
            operation_key=leaf_operation.address,
            delegation_key=None,
            agent_type="session",
            version_id=VERSION_ID,
            permission=reset_permission,
            budget_id=leaf_budget_id,
            epoch=epoch,
            issuer_did=parent_did,
            issuer_key_purpose="delegation",
            issuer_account=parent_delegation,
        )
        _replace_presented_leaf(delegation, reset_leaf)
    elif case_id == "L06":
        rogue_delegation = Account.create(
            extra_entropy=f"{experiment_id}:rogue-delegation"
        )
        forbidden_permission = copy.deepcopy(leaf_permission)
        forbidden_permission.update({"remaining_depth": 1, "delegable": True})
        forbidden_leaf = _signed_delegation(
            credential_jti=leaf_jti,
            branch_id=branch_id,
            root_did=root_did,
            parent_did=parent_did,
            child_did=leaf_did,
            parent_credential_jti=parent_jti,
            parent_credential_hash=sha256_json(parent_credential),
            operation_key=leaf_operation.address,
            delegation_key=rogue_delegation.address,
            agent_type="session",
            version_id=VERSION_ID,
            permission=forbidden_permission,
            budget_id=leaf_budget_id,
            epoch=epoch,
            issuer_did=parent_did,
            issuer_key_purpose="delegation",
            issuer_account=parent_delegation,
        )
        _replace_presented_leaf(delegation, forbidden_leaf)
    elif case_id == "L07":
        operation_signed_leaf = _signed_delegation(
            credential_jti=leaf_jti,
            branch_id=branch_id,
            root_did=root_did,
            parent_did=parent_did,
            child_did=leaf_did,
            parent_credential_jti=parent_jti,
            parent_credential_hash=sha256_json(parent_credential),
            operation_key=leaf_operation.address,
            delegation_key=None,
            agent_type="session",
            version_id=VERSION_ID,
            permission=leaf_permission,
            budget_id=leaf_budget_id,
            epoch=epoch,
            issuer_did=parent_did,
            issuer_key_purpose="operation",
            issuer_account=parent_operation,
        )
        _replace_presented_leaf(delegation, operation_signed_leaf)
    elif case_id == "L08":
        sibling_operation = Account.create(
            extra_entropy=f"{experiment_id}:sibling-operation"
        )
        sibling_did = did_from_address(sibling_operation.address, chain_id)
        invocation.update({"leaf_did": sibling_did, "origin_did": sibling_did})
        request_signer = sibling_operation
    elif case_id == "L09":
        other_parent_operation = Account.create(
            extra_entropy=f"{experiment_id}:other-parent-operation"
        )
        other_parent_delegation = Account.create(
            extra_entropy=f"{experiment_id}:other-parent-delegation"
        )
        other_leaf_operation = Account.create(
            extra_entropy=f"{experiment_id}:other-leaf-operation"
        )
        other_parent_did = did_from_address(other_parent_operation.address, chain_id)
        other_leaf_did = did_from_address(other_leaf_operation.address, chain_id)
        other_parent_jti = _stable_uuid(experiment_id, "other-parent-credential")
        other_leaf_jti = _stable_uuid(experiment_id, "other-leaf-credential")
        other_parent_budget = _bytes32_id(experiment_id, "other-parent-budget")
        other_leaf_budget = _bytes32_id(experiment_id, "other-leaf-budget")
        other_branch_id = _bytes32_id(experiment_id, "branch-two")
        other_parent = _signed_delegation(
            credential_jti=other_parent_jti,
            branch_id=other_branch_id,
            root_did=root_did,
            parent_did=root_did,
            child_did=other_parent_did,
            parent_credential_jti=f"urn:agentdid:epoch:{epoch}",
            parent_credential_hash=_bytes32_id(experiment_id, "epoch-certificate"),
            operation_key=other_parent_operation.address,
            delegation_key=other_parent_delegation.address,
            agent_type="persistent",
            version_id=VERSION_ID,
            permission=parent_permission,
            budget_id=other_parent_budget,
            epoch=epoch,
            issuer_did=root_did,
            issuer_key_purpose="delegation",
            issuer_account=root_delegation,
        )
        other_leaf = _signed_delegation(
            credential_jti=other_leaf_jti,
            branch_id=other_branch_id,
            root_did=root_did,
            parent_did=other_parent_did,
            child_did=other_leaf_did,
            parent_credential_jti=other_parent_jti,
            parent_credential_hash=sha256_json(other_parent),
            operation_key=other_leaf_operation.address,
            delegation_key=None,
            agent_type="session",
            version_id=VERSION_ID,
            permission=leaf_permission,
            budget_id=other_leaf_budget,
            epoch=epoch,
            issuer_did=other_parent_did,
            issuer_key_purpose="delegation",
            issuer_account=other_parent_delegation,
        )
        delegation["registered_chains"].append([other_parent, other_leaf])
        delegation["presented_chain"] = [parent_credential, other_leaf]
        _add_registered_chain(registry_state, other_parent, other_leaf)
        invocation.update({
            "leaf_did": other_leaf_did,
            "credential_jti": other_leaf_jti,
            "origin_did": other_leaf_did,
            "budget_id": other_leaf_budget,
        })
        request_signer = other_leaf_operation
    elif case_id == "L10":
        invocation["task_id"] = "task-2"
    elif case_id == "L11":
        invocation["audience"] = f"{audience}:other"
    elif case_id == "L12":
        registry_state["nodes"][parent_did].update({
            "active": False,
            "revoked": True,
        })
        registry_state["revocations"]["nodes"].append({
            "did": parent_did,
            "reason": "ancestor_revoked",
            "effective_epoch": epoch,
        })
    elif case_id == "L13":
        invocation["origin_did"] = parent_did
    elif case_id == "L14":
        invocation["version_id"] = OTHER_VERSION_ID

    attack_semantics = _normalized_semantics(case_id)
    request_hash = sha256_json({
        "invocation": invocation,
        "body": REQUEST_BODY,
    })
    unsigned_scenario: dict[str, Any] = {
        "schema": SCENARIO_SCHEMA,
        "case_id": case_id,
        "experiment_id": experiment_id,
        "chain_id": chain_id,
        "audience": audience,
        "lineage_enforced": False,
        "leaf_did": invocation["leaf_did"],
        "leaf_operation_address": request_signer.address,
        "credential_jti": invocation["credential_jti"],
        "epoch": epoch,
        "budget_id": invocation["budget_id"],
        "request_hash": request_hash,
        "request_hash_scope": "canonical_json({invocation,body})",
        "signature_scope": "canonical_json(all_top_level_fields_except_signature)",
        "body": copy.deepcopy(REQUEST_BODY),
        "baseline": baseline,
        "invocation": invocation,
        "delegation": delegation,
        "registry_state": registry_state,
        "mutation": attack_semantics["mutation"],
        "attack_semantics": attack_semantics,
        "attack_semantics_hash": sha256_json(attack_semantics),
    }
    # This is the only returned signature for the request envelope.  It covers
    # the complete public scenario body and is created by the current leaf's
    # freshly generated operation key.
    return {
        **unsigned_scenario,
        "signature": sign_json(unsigned_scenario, request_signer.key.hex()),
    }


# Compatibility name for callers that still refer to the control artifact as
# a request.  Both names intentionally expose the same signature and behavior.
build_control_request = build_control_scenario


__all__ = [
    "build_control_request",
    "build_control_scenario",
]
