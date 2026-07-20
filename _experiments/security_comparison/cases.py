from __future__ import annotations

from dataclasses import dataclass


SCHEMES = ("original", "baseline", "lineage")
SCHEME_LABELS = {
    "original": "Original-AgentDID",
    "baseline": "Baseline-AgentDID",
    "lineage": "Lineage-AgentDID",
}
SCHEME_DIRECTORIES = {
    "original": "original-agentdid",
    "baseline": "baseline-agentdid",
    "lineage": "lineage-agentdid",
}


@dataclass(frozen=True)
class CaseSpec:
    case_id: str
    name: str
    family: str
    description: str


@dataclass(frozen=True)
class ExpectedOutcome:
    accepted: bool
    code: str
    detection_layer: str
    required_pass_layers: tuple[str, ...]


LINEAGE_REJECTION_CODES = {
    "L01": "PERMISSION_DENIED",
    "L02": "PERMISSION_DENIED",
    "L03": "POLICY_ESCALATION",
    "L04": "POLICY_ESCALATION",
    "L05": "POLICY_ESCALATION",
    "L06": "IDENTITY_POLICY_INVALID",
    "L07": "DELEGATION_SIGNATURE_INVALID",
    "L08": "LEAF_BINDING_MISMATCH",
    "L09": "PARENT_MISMATCH",
    "L10": "PERMISSION_DENIED",
    "L11": "AUDIENCE_MISMATCH",
    "L12": "STATUS_REVOKED",
    "L13": "ORIGIN_MISMATCH",
    "L14": "VERSION_MISMATCH",
}


CASES = (
    CaseSpec("H00", "legitimate", "honest", "Valid DID/VC/VP and authorized request"),
    CaseSpec("L01", "leaf_action_escalation", "lineage", "Leaf invokes an action outside delegated scope"),
    CaseSpec("L02", "leaf_resource_escalation", "lineage", "Leaf invokes a resource outside delegated scope"),
    CaseSpec("L03", "delegation_scope_escalation", "lineage", "Child credential expands the parent action set"),
    CaseSpec("L04", "validity_extension", "lineage", "Child credential extends parent validity"),
    CaseSpec("L05", "depth_reset", "lineage", "Child credential resets remaining delegation depth"),
    CaseSpec("L06", "forbidden_session_delegation", "lineage", "Session identity attempts to become delegable"),
    CaseSpec("L07", "operation_key_signed_delegation", "lineage", "Operation key signs a delegation credential"),
    CaseSpec("L08", "sibling_credential_impersonation", "lineage", "Sibling identity presents another leaf credential"),
    CaseSpec("L09", "branch_splice", "lineage", "Credentials from independent branches are spliced"),
    CaseSpec("L10", "cross_task_replay", "lineage", "Request moves to a task outside delegated scope"),
    CaseSpec("L11", "cross_audience_replay", "lineage", "Request moves to another audience"),
    CaseSpec("L12", "ancestor_revocation", "lineage", "Descendant invokes after ancestor revocation"),
    CaseSpec("L13", "confused_deputy", "lineage", "Leaf changes the declared request origin"),
    CaseSpec("L14", "version_substitution", "lineage", "Leaf substitutes an unauthorized version"),
    CaseSpec("A01", "agent_impersonation", "identity", "Attacker signs a VP that claims the victim DID"),
    CaseSpec("A02", "vp_replay", "identity", "Previously valid VP is replayed under a new challenge"),
    CaseSpec("A03", "cross_holder_vc_replay", "identity", "Attacker places the victim VC in its own VP"),
    CaseSpec("A04", "false_capability", "semantic", "Trusted issuer signs a capability contradicted by evidence"),
    CaseSpec("A05", "false_current_state", "state", "Holder signs a state that differs from the actual artifact"),
    CaseSpec("A06", "context_loss_or_reset", "context", "Holder resets context after authentication"),
)

CASE_BY_ID = {item.case_id: item for item in CASES}


def expected_acceptance(scheme: str, case_id: str) -> bool:
    return expected_outcome(scheme, case_id).accepted


def expected_outcome(scheme: str, case_id: str) -> ExpectedOutcome:
    if scheme not in SCHEMES:
        raise ValueError(f"unsupported scheme: {scheme}")
    case = CASE_BY_ID[case_id]
    if case.family == "honest":
        if scheme == "original":
            return ExpectedOutcome(True, "ORIGINAL_IDENTITY_ACCEPTED", "original-agentdid", ("did-vc-vp",))
        if scheme == "baseline":
            return ExpectedOutcome(True, "BASELINE_ACCEPTED", "baseline-agentdid", ("did-vc-vp", "baseline-agentdid"))
        return ExpectedOutcome(True, "ACCEPTED", "lineage-agentdid", ("did-vc-vp", "baseline-agentdid", "lineage-agentdid"))
    if case.family == "identity":
        codes = {
            "A01": "VP_SIGNATURE_INVALID",
            "A02": "VP_CHALLENGE_MISMATCH",
            "A03": "VC_SUBJECT_HOLDER_MISMATCH",
        }
        return ExpectedOutcome(False, codes[case_id], "did-vc-vp", ())
    if case.family in {"semantic", "state", "context"}:
        if scheme == "original":
            return ExpectedOutcome(True, "ORIGINAL_IDENTITY_ACCEPTED", "original-agentdid", ("did-vc-vp",))
        codes = {
            "A04": "CAPABILITY_EVIDENCE_MISMATCH",
            "A05": "STATE_GROUND_TRUTH_MISMATCH",
            "A06": "CONTEXT_CONTINUITY_MISMATCH",
        }
        return ExpectedOutcome(False, codes[case_id], "baseline-agentdid", ("did-vc-vp",))
    if case.family == "lineage":
        if scheme == "original":
            return ExpectedOutcome(True, "ORIGINAL_IDENTITY_ACCEPTED", "original-agentdid", ("did-vc-vp",))
        if scheme == "baseline":
            return ExpectedOutcome(True, "BASELINE_ACCEPTED", "baseline-agentdid", ("did-vc-vp", "baseline-agentdid"))
        return ExpectedOutcome(
            False,
            LINEAGE_REJECTION_CODES[case_id],
            "lineage-agentdid",
            ("did-vc-vp", "baseline-agentdid"),
        )
    raise ValueError(f"unsupported case family: {case.family}")
