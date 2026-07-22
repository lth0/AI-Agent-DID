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
ROBUSTNESS_CHECKS = {
    "A01": {
        "dimension": "did-key-binding",
        "target": "VP holder DID and authentication key binding",
        "control": "claimed holder signs with its registered authentication key",
        "variation": "the same holder claim is signed by an unrelated registered identity key",
    },
    "A02": {
        "dimension": "vp-freshness",
        "target": "VP challenge freshness",
        "control": "captured VP verifies under its original challenge",
        "variation": "the identical captured VP is checked against a fresh challenge",
    },
    "A03": {
        "dimension": "credential-holder-binding",
        "target": "VC subject and VP holder binding",
        "control": "VC subject presents the credential in its own VP",
        "variation": "a different valid holder presents the unchanged credential",
    },
    "A04": {
        "dimension": "capability-evidence-consistency",
        "target": "signed capability claim and independent benchmark consistency",
        "control": "claim and independently observed benchmark result agree",
        "variation": "valid signed claim conflicts with deterministic evaluation evidence",
    },
    "A05": {
        "dimension": "state-artifact-consistency",
        "target": "signed current-state claim and artifact digest consistency",
        "control": "reported state equals the verifier-observed artifact state",
        "variation": "valid signed state differs from the verifier-observed artifact digest",
    },
    "A06": {
        "dimension": "context-continuity",
        "target": "signed context hash and version continuity",
        "control": "context advances from the verifier-stored previous state",
        "variation": "valid signed snapshot restarts from an empty version-zero context",
    },
}
ROBUSTNESS_CASE_IDS = tuple(ROBUSTNESS_CHECKS)
LINEAGE_PHASE1_CHECKS = {
    "L01": {
        "dimension": "invocation-action-scope",
        "target": "invocation action must remain within the leaf permission",
        "control": "leaf invokes read from its delegated action set",
        "variation": "leaf invokes write, which is available to the parent but not the leaf",
    },
    "L02": {
        "dimension": "invocation-resource-scope",
        "target": "invocation resource must remain within the leaf permission",
        "control": "leaf invokes urn:tool:a from its delegated resource set",
        "variation": "leaf invokes urn:tool:b, which is available to the parent but not the leaf",
    },
    "L03": {
        "dimension": "delegation-action-attenuation",
        "target": "child action scope must be a subset of the parent action scope",
        "control": "child action scope contains only read",
        "variation": "validly signed child credential adds delete beyond the parent scope",
    },
    "L04": {
        "dimension": "delegation-validity-attenuation",
        "target": "child validity must not extend beyond parent validity",
        "control": "child expires before its parent",
        "variation": "validly signed child credential expires after its parent",
    },
    "L05": {
        "dimension": "delegation-depth-attenuation",
        "target": "remaining delegation depth must strictly decrease",
        "control": "session child has zero remaining delegation depth",
        "variation": "validly signed child credential resets depth to the parent value",
    },
}
LINEAGE_PHASE1_CASE_IDS = tuple(LINEAGE_PHASE1_CHECKS)
LINEAGE_L06_L14_ROBUSTNESS_CHECKS = {
    "L06": {
        "dimension": "session-delegability-policy",
        "target": "session identities must remain non-delegable",
        "control": "session permission is non-delegable and has no delegation key",
        "variation": "a validly signed session credential enables delegation and supplies a delegation key",
    },
    "L07": {
        "dimension": "delegation-key-purpose",
        "target": "delegation credentials must use the parent delegation key",
        "control": "the parent delegation key signs the child credential",
        "variation": "the parent operation key signs the otherwise unchanged child credential",
    },
    "L08": {
        "dimension": "leaf-credential-binding",
        "target": "the invocation leaf must match the presented leaf credential",
        "control": "the credential subject signs its own leaf invocation",
        "variation": "an independently authenticated sibling signs a fresh invocation while the original leaf credential is presented",
    },
    "L09": {
        "dimension": "delegation-branch-continuity",
        "target": "every adjacent credential must belong to one continuous branch",
        "control": "parent and leaf credentials come from the same registered branch",
        "variation": "the presented chain combines a parent from one branch with a leaf from another",
    },
    "L10": {
        "dimension": "invocation-task-scope",
        "target": "the invocation task must remain within the leaf permission",
        "control": "the leaf invokes delegated task-1",
        "variation": "the same leaf signs an invocation for non-delegated task-2",
    },
    "L11": {
        "dimension": "invocation-audience-binding",
        "target": "the invocation audience must equal the verifier audience",
        "control": "the invocation targets the verifier gateway audience",
        "variation": "the same leaf signs an invocation for a different gateway audience",
    },
    "L12": {
        "dimension": "ancestor-revocation-propagation",
        "target": "ancestor node revocation must invalidate descendant invocations",
        "control": "the registered parent node remains active",
        "variation": "the parent node is revoked on-chain before the descendant invocation is verified",
    },
    "L13": {
        "dimension": "request-origin-binding",
        "target": "the declared origin must equal the authenticated leaf DID",
        "control": "the leaf declares itself as request origin",
        "variation": "the leaf signs a request that declares its parent as origin",
    },
    "L14": {
        "dimension": "invocation-version-binding",
        "target": "the invocation version must equal the delegated leaf version",
        "control": "the invocation uses the delegated version identifier",
        "variation": "the same leaf signs an invocation using an unrelated version identifier",
    },
}
LINEAGE_L06_L14_ROBUSTNESS_CASE_IDS = tuple(LINEAGE_L06_L14_ROBUSTNESS_CHECKS)
LINEAGE_ROBUSTNESS_CHECKS = {
    **LINEAGE_PHASE1_CHECKS,
    **LINEAGE_L06_L14_ROBUSTNESS_CHECKS,
}
LINEAGE_ROBUSTNESS_CASE_IDS = tuple(LINEAGE_ROBUSTNESS_CHECKS)


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
    CaseSpec("L01", "action_scope_robustness", "robustness_lineage", "Checks an invocation action against the delegated leaf scope"),
    CaseSpec("L02", "resource_scope_robustness", "robustness_lineage", "Checks an invocation resource against the delegated leaf scope"),
    CaseSpec("L03", "delegation_scope_robustness", "robustness_lineage", "Checks that a child credential cannot expand its parent action set"),
    CaseSpec("L04", "validity_attenuation_robustness", "robustness_lineage", "Checks that child validity cannot extend beyond its parent"),
    CaseSpec("L05", "depth_attenuation_robustness", "robustness_lineage", "Checks that remaining delegation depth strictly decreases"),
    CaseSpec("L06", "session_delegability_robustness", "robustness_lineage", "Checks that a session identity cannot become delegable"),
    CaseSpec("L07", "delegation_key_purpose_robustness", "robustness_lineage", "Checks that an operation key cannot authorize a delegation credential"),
    CaseSpec("L08", "leaf_credential_binding_robustness", "robustness_lineage", "Checks a fresh sibling invocation against the presented leaf credential"),
    CaseSpec("L09", "delegation_branch_continuity_robustness", "robustness_lineage", "Checks that credentials from separate branches cannot form one chain"),
    CaseSpec("L10", "task_scope_robustness", "robustness_lineage", "Checks the invocation task against the delegated leaf scope"),
    CaseSpec("L11", "audience_binding_robustness", "robustness_lineage", "Checks the invocation audience against the verifier gateway"),
    CaseSpec("L12", "ancestor_revocation_robustness", "robustness_lineage", "Checks that on-chain ancestor revocation propagates to descendants"),
    CaseSpec("L13", "origin_binding_robustness", "robustness_lineage", "Checks the declared request origin against the authenticated leaf"),
    CaseSpec("L14", "version_binding_robustness", "robustness_lineage", "Checks the invocation version against the delegated leaf version"),
    CaseSpec("A01", "did_key_binding_robustness", "robustness_identity", "Checks rejection when a claimed DID is signed by an unrelated key"),
    CaseSpec("A02", "vp_freshness_robustness", "robustness_identity", "Checks rejection when a previously valid VP is presented for a new challenge"),
    CaseSpec("A03", "subject_holder_binding_robustness", "robustness_identity", "Checks rejection when a valid VC is presented by a different holder"),
    CaseSpec("A04", "capability_evidence_robustness", "robustness_semantic", "Checks a signed capability claim against independent evaluation evidence"),
    CaseSpec("A05", "state_artifact_robustness", "robustness_state", "Checks a signed current-state claim against the actual artifact"),
    CaseSpec("A06", "context_continuity_robustness", "robustness_context", "Checks whether a signed context snapshot preserves session continuity"),
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
    if case.family == "robustness_identity":
        codes = {
            "A01": "VP_SIGNATURE_INVALID",
            "A02": "VP_CHALLENGE_MISMATCH",
            "A03": "VC_SUBJECT_HOLDER_MISMATCH",
        }
        return ExpectedOutcome(False, codes[case_id], "did-vc-vp", ())
    if case.family in {
        "robustness_semantic",
        "robustness_state",
        "robustness_context",
    }:
        if scheme == "original":
            return ExpectedOutcome(True, "ORIGINAL_IDENTITY_ACCEPTED", "original-agentdid", ("did-vc-vp",))
        codes = {
            "A04": "CAPABILITY_EVIDENCE_MISMATCH",
            "A05": "STATE_GROUND_TRUTH_MISMATCH",
            "A06": "CONTEXT_CONTINUITY_MISMATCH",
        }
        return ExpectedOutcome(False, codes[case_id], "baseline-agentdid", ("did-vc-vp",))
    if case.family in {"robustness_lineage", "lineage"}:
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
