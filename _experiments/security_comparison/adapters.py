from __future__ import annotations

import copy
import dataclasses
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from eth_account import Account

from infrastructure.agentdid_protocol import (
    DidVcVpVerifier,
    ProtocolIdentity,
    create_presentation,
    issue_credential,
    issue_status_list,
    make_did_document,
    relationship_method_for_address,
    sign_json,
    verify_relationship_signature,
)
from infrastructure.security import ReplayGuard, sha256_json
from infrastructure.semantic_benchmark import (
    BENCHMARK_ID,
    DEFAULT_THRESHOLD,
    artifact_digest,
    evaluate as evaluate_benchmark,
)

from .cases import CaseSpec, ROBUSTNESS_CHECKS
from .chain import ActorKeys, ChainConfig
from .lineage_cases import AUDIENCE, LineageCase, build_lineage_case
from .scenarios import build_control_scenario


FULL_CREDENTIAL_TYPES = {
    "AgentIdentityCredential",
    "AgentModelCredential",
    "AgentCapabilityCredential",
    "AgentToolsetCredential",
    "AgentComplianceCredential",
}


@dataclass
class ExperimentBundle:
    case: CaseSpec
    scheme: str
    experiment_id: str
    identities: dict[str, ProtocolIdentity]
    documents: dict[str, dict[str, Any]]
    credentials: list[dict[str, Any]]
    status_lists: dict[str, dict[str, Any]]
    presentation: dict[str, Any]
    expected_holder: str
    expected_challenge: str
    expected_audience: str
    presentation_signer: ProtocolIdentity
    presentation_verification_address: str
    evaluator_report: dict[str, Any]
    state_statement: dict[str, Any]
    actual_state: dict[str, Any]
    context_statement: dict[str, Any]
    expected_context: dict[str, Any]
    lineage: LineageCase | None
    replay_guard: ReplayGuard
    independent_state: dict[str, Any]
    trusted_evaluators: frozenset[str]

    def state_artifact(self) -> dict[str, Any]:
        return {
            "reported_state": self.state_statement,
            "actual_state": self.actual_state,
            "evaluator_report": self.evaluator_report,
            "reported_context": self.context_statement,
            "expected_context": self.expected_context,
        }


@dataclass(frozen=True)
class SchemeDecision:
    accepted: bool
    code: str
    reason: str
    detection_layer: str
    protocol: dict[str, Any]
    baseline: dict[str, Any] | None = None
    lineage: dict[str, Any] | None = None
    chain_transactions: tuple[dict[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "code": self.code,
            "reason": self.reason,
            "detection_layer": self.detection_layer,
            "protocol": self.protocol,
            "baseline": self.baseline,
            "lineage": self.lineage,
            "chain_transactions": list(self.chain_transactions),
        }


def _signed_statement(body: dict[str, Any], signer: ProtocolIdentity) -> dict[str, Any]:
    return {**copy.deepcopy(body), "signature": sign_json(body, signer.operation_private_key)}


def _credential_claims(case_id: str) -> tuple[str, dict[str, dict[str, Any]]]:
    # A04 isolates a false capability claim: the artifact is faulty while the
    # trusted issuer signs a qualified/correct claim.  A05 must *not* also
    # trigger the capability layer, so it uses a correct artifact and lies only
    # in the separately signed current-state statement.
    actual_profile = "faulty" if case_id == "A04" else "correct"
    claimed_profile = "correct" if case_id == "A04" else actual_profile
    claimed_score = 1.0 if claimed_profile == "correct" else 0.0
    claims = {
        "AgentIdentityCredential": {
            "agentName": "Comparison Agent",
            "softwareVersion": "v1",
            "artifactDigest": artifact_digest(claimed_profile),
        },
        "AgentModelCredential": {
            "model": "deterministic-integer-agent",
            "modelVersion": "v1",
        },
        "AgentCapabilityCredential": {
            "benchmarkId": BENCHMARK_ID,
            "capability": f"urn:benchmark:{BENCHMARK_ID}",
            "claimedScore": claimed_score,
            "threshold": DEFAULT_THRESHOLD,
            "qualified": claimed_score >= DEFAULT_THRESHOLD,
            "artifactDigest": artifact_digest(claimed_profile),
        },
        "AgentToolsetCredential": {
            "tools": ["integer-addition"],
            "operationalStatus": "Active",
        },
        "AgentComplianceCredential": {
            "profile": "agentdid-comparison-v1",
            "compliant": True,
        },
    }
    return actual_profile, claims


def build_experiment_bundle(
    case: CaseSpec,
    scheme: str,
    *,
    experiment_id: str,
    run_id: str,
    lineage_epoch: int,
    chain_config: ChainConfig,
    actor_keys: ActorKeys,
) -> ExperimentBundle:
    identities = actor_keys.identities(chain_config.chain_id)
    lineage: LineageCase | None = None
    if scheme == "lineage":
        lineage = build_lineage_case(
            case.case_id,
            experiment_id=experiment_id,
            run_id=run_id,
            requested_epoch=lineage_epoch,
            chain_config=chain_config,
            chain_private_key=actor_keys.chain_private_key,
        )
        holder_account = Account.from_key(
            lineage.protocol_holder_private_key
        )
        identities["holder"] = ProtocolIdentity.from_keys(
            "holder",
            holder_account.key.hex(),
            holder_account.key.hex(),
            chain_config.chain_id,
        )
        if identities["holder"].did != lineage.protocol_holder_did:
            raise ValueError("protocol holder DID is not bound to the Lineage operation key")

    documents = {
        identity.did: make_did_document(identity)
        for identity in identities.values()
    }
    issuer = identities["issuer"]
    holder = identities["holder"]
    alternate = identities["alternate"]
    evaluator = identities["evaluator"]
    status_list_id = f"urn:agentdid:status:{experiment_id}"
    status_list = issue_status_list(issuer, list_id=status_list_id)
    status_lists = {status_list_id: status_list}

    actual_profile, claims = _credential_claims(case.case_id)
    if scheme == "original":
        credential_types = ["AgentIdentityCredential"]
        if case.case_id == "A04":
            credential_types.append("AgentCapabilityCredential")
    else:
        credential_types = sorted(FULL_CREDENTIAL_TYPES)
    credentials = [
        issue_credential(
            issuer,
            holder.did,
            credential_type=credential_type,
            claims=claims[credential_type],
            status_list_id=status_list_id,
            status_index=index,
        )
        for index, credential_type in enumerate(credential_types)
    ]

    challenge = f"challenge-{experiment_id}"
    expected_challenge = challenge
    expected_holder = holder.did
    protocol_audience = lineage.expected_audience if lineage else AUDIENCE
    presentation_holder = holder
    presentation_verification_address = holder.operation_address
    if case.case_id == "A01":
        presentation_holder = dataclasses.replace(
            holder,
            operation_address=alternate.operation_address,
            operation_private_key=alternate.operation_private_key,
        )
    elif case.case_id == "A02":
        challenge = f"captured-{experiment_id}"
        expected_challenge = f"fresh-{experiment_id}"
    elif case.case_id == "A03":
        presentation_holder = alternate
        presentation_verification_address = alternate.operation_address
        expected_holder = alternate.did
    presentation = create_presentation(
        credentials,
        presentation_holder,
        challenge=challenge,
        audience=protocol_audience,
    )

    # Run the real, deterministic 100-case benchmark.  The evaluator signs the
    # resulting digest and output hash; no score or qualification bit is
    # hand-written by the scenario builder.
    benchmark_result = evaluate_benchmark(actual_profile)
    report_body = {
        "schema": "agentdid-capability-evidence-v1",
        "holder_did": holder.did,
        "benchmark_id": benchmark_result.benchmark_id,
        "artifact_digest": benchmark_result.artifact_digest,
        "observed_score": benchmark_result.observed_score,
        "threshold": benchmark_result.threshold,
        "qualified": benchmark_result.qualified,
        "input_count": benchmark_result.input_count,
        "outputs_hash": benchmark_result.outputs_hash,
        "evaluated_at": time.time(),
        "evaluator_did": evaluator.did,
    }
    evaluator_report = _signed_statement(report_body, evaluator)

    actual_state = {
        "artifact_digest": artifact_digest(actual_profile),
        "ready": True,
        "state_version": 3,
    }
    reported_state = copy.deepcopy(actual_state)
    if case.case_id == "A05":
        reported_state["artifact_digest"] = artifact_digest("faulty")
    state_body = {
        "holder_did": holder.did,
        "audience": protocol_audience,
        "nonce": f"state-{experiment_id}",
        "timestamp": time.time(),
        "state": reported_state,
    }
    state_statement = _signed_statement(state_body, holder)

    previous_messages = [{"role": "system", "content": "authenticated"}]
    current_messages = [
        *previous_messages,
        {"role": "user", "content": "integer-addition task"},
    ]
    expected_context = {
        "previous_hash": sha256_json(previous_messages),
        "previous_version": 1,
        "context_hash": sha256_json(current_messages),
        "context_version": 2,
    }
    reported_context = copy.deepcopy(expected_context)
    if case.case_id == "A06":
        reset_messages: list[dict[str, str]] = []
        reported_context = {
            "previous_hash": sha256_json(reset_messages),
            "previous_version": 0,
            "context_hash": sha256_json(reset_messages),
            "context_version": 1,
        }
    context_body = {
        "holder_did": holder.did,
        "audience": protocol_audience,
        "auth_challenge": expected_challenge,
        "nonce": f"context-{experiment_id}",
        "timestamp": time.time(),
        **reported_context,
    }
    context_statement = _signed_statement(context_body, holder)

    replay_guard = ReplayGuard(ttl_seconds=3600)
    replay_guard_id = f"urn:uuid:{uuid.uuid4()}"
    control_request = build_control_scenario(
        case.case_id,
        experiment_id=experiment_id,
        chain_id=chain_config.chain_id,
        audience=protocol_audience,
    )
    if lineage is None:
        lineage_isolation = {
            "enforced": False,
            "child_did": control_request["leaf_did"],
            "child_operation_address": control_request["leaf_operation_address"],
            "credential_jti": control_request["credential_jti"],
            "epoch": control_request["epoch"],
            "budget_id": control_request["budget_id"],
            "request_hash": control_request["request_hash"],
            "scenario_semantics_hash": control_request["scenario_semantics_hash"],
            "mutation": control_request["mutation"],
            "control_request": control_request,
        }
    else:
        lineage_isolation = {
            "enforced": True,
            "child_did": lineage.invocation.leaf_did,
            "child_operation_address": holder.operation_address,
            "credential_jti": lineage.invocation.credential_jti,
            "epoch": int(lineage.epoch.epoch),
            "budget_id": lineage.invocation.budget_id,
            "request_hash": sha256_json(lineage.invocation.unsigned_dict()),
            "scenario_semantics_hash": control_request["scenario_semantics_hash"],
            "mutation": control_request["mutation"],
        }
    independent_state = {
        "replay_guard_id": replay_guard_id,
        "vp_challenge": challenge,
        "vc_ids": [item["id"] for item in credentials],
        "vp_hash": sha256_json(presentation),
        "state_nonce": state_body["nonce"],
        "context_nonce": context_body["nonce"],
        "context_state_hash": sha256_json(reported_context),
        "lineage": lineage_isolation,
    }

    return ExperimentBundle(
        case=case,
        scheme=scheme,
        experiment_id=experiment_id,
        identities=identities,
        documents=documents,
        credentials=credentials,
        status_lists=status_lists,
        presentation=presentation,
        expected_holder=expected_holder,
        expected_challenge=expected_challenge,
        expected_audience=protocol_audience,
        presentation_signer=presentation_holder,
        presentation_verification_address=presentation_verification_address,
        evaluator_report=evaluator_report,
        state_statement=state_statement,
        actual_state=actual_state,
        context_statement=context_statement,
        expected_context=expected_context,
        lineage=lineage,
        replay_guard=replay_guard,
        independent_state=independent_state,
        trusted_evaluators=frozenset({evaluator.did}),
    )


def bind_resolved_documents(
    bundle: ExperimentBundle,
    documents: dict[str, dict[str, Any]],
) -> None:
    """Replace fixture documents with chain-resolved documents and re-sign VP.

    ``ethr-did-resolver`` assigns event-derived fragments such as
    ``#delegate-1``.  The proof must name that resolved method rather than an
    in-memory placeholder.  A01 deliberately retains the claimed holder method
    id but signs with an unrelated key, so the protocol still rejects it at the
    authentication relationship.
    """

    signer_document = documents.get(bundle.presentation_signer.did)
    if signer_document is None:
        raise ValueError("presentation signer DID did not resolve")
    verification_method = relationship_method_for_address(
        signer_document,
        "authentication",
        bundle.presentation_verification_address,
    )
    proof = bundle.presentation["proof"]
    bundle.documents = documents
    bundle.presentation = create_presentation(
        bundle.credentials,
        bundle.presentation_signer,
        challenge=str(proof["challenge"]),
        audience=str(proof["audience"]),
        verification_method=verification_method,
    )
    bundle.independent_state["vp_hash"] = sha256_json(bundle.presentation)


def build_robustness_evidence(bundle: ExperimentBundle) -> dict[str, Any] | None:
    definition = ROBUSTNESS_CHECKS.get(bundle.case.case_id)
    if definition is None:
        return None
    evidence: dict[str, Any] = {
        "schema_version": "agentdid-robustness-evidence-v1",
        "classification": "agent-robustness-check",
        "case_id": bundle.case.case_id,
        "dimension": definition["dimension"],
        "target": definition["target"],
        "control": definition["control"],
        "variation": definition["variation"],
    }
    if bundle.case.case_id == "A01":
        evidence["observations"] = {
            "claimed_holder": bundle.presentation["holder"],
            "registered_authentication_address": bundle.presentation_verification_address,
            "signing_operation_address": bundle.presentation_signer.operation_address,
            "challenge": bundle.presentation["proof"]["challenge"],
            "audience": bundle.presentation["proof"]["audience"],
        }
    elif bundle.case.case_id == "A02":
        captured_challenge = str(bundle.presentation["proof"]["challenge"])
        control = DidVcVpVerifier(
            bundle.documents,
            trusted_issuers={bundle.identities["issuer"].did},
            status_lists=bundle.status_lists,
            replay_guard=ReplayGuard(ttl_seconds=3600),
        ).verify(
            bundle.presentation,
            expected_holder=bundle.expected_holder,
            expected_challenge=captured_challenge,
            expected_audience=bundle.expected_audience,
        )
        evidence["observations"] = {
            "captured_challenge": captured_challenge,
            "fresh_expected_challenge": bundle.expected_challenge,
            "captured_vp_hash": sha256_json(bundle.presentation),
            "captured_vp_control_verification": control.to_dict(),
            "same_presentation_reused": True,
        }
    elif bundle.case.case_id == "A03":
        evidence["observations"] = {
            "vp_holder": bundle.presentation["holder"],
            "credential_subjects": [
                item["credentialSubject"]["id"] for item in bundle.credentials
            ],
            "vp_signing_operation_address": bundle.presentation_signer.operation_address,
        }
    elif bundle.case.case_id == "A04":
        capability = _credential_by_type(bundle, "AgentCapabilityCredential")
        evidence["observations"] = {
            "signed_capability_claim": capability["credentialSubject"] if capability else None,
            "independent_evaluation": bundle.evaluator_report,
            "ground_truth_source": "deterministic-benchmark:integer-addition-v1:100-cases",
        }
    elif bundle.case.case_id == "A05":
        evidence["observations"] = {
            "signed_reported_state": bundle.state_statement,
            "verifier_observed_state": bundle.actual_state,
            "ground_truth_source": "deterministic-artifact-digest",
        }
    elif bundle.case.case_id == "A06":
        evidence["observations"] = {
            "signed_reported_context": bundle.context_statement,
            "verifier_stored_context": bundle.expected_context,
            "ground_truth_source": "verifier-session-context",
        }
    return evidence


def _credential_by_type(bundle: ExperimentBundle, credential_type: str) -> dict[str, Any] | None:
    for credential in bundle.credentials:
        if credential_type in credential.get("type", []):
            return credential
    return None


def verify_baseline_policy(bundle: ExperimentBundle) -> tuple[bool, str, str, dict[str, Any]]:
    trace: dict[str, Any] = {"layer": "baseline-agentdid", "checks": []}

    def reject(code: str, reason: str) -> tuple[bool, str, str, dict[str, Any]]:
        trace.update({"accepted": False, "code": code})
        return False, code, reason, trace

    presented_types = {
        item
        for credential in bundle.credentials
        for item in credential.get("type", [])
        if item != "VerifiableCredential"
    }
    if not FULL_CREDENTIAL_TYPES.issubset(presented_types):
        missing = sorted(FULL_CREDENTIAL_TYPES - presented_types)
        return reject(
            "AGENTDID_CREDENTIAL_SET_INCOMPLETE",
            f"missing credentials: {missing}",
        )
    trace["checks"].append("credential_set")

    capability = _credential_by_type(bundle, "AgentCapabilityCredential")
    assert capability is not None
    capability_claim = capability["credentialSubject"]
    report = copy.deepcopy(bundle.evaluator_report)
    report_signature = report.pop("signature", "")
    evaluator_did = report.get("evaluator_did")
    if evaluator_did not in bundle.trusted_evaluators:
        return reject(
            "CAPABILITY_EVALUATOR_UNTRUSTED",
            "capability evidence evaluator is not trusted",
        )
    evaluator_document = bundle.documents.get(str(evaluator_did))
    if not evaluator_document or not verify_relationship_signature(
        evaluator_document,
        "authentication",
        report,
        str(report_signature),
    ):
        return reject(
            "CAPABILITY_EVIDENCE_SIGNATURE_INVALID",
            "evaluator report signature is invalid",
        )
    if (
        report.get("benchmark_id") != BENCHMARK_ID
        or int(report.get("input_count", 0)) != 100
        or not report.get("outputs_hash")
        or abs(time.time() - float(report.get("evaluated_at", 0))) > 120
    ):
        return reject(
            "CAPABILITY_EVIDENCE_BINDING_INVALID",
            "capability evidence benchmark, sample count, output hash, or freshness is invalid",
        )
    evidence_matches = (
        report.get("holder_did") == bundle.identities["holder"].did
        and report.get("benchmark_id") == capability_claim.get("benchmarkId")
        and report.get("artifact_digest") == capability_claim.get("artifactDigest")
        and bool(report.get("qualified")) == bool(capability_claim.get("qualified"))
        and abs(float(report.get("observed_score", -1)) - float(capability_claim.get("claimedScore", -2))) < 1e-12
    )
    if not evidence_matches:
        return reject(
            "CAPABILITY_EVIDENCE_MISMATCH",
            "capability claim contradicts independent evidence",
        )
    if not bool(capability_claim.get("qualified")):
        return reject(
            "CAPABILITY_NOT_QUALIFIED",
            "agent is not qualified for the requested capability",
        )
    trace["checks"].append("capability_evidence")

    state = copy.deepcopy(bundle.state_statement)
    state_signature = state.pop("signature", "")
    holder_document = bundle.documents[bundle.identities["holder"].did]
    if not verify_relationship_signature(
        holder_document,
        "authentication",
        state,
        str(state_signature),
    ):
        return reject("STATE_SIGNATURE_INVALID", "state statement signature is invalid")
    if (
        state.get("holder_did") != bundle.identities["holder"].did
        or state.get("audience") != bundle.expected_audience
        or abs(time.time() - float(state.get("timestamp", 0))) > 120
    ):
        return reject("STATE_BINDING_INVALID", "state statement binding is invalid")
    if state.get("state") != bundle.actual_state:
        return reject(
            "STATE_GROUND_TRUTH_MISMATCH",
            "reported state differs from actual artifact",
        )
    if not bundle.replay_guard.consume("state", str(state.get("nonce"))):
        return reject("STATE_REPLAY", "state statement nonce has already been consumed")
    trace["checks"].append("state_cross_check")

    context = copy.deepcopy(bundle.context_statement)
    context_signature = context.pop("signature", "")
    if not verify_relationship_signature(
        holder_document,
        "authentication",
        context,
        str(context_signature),
    ):
        return reject("CONTEXT_SIGNATURE_INVALID", "context statement signature is invalid")
    if (
        context.get("holder_did") != bundle.identities["holder"].did
        or context.get("audience") != bundle.expected_audience
        or context.get("auth_challenge") != bundle.expected_challenge
        or abs(time.time() - float(context.get("timestamp", 0))) > 120
    ):
        return reject("CONTEXT_BINDING_INVALID", "context statement binding is invalid")
    expected = bundle.expected_context
    continuity = all(
        context.get(field) == expected[field]
        for field in ("previous_hash", "previous_version", "context_hash", "context_version")
    )
    if not continuity:
        return reject("CONTEXT_CONTINUITY_MISMATCH", "context was lost or reset")
    if int(context.get("context_version", -1)) != int(context.get("previous_version", -1)) + 1:
        return reject("CONTEXT_VERSION_INVALID", "context version is not the next version")
    if not bundle.replay_guard.consume("context", str(context.get("nonce"))):
        return reject("CONTEXT_REPLAY", "context statement nonce has already been consumed")
    trace["checks"].append("context_continuity")
    trace.update({"accepted": True, "code": "BASELINE_ACCEPTED"})
    return True, "BASELINE_ACCEPTED", "complete AgentDID policy verified", trace


class SchemeAdapter(ABC):
    """Common interface for the three formal comparison schemes.

    Every adapter calls :meth:`verify_protocol` first.  Subclasses may only
    add policy layers; they cannot replace or weaken DID/VC/VP verification.
    """

    scheme_id: str
    label: str

    @staticmethod
    def verify_protocol(bundle: ExperimentBundle):
        return DidVcVpVerifier(
            bundle.documents,
            trusted_issuers={bundle.identities["issuer"].did},
            status_lists=bundle.status_lists,
            replay_guard=bundle.replay_guard,
        ).verify(
            bundle.presentation,
            expected_holder=bundle.expected_holder,
            expected_challenge=bundle.expected_challenge,
            expected_audience=bundle.expected_audience,
        )

    @staticmethod
    def protocol_rejection(bundle: ExperimentBundle, protocol: Any) -> SchemeDecision:
        return SchemeDecision(
            False,
            protocol.code,
            protocol.reason,
            "did-vc-vp",
            protocol.to_dict(),
            chain_transactions=tuple(bundle.lineage.transactions if bundle.lineage else ()),
        )

    def require_scheme(self, bundle: ExperimentBundle) -> None:
        if bundle.scheme != self.scheme_id:
            raise ValueError(
                f"{self.label} cannot evaluate bundle for scheme {bundle.scheme!r}"
            )

    @abstractmethod
    def evaluate(self, bundle: ExperimentBundle) -> SchemeDecision:
        raise NotImplementedError


class OriginalAgentDidAdapter(SchemeAdapter):
    scheme_id = "original"
    label = "Original-AgentDID"

    def evaluate(self, bundle: ExperimentBundle) -> SchemeDecision:
        self.require_scheme(bundle)
        protocol = self.verify_protocol(bundle)
        if not protocol.accepted:
            return self.protocol_rejection(bundle, protocol)
        return SchemeDecision(
            True,
            "ORIGINAL_IDENTITY_ACCEPTED",
            "DID identity and minimal VC/VP verified",
            "original-agentdid",
            protocol.to_dict(),
        )


class BaselineAgentDidAdapter(SchemeAdapter):
    scheme_id = "baseline"
    label = "Baseline-AgentDID"

    @staticmethod
    def verify_baseline(bundle: ExperimentBundle):
        return verify_baseline_policy(bundle)

    def evaluate(self, bundle: ExperimentBundle) -> SchemeDecision:
        self.require_scheme(bundle)
        protocol = self.verify_protocol(bundle)
        if not protocol.accepted:
            return self.protocol_rejection(bundle, protocol)
        baseline_ok, code, reason, trace = self.verify_baseline(bundle)
        if not baseline_ok:
            return SchemeDecision(
                False,
                code,
                reason,
                "baseline-agentdid",
                protocol.to_dict(),
                trace,
            )
        return SchemeDecision(
            True,
            "BASELINE_ACCEPTED",
            reason,
            "baseline-agentdid",
            protocol.to_dict(),
            trace,
        )


class LineageAgentDidAdapter(BaselineAgentDidAdapter):
    scheme_id = "lineage"
    label = "Lineage-AgentDID"

    def evaluate(self, bundle: ExperimentBundle) -> SchemeDecision:
        self.require_scheme(bundle)
        protocol = self.verify_protocol(bundle)
        if not protocol.accepted:
            return self.protocol_rejection(bundle, protocol)

        baseline_ok, code, reason, trace = self.verify_baseline(bundle)
        if not baseline_ok:
            return SchemeDecision(
                False,
                code,
                reason,
                "baseline-agentdid",
                protocol.to_dict(),
                trace,
                chain_transactions=tuple(
                    bundle.lineage.transactions if bundle.lineage else ()
                ),
            )

        # The Lineage gateway/contract decision is deliberately unreachable
        # until both lower layers have passed.
        if bundle.lineage is None:
            raise ValueError("Lineage-AgentDID requires a Lineage case")
        bundle.lineage.materialize()
        lineage_decision, transactions = bundle.lineage.evaluate()
        return SchemeDecision(
            bool(lineage_decision["accepted"]),
            str(lineage_decision["code"]),
            str(lineage_decision["reason"]),
            "lineage-agentdid",
            protocol.to_dict(),
            trace,
            lineage_decision,
            tuple(transactions),
        )


ADAPTERS: dict[str, SchemeAdapter] = {
    adapter.scheme_id: adapter
    for adapter in (
        OriginalAgentDidAdapter(),
        BaselineAgentDidAdapter(),
        LineageAgentDidAdapter(),
    )
}


def get_adapter(scheme: str) -> SchemeAdapter:
    try:
        return ADAPTERS[scheme]
    except KeyError as exc:
        raise ValueError(f"unsupported scheme: {scheme}") from exc


def evaluate_scheme(bundle: ExperimentBundle) -> SchemeDecision:
    """Backward-compatible functional entry point used by ``run_one``."""

    return get_adapter(bundle.scheme).evaluate(bundle)
