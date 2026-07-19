"""Self-contained semantic-soundness experiment built on AgentDID keys.

The experiment is intentionally safe: the only downstream action is integer
addition in a local simulator.  Private keys are used for signing but are never
written to the evidence bundle.
"""

from __future__ import annotations

import base64
import copy
import datetime as dt
import gzip
import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from eth_account import Account
from eth_account.messages import encode_defunct

from infrastructure.load_config import load_key_config
from infrastructure.security import canonical_json
from infrastructure.semantic_benchmark import (
    BENCHMARK_ID,
    DEFAULT_THRESHOLD,
    artifact_digest,
    benchmark_inputs,
    evaluate,
    execute,
    sha256_json,
)


STATUS_BYTES = 16_384
STATUS_INDEX = 42
VP_PROOF_VERSION = "agentdid-v2"


def utc_iso(offset_seconds: int = 0) -> str:
    value = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=offset_seconds)
    return value.isoformat().replace("+00:00", "Z")


def did(address: str) -> str:
    return f"did:ethr:sepolia:{address}"


def sign_json(body: dict[str, Any], private_key: str) -> str:
    signed = Account.sign_message(
        encode_defunct(text=canonical_json(body)), private_key=private_key
    )
    return signed.signature.hex()


def recover_json(body: dict[str, Any], signature: str) -> str:
    return Account.recover_message(
        encode_defunct(text=canonical_json(body)), signature=signature
    )


def make_did_document(
    controller_address: str,
    *,
    authentication_address: str | None = None,
    assertion_address: str | None = None,
) -> dict[str, Any]:
    controller_did = did(controller_address)
    methods: list[dict[str, str]] = []
    relationships: dict[str, list[str]] = {}
    controller_id = f"{controller_did}#controller"
    methods.append({
        "id": controller_id,
        "type": "EcdsaSecp256k1RecoveryMethod2020",
        "controller": controller_did,
        "blockchainAccountId": f"eip155:11155111:{controller_address}",
    })
    if assertion_address:
        assertion_id = controller_id if assertion_address.lower() == controller_address.lower() else f"{controller_did}#assertion"
        if assertion_id != controller_id:
            methods.append({
                "id": assertion_id,
                "type": "EcdsaSecp256k1RecoveryMethod2020",
                "controller": controller_did,
                "blockchainAccountId": f"eip155:11155111:{assertion_address}",
            })
        relationships["assertionMethod"] = [assertion_id]
    if authentication_address:
        authentication_id = controller_id if authentication_address.lower() == controller_address.lower() else f"{controller_did}#delegate"
        if authentication_id != controller_id:
            methods.append({
                "id": authentication_id,
                "type": "EcdsaSecp256k1RecoveryMethod2020",
                "controller": controller_did,
                "blockchainAccountId": f"eip155:11155111:{authentication_address}",
            })
        relationships["authentication"] = [authentication_id]
    return {"id": controller_did, "verificationMethod": methods, **relationships}


def relationship_addresses(document: dict[str, Any], relationship: str) -> set[str]:
    methods = {method.get("id"): method for method in document.get("verificationMethod", [])}
    result: set[str] = set()
    for entry in document.get(relationship, []):
        method = methods.get(entry) if isinstance(entry, str) else entry
        if not isinstance(method, dict):
            continue
        account_id = method.get("blockchainAccountId", "")
        if account_id:
            result.add(account_id.split(":")[-1].lower())
    return result


def verify_relationship_signature(
    document: dict[str, Any], relationship: str, body: dict[str, Any], signature: str
) -> bool:
    try:
        recovered = recover_json(body, signature).lower()
    except Exception:
        return False
    return recovered in relationship_addresses(document, relationship)


def _status_bytes(revoked: bool) -> bytes:
    values = bytearray(STATUS_BYTES)
    if revoked:
        values[STATUS_INDEX // 8] |= 1 << (STATUS_INDEX % 8)
    return bytes(values)


def _encode_status(revoked: bool) -> str:
    compressed = gzip.compress(_status_bytes(revoked), mtime=0)
    return base64.urlsafe_b64encode(compressed).decode("ascii").rstrip("=")


def _decode_status(encoded: str, index: int) -> bool:
    padded = encoded + "=" * (-len(encoded) % 4)
    values = gzip.decompress(base64.urlsafe_b64decode(padded))
    return bool(values[index // 8] & (1 << (index % 8)))


def issue_status_list(issuer: "Actor", revoked: bool) -> dict[str, Any]:
    body = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": "https://agentdid.local/status/semantic-gap-v1",
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "issuer": issuer.did,
        "validFrom": utc_iso(-60),
        "credentialSubject": {
            "id": "https://agentdid.local/status/semantic-gap-v1#list",
            "type": "BitstringStatusList",
            "statusPurpose": "revocation",
            "encodedList": _encode_status(revoked),
        },
    }
    return with_proof(body, issuer, "assertionMethod")


def with_proof(body: dict[str, Any], signer: "Actor", purpose: str) -> dict[str, Any]:
    result = copy.deepcopy(body)
    result["proof"] = {
        "type": "EcdsaSecp256k1RecoverySignature2020",
        "created": utc_iso(),
        "proofPurpose": purpose,
        "verificationMethod": f"{signer.did}#controller",
        "jws": sign_json(body, signer.private_key),
    }
    return result


@dataclass(frozen=True)
class Actor:
    role: str
    did: str
    private_key: str
    address: str


@dataclass(frozen=True)
class CaseSpec:
    case_id: str
    artifact_profile: str
    claimed_profile: str
    claimed_score: float
    issuer_mode: str = "trusted"
    revoked: bool = False
    nonce_mode: str = "valid"
    mutate_vc: bool = False
    verifier_policy: str = "crypto_only"
    state_mode: str = "honest_state"
    mutate_state: bool = False
    expected: str = ""


CASE_SPECS = {
    "C0": CaseSpec("C0", "correct", "correct", 1.0, expected="accepted_correctly"),
    "C1": CaseSpec("C1", "faulty", "faulty", 0.99, expected="semantic_false_acceptance"),
    "C2": CaseSpec("C2", "faulty", "faulty", 0.99, revoked=True, expected="cryptographically_rejected"),
    "C3": CaseSpec("C3", "faulty", "faulty", 0.99, nonce_mode="wrong", expected="cryptographically_rejected"),
    "C4": CaseSpec("C4", "faulty", "faulty", 0.25, mutate_vc=True, expected="cryptographically_rejected"),
    "C5": CaseSpec("C5", "faulty", "faulty", 0.99, issuer_mode="wrong_relationship", expected="cryptographically_rejected"),
    "C6": CaseSpec("C6", "faulty", "faulty", 0.99, issuer_mode="untrusted", expected="cryptographically_rejected"),
    "C7": CaseSpec("C7", "faulty", "faulty", 0.99, verifier_policy="semantic_evidence", expected="semantically_rejected"),
    "H0": CaseSpec("H0", "correct", "correct", 1.0, expected="accepted_correctly"),
    "H1": CaseSpec("H1", "faulty", "correct", 1.0, state_mode="signed_false_state", expected="signed_false_state_wrong_action"),
    "H2": CaseSpec("H2", "faulty", "correct", 1.0, state_mode="signed_false_state", mutate_state=True, expected="cryptographically_rejected"),
    "H3": CaseSpec("H3", "faulty", "correct", 1.0, state_mode="signed_false_state", verifier_policy="state_cross_check", expected="state_cross_check_rejected"),
}


def load_actors() -> tuple[dict[str, Actor], dict[str, dict[str, Any]]]:
    accounts = load_key_config()["accounts"]

    def direct(role: str) -> Actor:
        item = accounts[role]
        return Actor(role, did(item["address"]), item["private_key"], item["address"])

    issuer = direct("issuer")
    untrusted = direct("agent_b_admin")
    wrong = direct("agent_c_op")
    holder_admin = accounts["agent_a_admin"]
    holder_op = accounts["agent_a_op"]
    holder = Actor(
        "agent_a_op", did(holder_admin["address"]), holder_op["private_key"], holder_op["address"]
    )
    verifier_admin = accounts["agent_c_admin"]
    verifier_op = accounts["agent_c_op"]
    verifier = Actor(
        "agent_c_op", did(verifier_admin["address"]), verifier_op["private_key"], verifier_op["address"]
    )
    evaluator_admin = accounts["agent_d_admin"]
    evaluator_op = accounts["agent_d_op"]
    evaluator = Actor(
        "agent_d_op", did(evaluator_admin["address"]), evaluator_op["private_key"], evaluator_op["address"]
    )
    actors = {
        "issuer": issuer,
        "untrusted": untrusted,
        "wrong": wrong,
        "holder": holder,
        "verifier": verifier,
        "evaluator": evaluator,
    }
    docs = {
        issuer.did: make_did_document(issuer.address, assertion_address=issuer.address),
        untrusted.did: make_did_document(untrusted.address, assertion_address=untrusted.address),
        holder.did: make_did_document(holder_admin["address"], authentication_address=holder.address),
        verifier.did: make_did_document(verifier_admin["address"], authentication_address=verifier.address),
        evaluator.did: make_did_document(evaluator_admin["address"], authentication_address=evaluator.address),
    }
    return actors, docs


def issue_credential(
    spec: CaseSpec, holder: Actor, issuer: Actor, signing_actor: Actor
) -> dict[str, Any]:
    body = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": f"urn:uuid:{uuid.uuid4()}",
        "type": ["VerifiableCredential", "AgentCapabilityCredential"],
        "issuer": issuer.did,
        "validFrom": utc_iso(-60),
        "validUntil": utc_iso(86_400),
        "credentialSubject": {
            "id": holder.did,
            "evaluation": {
                "benchmarkId": BENCHMARK_ID,
                "capability": f"urn:benchmark:{BENCHMARK_ID}",
                "claimedScore": spec.claimed_score,
                "threshold": DEFAULT_THRESHOLD,
                "qualified": spec.claimed_score >= DEFAULT_THRESHOLD,
                "artifactDigest": artifact_digest(spec.claimed_profile),
                "datasetHash": sha256_json(benchmark_inputs()),
            },
        },
        "credentialStatus": {
            "id": f"https://agentdid.local/status/semantic-gap-v1#{STATUS_INDEX}",
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": str(STATUS_INDEX),
            "statusListCredential": "https://agentdid.local/status/semantic-gap-v1",
        },
    }
    return with_proof(body, signing_actor, "assertionMethod")


def create_presentation(
    credential: dict[str, Any], holder: Actor, challenge: str, audience: str
) -> dict[str, Any]:
    presentation = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiablePresentation"],
        "holder": holder.did,
        "verifiableCredential": [credential],
    }
    options = {
        "version": VP_PROOF_VERSION,
        "type": "EcdsaSecp256k1RecoverySignature2020",
        "created": utc_iso(),
        "verificationMethod": f"{holder.did}#delegate",
        "proofPurpose": "authentication",
        "challenge": challenge,
        "audience": audience,
    }
    result = copy.deepcopy(presentation)
    result["proof"] = {**options, "jws": sign_json({"presentation": presentation, "proofOptions": options}, holder.private_key)}
    return result


def create_state(
    spec: CaseSpec, holder: Actor, audience: str, nonce: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    actual = {
        "artifactDigest": artifact_digest(spec.artifact_profile),
        "ready": spec.artifact_profile == "correct",
        "stateVersion": 3,
    }
    reported = copy.deepcopy(actual)
    if spec.state_mode == "signed_false_state":
        reported = {
            "artifactDigest": artifact_digest("correct"),
            "ready": True,
            "stateVersion": 3,
        }
    body = {
        "holder_did": holder.did,
        "audience": audience,
        "nonce": nonce,
        "timestamp": time.time(),
        "state": reported,
    }
    result = {**body, "signature": sign_json(body, holder.private_key)}
    if spec.mutate_state:
        result["state"]["stateVersion"] = 99
    return result, actual


def create_evaluator_report(spec: CaseSpec, evaluator: Actor) -> tuple[dict[str, Any], Any]:
    result = evaluate(spec.artifact_profile)
    body = {
        **result.report(),
        "evaluationRunId": f"eval-{uuid.uuid4()}",
        "evaluatorDID": evaluator.did,
        "evaluatedAt": utc_iso(),
    }
    return {**body, "signature": sign_json(body, evaluator.private_key)}, result


def verify_case(
    spec: CaseSpec,
    credential: dict[str, Any],
    presentation: dict[str, Any],
    status_list: dict[str, Any],
    state: dict[str, Any],
    actual_state: dict[str, Any],
    evaluator_report: dict[str, Any],
    request: dict[str, Any],
    actors: dict[str, Actor],
    docs: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    trace: dict[str, Any] = {}
    trusted_issuer = actors["issuer"].did

    # Credential checks.
    issuer_did = credential.get("issuer", "")
    vc_body = copy.deepcopy(credential)
    vc_proof = vc_body.pop("proof", {})
    trace["issuerTrusted"] = issuer_did == trusted_issuer
    trace["issuerAssertionSignatureValid"] = bool(
        issuer_did in docs
        and verify_relationship_signature(
            docs[issuer_did], "assertionMethod", vc_body, vc_proof.get("jws", "")
        )
    )
    now = dt.datetime.now(dt.timezone.utc)
    trace["timeValid"] = (
        dt.datetime.fromisoformat(credential["validFrom"].replace("Z", "+00:00")) <= now
        <= dt.datetime.fromisoformat(credential["validUntil"].replace("Z", "+00:00"))
    )
    trace["subjectHolderBound"] = credential.get("credentialSubject", {}).get("id") == actors["holder"].did

    status_body = copy.deepcopy(status_list)
    status_proof = status_body.pop("proof", {})
    status_issuer = status_list.get("issuer", "")
    trace["statusSignatureValid"] = bool(
        status_issuer in docs
        and verify_relationship_signature(
            docs[status_issuer], "assertionMethod", status_body, status_proof.get("jws", "")
        )
    )
    trace["notRevoked"] = not _decode_status(
        status_list["credentialSubject"]["encodedList"],
        int(credential["credentialStatus"]["statusListIndex"]),
    )

    # VP v2 binds presentation and all proof options.
    proof = presentation.get("proof", {})
    presented_body = copy.deepcopy(presentation)
    presented_body.pop("proof", None)
    proof_options = copy.deepcopy(proof)
    proof_options.pop("jws", None)
    holder_doc = docs[actors["holder"].did]
    trace["holderAuthenticationSignatureValid"] = verify_relationship_signature(
        holder_doc,
        "authentication",
        {"presentation": presented_body, "proofOptions": proof_options},
        proof.get("jws", ""),
    )
    trace["vpVersionValid"] = proof.get("version") == VP_PROOF_VERSION
    trace["nonceValid"] = proof.get("challenge") == request["nonce"]
    trace["audienceValid"] = proof.get("audience") == request["audience"]

    # Holder state checks.
    state_body = copy.deepcopy(state)
    state_signature = state_body.pop("signature", "")
    trace["stateSignatureValid"] = verify_relationship_signature(
        holder_doc, "authentication", state_body, state_signature
    )
    trace["stateNonceValid"] = state.get("nonce") == request["stateNonce"]
    trace["stateAudienceValid"] = state.get("audience") == request["audience"]
    trace["stateFresh"] = abs(time.time() - float(state.get("timestamp", 0))) <= 120

    crypto_fields = [
        "issuerTrusted", "issuerAssertionSignatureValid", "timeValid",
        "subjectHolderBound", "statusSignatureValid", "notRevoked",
        "holderAuthenticationSignatureValid", "vpVersionValid", "nonceValid",
        "audienceValid", "stateSignatureValid", "stateNonceValid",
        "stateAudienceValid", "stateFresh",
    ]
    trace["cryptoOK"] = all(trace[field] for field in crypto_fields)

    evaluation = credential.get("credentialSubject", {}).get("evaluation", {})
    report_body = copy.deepcopy(evaluator_report)
    report_signature = report_body.pop("signature", "")
    evaluator_doc = docs[actors["evaluator"].did]
    trace["evaluatorSignatureValid"] = verify_relationship_signature(
        evaluator_doc, "authentication", report_body, report_signature
    )
    trace["evaluatorArtifactBound"] = evaluator_report.get("artifactDigest") == evaluation.get("artifactDigest")
    trace["evaluatorQualified"] = bool(evaluator_report.get("qualified"))
    trace["stateArtifactMatchesCredential"] = state.get("state", {}).get("artifactDigest") == evaluation.get("artifactDigest")
    trace["stateMatchesActualArtifact"] = state.get("state", {}).get("artifactDigest") == actual_state.get("artifactDigest")

    accepted = trace["cryptoOK"] and bool(evaluation.get("qualified")) and bool(state.get("state", {}).get("ready")) and trace["stateArtifactMatchesCredential"]
    rejection_layer = "crypto" if not trace["cryptoOK"] else "policy"
    if accepted and spec.verifier_policy == "semantic_evidence":
        accepted = (
            trace["evaluatorSignatureValid"]
            and trace["evaluatorArtifactBound"]
            and trace["evaluatorQualified"]
        )
        if not accepted:
            rejection_layer = "semantic_evidence"
    if accepted and spec.verifier_policy == "state_cross_check":
        accepted = trace["stateMatchesActualArtifact"]
        if not accepted:
            rejection_layer = "state_cross_check"
    trace["accepted"] = accepted
    trace["rejectionLayer"] = None if accepted else rejection_layer
    return trace


def deterministic_decision(accepted: bool) -> dict[str, Any]:
    return {
        "engine": "deterministic",
        "decision": "EXECUTE_INTEGER_ADDITION" if accepted else "REJECT_TASK",
        "reason": "verified policy conditions satisfied" if accepted else "verification or policy condition failed",
    }


def operation_results(profile: str, execute_action: bool, count: int = 20) -> dict[str, Any]:
    cases = benchmark_inputs(count)
    outputs = []
    for case in cases if execute_action else []:
        actual = execute(profile, case["a"], case["b"])
        expected = case["a"] + case["b"]
        outputs.append({**case, "expected": expected, "actual": actual, "correct": actual == expected})
    wrong = bool(outputs) and any(not item["correct"] for item in outputs)
    return {
        "actionExecuted": bool(execute_action),
        "action": "EXECUTE_INTEGER_ADDITION" if execute_action else "REJECT_TASK",
        "inputCount": len(outputs),
        "outputs": outputs,
        "wrongAction": wrong,
        "result": "FAILED_INCORRECT_OUTPUT" if wrong else ("SUCCESS" if outputs else "NOT_EXECUTED"),
    }


def classify_case(
    spec: CaseSpec, trace: dict[str, Any], ground_truth_qualified: bool,
    operation: dict[str, Any]
) -> str:
    if spec.case_id in {"C0", "H0"} and trace["accepted"] and ground_truth_qualified and not operation["wrongAction"]:
        return "accepted_correctly"
    if spec.case_id == "C1" and trace["accepted"] and not ground_truth_qualified and operation["wrongAction"]:
        return "semantic_false_acceptance"
    if spec.case_id == "C7" and not trace["accepted"] and trace["rejectionLayer"] == "semantic_evidence":
        return "semantically_rejected"
    if spec.case_id == "H1" and trace["accepted"] and not trace["stateMatchesActualArtifact"] and operation["wrongAction"]:
        return "signed_false_state_wrong_action"
    if spec.case_id == "H3" and not trace["accepted"] and trace["rejectionLayer"] == "state_cross_check":
        return "state_cross_check_rejected"
    if spec.case_id in {"C2", "C3", "C4", "C5", "C6", "H2"} and not trace["accepted"]:
        return "cryptographically_rejected"
    return "unexpected"


def run_case(case_id: str, workload_cases: int = 20) -> dict[str, Any]:
    spec = CASE_SPECS[case_id]
    actors, docs = load_actors()
    issuer_actor = actors["untrusted"] if spec.issuer_mode == "untrusted" else actors["issuer"]
    signing_actor = actors["wrong"] if spec.issuer_mode == "wrong_relationship" else issuer_actor
    status_list = issue_status_list(issuer_actor, spec.revoked)
    credential = issue_credential(spec, actors["holder"], issuer_actor, signing_actor)
    if spec.mutate_vc:
        credential["credentialSubject"]["evaluation"]["claimedScore"] = 0.99
        credential["credentialSubject"]["evaluation"]["qualified"] = True

    request = {
        "type": "SemanticQualificationRequest",
        "nonce": str(uuid.uuid4()),
        "stateNonce": str(uuid.uuid4()),
        "audience": actors["verifier"].did,
        "created": utc_iso(),
    }
    challenge = str(uuid.uuid4()) if spec.nonce_mode == "wrong" else request["nonce"]
    presentation = create_presentation(
        credential, actors["holder"], challenge, request["audience"]
    )
    state, actual_state = create_state(
        spec, actors["holder"], request["audience"], request["stateNonce"]
    )
    evaluator_report, benchmark = create_evaluator_report(spec, actors["evaluator"])
    trace = verify_case(
        spec, credential, presentation, status_list, state, actual_state,
        evaluator_report, request, actors, docs,
    )
    decision = deterministic_decision(trace["accepted"])
    operation = operation_results(
        spec.artifact_profile,
        decision["decision"] == "EXECUTE_INTEGER_ADDITION",
        workload_cases,
    )
    classification = classify_case(spec, trace, benchmark.qualified, operation)
    counterfactual_execute = bool(benchmark.qualified) and actual_state["ready"]
    case_result = {
        "caseId": case_id,
        "expected": spec.expected,
        "classification": classification,
        "passed": classification == spec.expected,
        "baselineAccepted": trace["accepted"],
        "cryptoOK": trace["cryptoOK"],
        "groundTruthQualified": benchmark.qualified,
        "semanticFalseAcceptance": trace["accepted"] and not benchmark.qualified,
        "signedFalseStateAcceptance": trace["accepted"] and not trace["stateMatchesActualArtifact"],
        "wrongAction": operation["wrongAction"],
        "counterfactualActionFlip": trace["accepted"] != counterfactual_execute,
        "claimedObservedGap": round(float(spec.claimed_score) - benchmark.observed_score, 6),
        "verifierPolicy": spec.verifier_policy,
        "observedAt": utc_iso(),
    }
    return {
        "spec": spec,
        "actors": actors,
        "did_documents": docs,
        "credential": credential,
        "presentation": presentation,
        "status_list": status_list,
        "request": request,
        "trace": trace,
        "artifact_manifest": {
            "benchmarkId": BENCHMARK_ID,
            "profile": spec.artifact_profile,
            "artifactDigest": artifact_digest(spec.artifact_profile),
        },
        "benchmark_inputs": benchmark_inputs(),
        "benchmark_outputs": benchmark.outputs,
        "ground_truth": {
            **benchmark.report(),
            "actualState": actual_state,
        },
        "evaluator_report": evaluator_report,
        "state": state,
        "decision": decision,
        "operation": operation,
        "case_result": case_result,
    }


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def merkle_root(hex_hashes: list[str]) -> str:
    if not hex_hashes:
        return hashlib.sha256(b"").hexdigest()
    level = [bytes.fromhex(value) for value in hex_hashes]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(level[index] + level[index + 1]).digest()
            for index in range(0, len(level), 2)
        ]
    return level[0].hex()


def public_did_documents(result: dict[str, Any]) -> dict[str, Any]:
    return result["did_documents"]


def serializable_case_files(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "issuer-did-document.json": result["did_documents"][result["actors"]["issuer"].did],
        "holder-did-document.json": result["did_documents"][result["actors"]["holder"].did],
        "credential.json": result["credential"],
        "presentation.json": result["presentation"],
        "status-list.json": result["status_list"],
        "verifier-request.json": result["request"],
        "verifier-check-trace.json": result["trace"],
        "artifact-manifest.json": result["artifact_manifest"],
        "benchmark-inputs.json": result["benchmark_inputs"],
        "benchmark-outputs.json": result["benchmark_outputs"],
        "ground-truth-result.json": result["ground_truth"],
        "evaluator-report.json": result["evaluator_report"],
        "holder-state.json": result["state"],
        "agent-decision.json": result["decision"],
        "operation-results.json": result["operation"],
        "case-result.json": result["case_result"],
    }


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")


def write_case_bundle(directory: Path, result: dict[str, Any]) -> dict[str, Any]:
    directory.mkdir(parents=True, exist_ok=True)
    files = serializable_case_files(result)
    for name, value in files.items():
        write_json(directory / name, value)
    hashes = {name: file_sha256(directory / name) for name in sorted(files)}
    manifest = {
        "schemaVersion": "agentdid-semantic-gap-v1",
        "caseId": result["case_result"]["caseId"],
        "files": hashes,
        "merkleRoot": merkle_root(list(hashes.values())),
    }
    write_json(directory / "manifest.json", manifest)
    return manifest
