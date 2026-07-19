import sys
import os
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = current_dir
while not os.path.exists(os.path.join(project_root, "infrastructure")):
    parent = os.path.dirname(project_root)
    if parent == project_root: break 
    project_root = parent
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import json
import time
import datetime
import traceback
import uuid
from flask import Flask, request, jsonify
from web3 import Web3
from eth_account.messages import encode_defunct

# === 1. Import Project Components ===
from infrastructure.load_config import load_key_config
from infrastructure.validator import DIDValidator
from infrastructure.security import SecurityAuditRecorder, canonical_json, sha256_json
from infrastructure.semantic_benchmark import (
    BENCHMARK_ID,
    DEFAULT_THRESHOLD,
    artifact_digest,
)
from _ops_services.status_list_service import BitstringStatusListRegistry

app = Flask(__name__)

# === 2. Initialize Configuration ===
config = load_key_config() 
accounts = config["accounts"]
issuer_info = accounts["issuer"]
w3 = Web3()
validator = DIDValidator()
REQUIRE_CAPABILITY_EVIDENCE = (
    os.getenv("AGENTDID_ISSUER_REQUIRE_CAPABILITY_EVIDENCE", "false").lower() == "true"
)
ENABLE_SEMANTIC_EXPERIMENTS = (
    os.getenv("AGENTDID_ENABLE_SEMANTIC_EXPERIMENTS", "false").lower() == "true"
)
ENABLE_EXPERIMENT_CONTROL = (
    os.getenv("AGENTDID_ENABLE_EXPERIMENT_CONTROL", "false").lower() == "true"
)
EXPERIMENT_CONTROL_TOKEN = os.getenv("AGENTDID_EXPERIMENT_CONTROL_TOKEN", "")
ISSUER_CLAIM_MODE = os.getenv("AGENTDID_ISSUER_CLAIM_MODE", "honest").strip().lower()
if ISSUER_CLAIM_MODE not in {"honest", "authorized_false_claim"}:
    raise ValueError(
        "AGENTDID_ISSUER_CLAIM_MODE must be honest or authorized_false_claim"
    )

ISSUER_DID = f"did:ethr:sepolia:{issuer_info['address']}"
ISSUER_PUBLIC_URL = os.getenv(
    "AGENTDID_ISSUER_PUBLIC_URL", "http://127.0.0.1:8000"
).rstrip("/")
STATUS_STORAGE_DIR = os.getenv(
    "AGENTDID_STATUS_LIST_DIR",
    os.path.join(project_root, ".codex", "issuer_status"),
)
ISSUER_AUDIT_FILE = os.getenv(
    "AGENTDID_ISSUER_AUDIT_FILE",
    os.path.join(project_root, ".codex", "semantic_gap", "issuer_audit.jsonl"),
)
issuer_audit = SecurityAuditRecorder(ISSUER_AUDIT_FILE)

CAPABILITY_URN = "urn:benchmark:integer-addition-v1"
DEFAULT_DATASET_HASH = "sha256:" + sha256_json(
    {"benchmarkId": BENCHMARK_ID, "inputCount": 100, "seed": 20260718}
)
DEFAULT_CORRECT_ARTIFACT_DIGEST = artifact_digest("correct")
DEFAULT_FAULTY_ARTIFACT_DIGEST = artifact_digest("faulty")

status_registry = BitstringStatusListRegistry(
    issuer_did=ISSUER_DID,
    public_base_url=ISSUER_PUBLIC_URL,
    storage_dir=STATUS_STORAGE_DIR,
)

# Template directory
SCHEMA_DIR = os.path.join(project_root, "vc_schemas")

print("="*60)
print(f"Issuer Server Started (Port: 8000)")
print(f"Issuer DID: {ISSUER_DID}")
print(f"Template Dir: {SCHEMA_DIR}")
print(f"Issuer Claim Mode: {ISSUER_CLAIM_MODE}")
print(f"Status List: {status_registry.credential_url}")
print("="*60)

# === 3. Core Utility Functions ===

def sign_vc(vc_payload, private_key):
    """Sort JSON and sign"""
    serialized_data = canonical_json(vc_payload)
    message = encode_defunct(text=serialized_data)
    signed_message = w3.eth.account.sign_message(message, private_key=private_key)
    return signed_message.signature.hex()

def get_iso_time(offset_days=0):
    dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=offset_days)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_sha256_identifier(value):
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value[7:]
    return len(digest) == 64 and all(char in "0123456789abcdefABCDEF" for char in digest)


def _as_score(value, field_name):
    try:
        score = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be numeric") from exc
    if not 0.0 <= score <= 1.0:
        raise ValueError(f"{field_name} must be between 0 and 1")
    return score


def _is_loopback_request():
    return request.remote_addr in {"127.0.0.1", "::1", None}


def _experiment_control_authorized():
    if not ENABLE_EXPERIMENT_CONTROL or not _is_loopback_request():
        return False
    if not EXPERIMENT_CONTROL_TOKEN:
        return True
    supplied = request.headers.get("X-AgentDID-Experiment-Token", "")
    if not supplied:
        authorization = request.headers.get("Authorization", "")
        if authorization.startswith("Bearer "):
            supplied = authorization[7:]
    return supplied == EXPERIMENT_CONTROL_TOKEN


def _extract_issuance_context(data):
    """Resolve a safe, signed experiment configuration for one issuance request."""

    raw = data.get("experimentConfig", data.get("experiment", {}))
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError("experimentConfig must be an object")

    requested_mode = str(raw.get("issuerClaimMode", ISSUER_CLAIM_MODE)).strip().lower()
    if requested_mode not in {"honest", "authorized_false_claim"}:
        raise ValueError("issuerClaimMode must be honest or authorized_false_claim")
    if (
        requested_mode == "authorized_false_claim"
        and requested_mode != ISSUER_CLAIM_MODE
        and not (ENABLE_SEMANTIC_EXPERIMENTS and _is_loopback_request())
    ):
        raise PermissionError(
            "request-level authorized_false_claim requires local semantic experiment mode"
        )

    default_profile = "faulty" if requested_mode == "authorized_false_claim" else "correct"
    artifact_profile = str(raw.get("artifactProfile", default_profile)).strip().lower()
    if artifact_profile not in {"correct", "faulty"}:
        raise ValueError("artifactProfile must be correct or faulty")
    if requested_mode == "authorized_false_claim":
        artifact_profile = "faulty"

    revoke_credential = bool(raw.get("revokeCredential", False))
    if revoke_credential and not (ENABLE_SEMANTIC_EXPERIMENTS and _is_loopback_request()):
        raise PermissionError(
            "request-level revocation requires local semantic experiment mode"
        )

    default_digest = (
        DEFAULT_FAULTY_ARTIFACT_DIGEST
        if artifact_profile == "faulty"
        else DEFAULT_CORRECT_ARTIFACT_DIGEST
    )
    artifact_digest = raw.get(
        "artifactDigest",
        os.getenv(
            "AGENTDID_FAULTY_ARTIFACT_DIGEST"
            if artifact_profile == "faulty"
            else "AGENTDID_CORRECT_ARTIFACT_DIGEST",
            default_digest,
        ),
    )
    dataset_hash = raw.get("datasetHash", DEFAULT_DATASET_HASH)
    if not _is_sha256_identifier(artifact_digest):
        raise ValueError("artifactDigest must be a full sha256 identifier")
    if not _is_sha256_identifier(dataset_hash):
        raise ValueError("datasetHash must be a full sha256 identifier")

    threshold = _as_score(raw.get("threshold", DEFAULT_THRESHOLD), "threshold")
    actual_score = 0.0 if artifact_profile == "faulty" else 1.0
    return {
        "caseId": str(raw.get("caseId", "unspecified")),
        "issuerClaimMode": requested_mode,
        "artifactProfile": artifact_profile,
        "artifactDigest": artifact_digest,
        "datasetHash": dataset_hash,
        "threshold": threshold,
        "actualScore": actual_score,
        "actualQualified": actual_score >= threshold,
        "revokeCredential": revoke_credential,
    }


def verify_capability_evidence(evidence, applicant_did):
    """Verify a benchmark report signed by an independently registered evaluator."""

    if not isinstance(evidence, dict):
        return False, "Capability evidence is missing"
    semantic_v2 = any(
        field in evidence
        for field in (
            "artifactDigest", "observedScore", "qualified", "outputsHash", "inputCount"
        )
    )
    if semantic_v2:
        required = {
            "benchmarkId", "artifactDigest", "datasetHash", "observedScore",
            "threshold", "qualified", "outputsHash", "inputCount", "evaluatedAt",
            "evaluatorDID", "evaluatedAgentDID", "signature",
        }
    else:
        # Backward-compatible validation for the original evidence API.
        required = {
            "evaluationRunId", "datasetHash", "ratingValue", "evaluatedAt",
            "reportHash", "evaluatorDID", "evaluatedAgentDID", "signature",
        }
    missing = sorted(required.difference(evidence))
    if missing:
        return False, f"Capability evidence missing fields: {', '.join(missing)}"
    if not _is_sha256_identifier(evidence["datasetHash"]):
        return False, "datasetHash must be a full sha256 identifier"
    if evidence["evaluatedAgentDID"] != applicant_did:
        return False, "Capability evidence subject does not match applicant"

    if semantic_v2:
        if evidence["benchmarkId"] != BENCHMARK_ID:
            return False, f"Unsupported benchmarkId: {evidence['benchmarkId']}"
        if not _is_sha256_identifier(evidence["artifactDigest"]):
            return False, "artifactDigest must be a full sha256 identifier"
        if not _is_sha256_identifier(evidence["outputsHash"]):
            return False, "outputsHash must be a full sha256 identifier"
        try:
            observed_score = _as_score(evidence["observedScore"], "observedScore")
            threshold = _as_score(evidence["threshold"], "threshold")
        except ValueError as exc:
            return False, str(exc)
        if not isinstance(evidence["qualified"], bool):
            return False, "qualified must be a boolean"
        if evidence["qualified"] != (observed_score >= threshold):
            return False, "qualified is inconsistent with observedScore and threshold"
        input_count = evidence["inputCount"]
        if (
            not isinstance(input_count, int)
            or isinstance(input_count, bool)
            or input_count <= 0
        ):
            return False, "inputCount must be a positive integer"
    elif not _is_sha256_identifier(evidence["reportHash"]):
        return False, "reportHash must be a full sha256 identifier"

    evidence_body = dict(evidence)
    evidence_signature = evidence_body.pop("signature")
    return validator.verify_request_signature(
        canonical_json(evidence_body), evidence_signature, evidence["evaluatorDID"]
    )


def _default_issuance_context():
    profile = "faulty" if ISSUER_CLAIM_MODE == "authorized_false_claim" else "correct"
    score = 0.0 if profile == "faulty" else 1.0
    return {
        "caseId": "unspecified",
        "issuerClaimMode": ISSUER_CLAIM_MODE,
        "artifactProfile": profile,
        "artifactDigest": (
            DEFAULT_FAULTY_ARTIFACT_DIGEST
            if profile == "faulty"
            else DEFAULT_CORRECT_ARTIFACT_DIGEST
        ),
        "datasetHash": DEFAULT_DATASET_HASH,
        "threshold": DEFAULT_THRESHOLD,
        "actualScore": score,
        "actualQualified": score >= DEFAULT_THRESHOLD,
        "revokeCredential": False,
    }


def _build_capability_claim(capability_evidence, issuance_context):
    context = issuance_context or _default_issuance_context()
    mode = context["issuerClaimMode"]
    evidence_is_semantic = bool(
        capability_evidence and "observedScore" in capability_evidence
    )

    if mode == "authorized_false_claim":
        claimed_score = 0.99
        qualified = True
        artifact_value = context["artifactDigest"]
        dataset_hash = context["datasetHash"]
    elif evidence_is_semantic:
        claimed_score = _as_score(
            capability_evidence["observedScore"], "observedScore"
        )
        qualified = bool(capability_evidence["qualified"])
        artifact_value = capability_evidence["artifactDigest"]
        dataset_hash = capability_evidence["datasetHash"]
    elif capability_evidence:
        # Preserve the original evidence wire format while emitting the new,
        # explicit semantic claim fields.
        claimed_score = _as_score(capability_evidence["ratingValue"], "ratingValue")
        qualified = claimed_score >= context["threshold"]
        artifact_value = context["artifactDigest"]
        dataset_hash = capability_evidence["datasetHash"]
    else:
        claimed_score = float(context["actualScore"])
        qualified = bool(context["actualQualified"])
        artifact_value = context["artifactDigest"]
        dataset_hash = context["datasetHash"]

    claim = {
        "benchmarkId": BENCHMARK_ID,
        "capability": CAPABILITY_URN,
        "claimedScore": round(claimed_score, 6),
        "threshold": round(float(context["threshold"]), 6),
        "qualified": qualified,
        "artifactDigest": artifact_value,
        "datasetHash": dataset_hash,
    }
    return claim


def _record_capability_issuance(applicant_did, final_vc, issuance_context):
    subject = final_vc["credentialSubject"]
    claimed_score = float(subject["claimedScore"])
    threshold = float(subject["threshold"])
    claimed_qualified = bool(subject["qualified"])
    actual_score = float(issuance_context["actualScore"])
    actual_qualified = bool(issuance_context["actualQualified"])
    semantic_truth = (
        claimed_qualified == actual_qualified
        and abs(claimed_score - actual_score) < 1e-12
    )
    issuer_audit.record(
        "issuer_capability_attestation",
        applicant_did,
        {
            "caseId": issuance_context["caseId"],
            "artifactProfile": issuance_context["artifactProfile"],
            "artifactDigest": issuance_context["artifactDigest"],
        },
        final_vc,
        True,
        "Issuer signed capability credential",
        case_id=issuance_context["caseId"],
        issuer_claim_mode=issuance_context["issuerClaimMode"],
        artifact_profile=issuance_context["artifactProfile"],
        artifact_digest=issuance_context["artifactDigest"],
        claimed_score=claimed_score,
        actual_score=actual_score,
        threshold=threshold,
        claimed_qualified=claimed_qualified,
        actual_qualified=actual_qualified,
        semantic_truth=semantic_truth,
        vc_signature_present=bool(final_vc.get("proof", {}).get("jws")),
        status_list_index=final_vc.get("credentialStatus", {}).get("statusListIndex"),
    )


def process_single_template(
    template_data,
    applicant_did,
    capability_evidence=None,
    issuance_context=None,
):
    """
    Process single template data: Replace ID -> Supplement info -> Sign
    """

    vc_payload = json.loads(json.dumps(template_data))

    # 1. Replace ID
    if "credentialSubject" in vc_payload:
        vc_payload["credentialSubject"]["id"] = applicant_did
    else:
        vc_payload["credentialSubject"] = {"id": applicant_did}

    issuance_context = issuance_context or _default_issuance_context()
    vc_types = vc_payload.get("type", [])
    if "AgentCapabilityCredential" in vc_types:
        capability_claim = _build_capability_claim(
            capability_evidence, issuance_context
        )
        vc_payload["credentialSubject"].update(capability_claim)
        # Keep the legacy rating path readable for existing demos, but mirror
        # only normal credential data.  Attack-mode metadata is audit-only.
        vc_payload["credentialSubject"]["evaluation"] = {
            "@type": "Rating",
            "ratingSystem": BENCHMARK_ID,
            "ratingValue": f"{capability_claim['claimedScore']:.3f}",
            "bestRating": "1.000",
            "datasetHash": capability_claim["datasetHash"],
        }
        if capability_evidence:
            vc_payload["credentialSubject"]["evaluation"].update({
                "evaluatedAt": capability_evidence["evaluatedAt"],
                "evaluatorDID": capability_evidence["evaluatorDID"],
                "evidenceHash": f"sha256:{sha256_json(capability_evidence)}",
            })

    # 2. Fill in Issuer and Time info
    issuer_did = ISSUER_DID
    vc_payload["issuer"] = issuer_did
    vc_payload["id"] = f"urn:uuid:{uuid.uuid4()}"
    status_entry = status_registry.allocate()
    vc_payload["credentialStatus"] = status_entry.as_credential_status()
    
    # Auto-generate validity period if not in template
    if "validFrom" not in vc_payload:
        vc_payload["validFrom"] = get_iso_time(0)
    if "validUntil" not in vc_payload:
        vc_payload["validUntil"] = get_iso_time(365)

    # 3. Sign
    signature = sign_vc(vc_payload, issuer_info["private_key"])

    # 4. Wrap Proof
    final_vc = vc_payload.copy()
    final_vc["proof"] = {
        "type": "EcdsaSecp256k1Signature2019",
        "created": get_iso_time(0),
        "proofPurpose": "assertionMethod",
        "verificationMethod": f"{issuer_did}#controller",
        "jws": signature
    }

    if "AgentCapabilityCredential" in vc_types:
        _record_capability_issuance(applicant_did, final_vc, issuance_context)

    return final_vc

def generate_all_vcs(applicant_did, capability_evidence=None, issuance_context=None):
    """
    Traverse vc_schemas directory, issue all VCs defined in templates for applicant
    """
    issued_vcs = []
    
    if not os.path.exists(SCHEMA_DIR):
        print(f"[Error] Schema dir not found: {SCHEMA_DIR}")
        return []

    # Get all JSON files and sort
    files = sorted([f for f in os.listdir(SCHEMA_DIR) if f.endswith(".json")])
    
    print(f"    [Process] Found {len(files)} templates. Processing...")

    for filename in files:
        file_path = os.path.join(SCHEMA_DIR, filename)
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                template = json.load(f)

            vc_types = template.get("type", [])
            if (
                REQUIRE_CAPABILITY_EVIDENCE
                and "AgentCapabilityCredential" in vc_types
                and not capability_evidence
            ):
                print(f"      - Skipped: {filename} -> missing verified capability evidence")
                continue

            # Process single template
            vc = process_single_template(
                template,
                applicant_did,
                capability_evidence,
                issuance_context,
            )
            issued_vcs.append(vc)

            vc_json_str = json.dumps(vc)
            vc_size_bytes = len(vc_json_str)
            vc_size_kb = vc_size_bytes / 1024
            
            vc_type = template.get("type", ["Unknown"])[-1]
            print(f"      - Issued: {filename} -> {vc_type} | Size: {vc_size_bytes} bytes ({vc_size_kb:.2f} KB)")
            
        except Exception as e:
            print(f"      - Error processing {filename}: {e}")

    return issued_vcs

# === 4. API Definitions ===

@app.route('/issue_vc', methods=['POST'])
def handle_issue_vc():
    """
    Receive application -> Verify signature -> Simulate delay -> Batch issuance
    """
    try:
        data = request.json
        applicant_did = data.get('applicant')
        signature = data.get('signature')
        
        print(f"\n>>> [Request] VC Application from: {applicant_did}")

        # --- A. Verify Identity ---
        if not applicant_did or not signature:
            return jsonify({"error": "Missing applicant or signature"}), 400
        
        # Reconstruct original message for signature verification
        payload_copy = data.copy()
        if 'signature' in payload_copy: del payload_copy['signature']
        serialized_payload = canonical_json(payload_copy)
        
        # Verify: Signer must be the legitimate controller of applicant DID
        is_valid, reason = validator.verify_request_signature(serialized_payload, signature, applicant_did)
        
        if not is_valid:
            print(f"    [Auth Fail] {reason}")
            return jsonify({"error": f"Signature verification failed: {reason}"}), 401

        print("    [Auth Success] Signature Verified")

        capability_evidence = data.get("capabilityEvidence")
        evidence_valid = False
        evidence_reason = "Capability evidence not supplied"
        if capability_evidence is not None:
            evidence_valid, evidence_reason = verify_capability_evidence(
                capability_evidence, applicant_did
            )

        if REQUIRE_CAPABILITY_EVIDENCE and not evidence_valid:
            print(f"    [Capability] Credential will be skipped: {evidence_reason}")

        # --- B. Simulate Approval ---
        # Sleep for 2 seconds and print
        time.sleep(2)
        print("    [Process] Assuming applicant identity attributes verified, issuing VCs...")

        # --- C. Batch Issue All Certificates ---
        vc_list = generate_all_vcs(
            applicant_did,
            capability_evidence if evidence_valid else None,
        )
        
        print(f"    [Issued] Successfully issued {len(vc_list)} VCs to {applicant_did}")
        
        # Return list
        return jsonify(vc_list)

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000, threaded=True)
