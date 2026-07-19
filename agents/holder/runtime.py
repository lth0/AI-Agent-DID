import sys
import os
import json
import hashlib
import datetime
import time
import traceback
import uuid
import requests
import re
from flask import Flask, request, jsonify

# === Path Setup ===
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(os.path.dirname(current_dir))
if root_dir not in sys.path:
    sys.path.append(root_dir)

# === Import Infrastructure and Agent ===
from infrastructure.wallet import IdentityWallet
from infrastructure.validator import DIDValidator
from infrastructure.security import (
    ReplayGuard,
    SecurityAuditRecorder,
    canonical_json,
)
from agents.holder.definition import create_holder_agent
from agents.holder.attack_profiles import AttackInjector, AttackProfile

app = Flask(__name__)

# === 1. Initialize Runtime Components ===

DATA_DIR = os.getenv("AGENTDID_DATA_DIR", os.path.join(current_dir, "data"))
os.makedirs(DATA_DIR, exist_ok=True)

# === Global Variables Placeholder ===
# Actual initialization decided in __main__ based on args, or default loaded at import
wallet = None
validator = DIDValidator()
agent_app = None
ROLE_NAME = "agent_a_op" # Default value
ATTACK_PROFILE = AttackProfile.from_environment()
ATTACK_INJECTOR = AttackInjector(ATTACK_PROFILE)
REQUEST_REPLAY_GUARD = ReplayGuard(ttl_seconds=600)
ALLOW_UNSAFE_RESET = os.getenv("AGENTDID_ALLOW_UNSAFE_RESET", "false").lower() == "true"
DETERMINISTIC_MODE = os.getenv("AGENTDID_DETERMINISTIC_MODE", "false").lower() == "true"
AUDIT_RECORDER = SecurityAuditRecorder(
    os.path.join(root_dir, ".codex", "security_results", f"holder_{os.getpid()}.jsonl")
)

# === 2. Memory Management ===
def get_memory_file(verifier_did):
    if not verifier_did: verifier_did = "unknown"
    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", verifier_did)
    return os.path.join(DATA_DIR, f"memory_{safe_name}.json")

def get_snapshot_hash(verifier_did):
    file_path = get_memory_file(verifier_did)
    if not os.path.exists(file_path):
        return hashlib.sha256(json.dumps([]).encode('utf-8')).hexdigest()
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            memory_data = json.load(f)
        serialized = json.dumps(memory_data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        return hashlib.sha256(serialized.encode('utf-8')).hexdigest()
    except Exception:
        return hashlib.sha256(json.dumps([]).encode('utf-8')).hexdigest()

def append_interaction(verifier_did, request_data, response_data):
    file_path = get_memory_file(verifier_did)
    memory_data = []
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                memory_data = json.load(f)
        except: memory_data = []
    memory_data.append(request_data)
    memory_data.append(response_data)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(memory_data, f, indent=2, ensure_ascii=False)
    #print(f"[Memory] Interaction appended for {verifier_did}")

def ai_content_to_text(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        text_parts = []
        for item in content:
            if isinstance(item, dict):
                if item.get("type") == "text" and item.get("text") is not None:
                    text_parts.append(str(item["text"]))
            elif item is not None:
                text_parts.append(str(item))
        return "\n".join(text_parts)
    return "" if content is None else str(content)


def deterministic_probe_result(prompt_text):
    """Produce a reproducible probe result for security-only experiments."""
    quoted = re.findall(r"['\"](.*?)['\"]", prompt_text or "", flags=re.DOTALL)
    excluded = {
        "get_current_utc_date", "get_hash", "summary", "current_date", "text_hash"
    }
    input_text = next(
        (item for item in quoted if item not in excluded and len(item.strip()) > 3),
        prompt_text or "",
    )
    digest = hashlib.sha256(input_text.encode("utf-8")).hexdigest()
    timestamp_text = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )
    return f"SHA256: {digest}\nTimestamp: {timestamp_text}"

def verify_incoming_json(json_data):
    if not isinstance(json_data, dict):
        return False, "Request must be a JSON object"
    verifier_did = json_data.get('verifier_did')
    signature = json_data.get('verifier_signature')
    if not verifier_did or not signature: return False, "Missing DID or Signature"
    payload_copy = json_data.copy()
    if 'verifier_signature' in payload_copy: del payload_copy['verifier_signature']
    serialized_payload = canonical_json(payload_copy)
    valid, reason = validator.verify_request_signature(serialized_payload, signature, verifier_did)
    if not valid:
        return False, reason

    timestamp = json_data.get("timestamp")
    if not isinstance(timestamp, (int, float)) or abs(time.time() - float(timestamp)) > 120:
        return False, "Missing or stale request timestamp"

    token = json_data.get("nonce") or json_data.get("task_id")
    request_type = json_data.get("type") or ("ProbeTask" if json_data.get("task_id") else "Unknown")
    if not REQUEST_REPLAY_GUARD.consume(f"{verifier_did}:{request_type}", token):
        return False, "Request replay detected"
    return True, "Verification passed"

# === 3. VC Management & Application Logic ===

def save_vc_to_wallet(vc_data):
    """
    Save single VC to local data directory
    Filename format: vc_{DID}_{VC_Type}.json
    """
    safe_did = wallet.did.replace(":", "_")
    vc_types = vc_data.get("type", ["UnknownCredential"])
    vc_type_name = vc_types[-1] if isinstance(vc_types, list) else str(vc_types)
    filename = f"vc_{safe_did}_{vc_type_name}.json"
    vc_file = os.path.join(DATA_DIR, filename)
    try:
        with open(vc_file, 'w', encoding='utf-8') as f:
            json.dump(vc_data, f, indent=2, ensure_ascii=False)
        #print(f"[Wallet] VC Saved to: {vc_file}")
    except Exception as e:
        print(f"[Wallet] Failed to save VC: {e}")

def has_local_vc():
    """Check for local VC files"""
    import glob
    if not wallet or not wallet.did:
        return False
    safe_did = wallet.did.replace(":", "_")
    pattern = os.path.join(DATA_DIR, f"vc_{safe_did}_*.json")
    files = glob.glob(pattern)
    return len(files) > 0

def execute_request_vc(issuer_url, credential_type):
    print(f"[Action] Requesting {credential_type} from {issuer_url}...")
    
    payload = {
        "type": "CredentialApplication",
        "credentialType": credential_type,
        "applicant": wallet.did,
        "timestamp": time.time(),
        "nonce": str(uuid.uuid4())
    }

    evidence_file = os.getenv("AGENTDID_CAPABILITY_EVIDENCE_FILE", "").strip()
    if evidence_file:
        with open(evidence_file, "r", encoding="utf-8") as handle:
            payload["capabilityEvidence"] = json.load(handle)
    
    serialized = canonical_json(payload)
    payload["signature"] = wallet.sign_message(serialized)
    
    try:
        resp = requests.post(f"{issuer_url}/issue_vc", json=payload, timeout=30)
        if resp.status_code == 200:
            vc_list = resp.json() # Note: Issuer now returns a List
            
            for vc in vc_list:
                save_vc_to_wallet(vc) # 1. Save to disk
                wallet.add_vc(vc)     # 2. Load into memory
            
            return True, f"Received {len(vc_list)} VCs"
        else:
            return False, f"Issuer Error: {resp.status_code}"
    except Exception as e:
        print(f"[Warning] Issuer unreachable ({e}). Simulating...")
        fake_vc = {
            "type": credential_type, 
            "credentialSubject": {"id": wallet.did}, 
            "mock": True
        }
        save_vc_to_wallet(fake_vc)
        wallet.add_vc(fake_vc) # Load simulated one too
        return True, "VC Simulated"

def perform_startup_check():
    """Startup self-check sequence"""
    if has_local_vc():
        print("[Startup] ✅ VC found in local storage.")
        wallet.load_local_vcs(DATA_DIR)
        print(f"[Startup] Loaded {len(wallet.my_vcs)} VCs into memory.")
        return

    print("[Startup] ⚠️ No VC found. Initiating request sequence...")
    ISSUER_URL = "http://localhost:8000"
    CRED_TYPE = "Audit_License"
    
    success, msg = execute_request_vc(ISSUER_URL, CRED_TYPE)
    
    if success:
        print(f"[{wallet.role_name}] ✅ VC Acquired.")
    else:
        print(f"[{wallet.role_name}] ❌ VC Request Failed.")
        sys.exit(1)

# === 4. API Routes ===

@app.route('/auth', methods=['POST'])
def handle_auth():
    data = request.get_json(silent=True) or {}
    verifier_did = data.get('verifier_did')
    nonce = data.get('nonce')
    
    print(f"\n>>> [Request] Auth from {verifier_did}")
    is_valid, reason = verify_incoming_json(data)
    if not is_valid: 
        print(f"❌ [Auth Failed] DID: {verifier_did}")
        print(f"   Reason: {reason}")
        return jsonify({"error": reason}), 401

    if agent_app:
        try:
            prompt = (
                f"Authentication Request from {verifier_did}.\n"
                f"Nonce: {nonce}\n"
                "Action: Analyze trust. If you agree to authenticate, output 'APPROVE'."
            )
            config = {"configurable": {"thread_id": f"auth-{nonce}"}}
            if DETERMINISTIC_MODE:
                decision_text = "APPROVE"
            else:
                response = agent_app.invoke(
                    {"messages": [{"role": "user", "content": prompt}]},
                    config=config
                )
                decision_text = ai_content_to_text(response["messages"][-1].content)
            print(f"    [Agent] Decision: {decision_text}")
            
            if "APPROVE" in decision_text.strip().upper():
                if ATTACK_PROFILE.mode in {
                    "impersonation", "vp_replay", "vc_replay_duplicate", "false_capability"
                }:
                    vp, injected_behavior = ATTACK_INJECTOR.create_vp(wallet, nonce)
                    duration = 0.0
                else:
                    vp, duration = wallet.create_vp(nonce)
                    injected_behavior = "none"
                append_interaction(verifier_did, data, vp)
                AUDIT_RECORDER.record(
                    "holder_auth_response",
                    wallet.did,
                    data,
                    vp,
                    True,
                    "VP returned",
                    experiment_id=ATTACK_PROFILE.experiment_id,
                    attack_mode=ATTACK_PROFILE.mode,
                    injected_behavior=injected_behavior,
                    creation_ms=duration,
                )
                return jsonify(vp)
            else:
                return jsonify({"error": "Request rejected by Agent"}), 403
        except Exception as e:
            traceback.print_exc()
            return jsonify({"error": str(e)}), 500
    return jsonify({"error": "Agent not initialized"}), 500

@app.route('/probe', methods=['POST'])
def handle_probe():
    data = request.get_json(silent=True) or {}
    verifier_did = data.get('verifier_did')
    task_id = data.get('task_id')
    prompt_text = data.get('prompt')
    
    print(f"\n>>> [Request] Probe Task {(task_id or 'missing')[:8]}...")
    is_valid, reason = verify_incoming_json(data)
    if not is_valid: return jsonify({"error": reason}), 401

    if agent_app:
        try:
            agent_input = (
                f"New Task from {verifier_did}: {prompt_text}\n"
                f"Task ID: {task_id}\n"
                "Execute using tools and output the final result text."
            )
            config = {"configurable": {"thread_id": task_id}}
            if DETERMINISTIC_MODE:
                result_text = deterministic_probe_result(prompt_text)
            else:
                response = agent_app.invoke(
                    {"messages": [{"role": "user", "content": agent_input}]},
                    config=config
                )
                result_text = ai_content_to_text(response["messages"][-1].content)
            if not DETERMINISTIC_MODE:
                timestamp_text = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                result_text = f"{result_text}\nTimestamp: {timestamp_text}"
            print(f"    [Agent] Result: {result_text[:50]}...")
            
            response_payload = {
                "task_id": task_id,
                "holder_did": wallet.did,
                "execution_result": result_text,
                "timestamp": time.time(),
            }
            serialized = canonical_json(response_payload)
            response_payload["signature"] = wallet.sign_message(serialized)
            append_interaction(verifier_did, data, response_payload)
            AUDIT_RECORDER.record(
                "holder_probe_response",
                wallet.did,
                data,
                response_payload,
                True,
                "Probe result returned",
                experiment_id=ATTACK_PROFILE.experiment_id,
                attack_mode=ATTACK_PROFILE.mode,
            )
            return jsonify(response_payload)
        except Exception as e:
            traceback.print_exc()
            return jsonify({"error": str(e)}), 500
    return jsonify({"error": "Agent error"}), 500

@app.route('/context_hash', methods=['POST'])
def handle_context_hash():
    data = request.get_json(silent=True) or {}
    verifier_did = data.get('verifier_did')
    nonce = data.get('nonce')
    
    print(f"\n>>> [Request] Context Hash Check from {verifier_did}")
    is_valid, reason = verify_incoming_json(data)
    if not is_valid: return jsonify({"error": reason}), 401
    
    current_hash = get_snapshot_hash(verifier_did)
    reported_hash, state_behavior = ATTACK_INJECTOR.context_hash(current_hash)
    print(f"    [Runtime] Snapshot Hash: {current_hash}")

    if agent_app:
        try:
            agent_input = (
                f"Context Hash Request from {verifier_did}.\n"
                f"Current Snapshot Hash: {current_hash}\n"
                "Do you agree to audit? If yes, output 'APPROVE'."
            )
            config = {"configurable": {"thread_id": f"ctx-{nonce}"}}
            if DETERMINISTIC_MODE:
                decision_text = "APPROVE"
            else:
                response = agent_app.invoke(
                    {"messages": [{"role": "user", "content": agent_input}]},
                    config=config
                )
                decision_text = ai_content_to_text(response["messages"][-1].content)
            
            if "APPROVE" in decision_text.strip().upper():
                payload = {
                    "holder_did": wallet.did,
                    "context_hash": reported_hash,
                    "nonce": nonce,
                    "timestamp": time.time(),
                }
                serialized = canonical_json(payload)
                payload["signature"] = wallet.sign_message(serialized)
                append_interaction(verifier_did, data, payload)
                AUDIT_RECORDER.record(
                    "holder_context_response",
                    wallet.did,
                    data,
                    payload,
                    True,
                    "Context state returned",
                    experiment_id=ATTACK_PROFILE.experiment_id,
                    attack_mode=ATTACK_PROFILE.mode,
                    state_behavior=state_behavior,
                    real_context_hash=current_hash,
                )
                return jsonify(payload)
            else:
                return jsonify({"error": "Rejected"}), 403
        except Exception as e:
            traceback.print_exc()
            return jsonify({"error": str(e)}), 500
    return jsonify({"error": "Agent error"}), 500

@app.route('/reset_memory', methods=['POST'])
def reset_memory():
    data = request.get_json(silent=True) or {}
    verifier_did = data.get('verifier_did')
    if not ALLOW_UNSAFE_RESET:
        is_valid, reason = verify_incoming_json(data)
        if not is_valid:
            return jsonify({"error": reason}), 401
    if verifier_did:
        f = get_memory_file(verifier_did)
        if os.path.exists(f):
            os.remove(f)
            result = {
                "status": "cleared",
                "target": verifier_did,
                "unsafe_mode": ALLOW_UNSAFE_RESET,
            }
            AUDIT_RECORDER.record(
                "context_reset",
                wallet.did if wallet else None,
                data,
                result,
                True,
                "Memory file cleared",
                experiment_id=ATTACK_PROFILE.experiment_id,
                unsafe_mode=ALLOW_UNSAFE_RESET,
            )
            return jsonify(result)
    return jsonify({"status": "no_op"})

if __name__ == '__main__':
    # Argument parsing
    # argv[1]: Port
    # argv[2]: Role Name (e.g., holder_1_op)
    # argv[3]: (Optional) Custom Key File Path
    
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    cmd_role = sys.argv[2] if len(sys.argv) > 2 else "agent_a_op"
    key_file_path = sys.argv[3] if len(sys.argv) > 3 else None
    
    print("="*60)
    print(f"Holder Runtime Launching...")
    print(f"Port: {port}")
    print(f"Role: {cmd_role}")

    # Dynamic initialization
    try:
        ROLE_NAME = cmd_role
        
        # If specific key file provided (P2P experiment mode), load that config
        custom_config = None
        if key_file_path and os.path.exists(key_file_path):
            print(f"[Init] Loading custom keys from: {key_file_path}")
            with open(key_file_path, 'r', encoding='utf-8') as f:
                custom_config = json.load(f)
        
        # Initialize Wallet
        wallet = IdentityWallet(ROLE_NAME, override_config=custom_config)
        wallet.load_local_vcs(DATA_DIR)
        print(f"Identity Loaded: {wallet.did}")
        
        # Initialize Agent
        agent_app = create_holder_agent(wallet.did, config_override=custom_config)
        
    except Exception as e:
        print(f"[Fatal] Failed to initialize for {cmd_role}: {e}")
        traceback.print_exc()
        sys.exit(1)

    # Startup check (VC application)
    perform_startup_check()

    print("="*60)
    # Disable Flask Startup Banner to reduce console noise with N processes
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    app.run(host='0.0.0.0', port=port, threaded=True)
