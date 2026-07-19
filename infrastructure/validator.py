import json
import subprocess
import os
import datetime
import time
from web3 import Web3
from eth_account.messages import encode_defunct
from infrastructure.load_config import get_resolve_script_path, load_key_config
from infrastructure.security import canonical_json, sha256_json

# Attempt to get global configuration
try:
    from infrastructure.utils import get_w3, get_rpc_url
    global_w3, global_config = get_w3()
    RPC_URL = global_config["api_url"]
except ImportError:
    # If utils cannot be found, load independently
    conf = load_key_config()
    RPC_URL = conf["api_url"]
    global_w3 = Web3(Web3.HTTPProvider(RPC_URL))
    get_rpc_url = lambda: (RPC_URL, conf)

class DIDValidator:
    def __init__(self):
        self.w3 = global_w3
        self.resolve_script = get_resolve_script_path()
        self.did_cache = {} # In-memory cache
        
        # Load trusted Issuers
        key_conf = load_key_config()
        if "issuer" in key_conf["accounts"]:
            self.trusted_issuers = [key_conf["accounts"]["issuer"]["address"].lower()]
        else:
            self.trusted_issuers = []
        self.strict_issuer = os.getenv("AGENTDID_STRICT_ISSUER", "true").lower() == "true"

    def resolve_did(self, did):
        """Calls Node.js to resolve a DID (includes retry mechanism)"""
        # 1. Check cache first
        if did in self.did_cache:
            #print(f"    [Cache Hit] Using in-memory cache directly: {did}")
            return self.did_cache[did]
        
        # 2. Set retry parameters
        max_retries = 5
        
        # 3. Start retry loop
        for attempt in range(max_retries):
            # Re-fetch an RPC node on each retry (implements failover)
            current_rpc_url, _ = get_rpc_url()
            
            try:
                process = subprocess.run(
                    ["node", self.resolve_script, did, current_rpc_url],
                    capture_output=True, text=True, encoding='utf-8'
                )
                
                # If return code is 0 (success) and there is output
                if process.returncode == 0:
                    result = json.loads(process.stdout)
                    if "didDocument" in result:
                        doc = result["didDocument"]
                        self.did_cache[did] = doc # Write to cache
                        return doc
                
                # If it fails (e.g., 429 Too Many Requests), print a warning but don't exit; continue to the next loop iteration
                print(f"[Validator Warning] Attempt {attempt+1} failed to resolve (Node: {current_rpc_url}): {process.stderr.strip()}")
                
            except Exception as e:
                print(f"[Validator Error] Exception during resolution attempt {attempt+1}: {e}")
            
            # Sleep for a while after failure to give the RPC node or local CPU a break
            if attempt < max_retries - 1:
                time.sleep(1)

        # 4. If all retries fail
        print(f"[Validator Fatal] {did} resolution ultimately failed after {max_retries} retries")
        return None

    def check_authorization(self, did_doc, recovered_address):
        """Checks if recovered_address is the Owner or a Delegate of the DID"""
        if not did_doc or "verificationMethod" not in did_doc:
            return False
        
        target = recovered_address.lower().replace("0x", "")
        authorized = False
        
        for method in did_doc["verificationMethod"]:
            # 1. Check Owner (blockchainAccountId)
            if "blockchainAccountId" in method:
                parts = method["blockchainAccountId"].split(":")
                if len(parts) > 0:
                    owner_addr = parts[-1].lower().replace("0x", "")
                    if owner_addr == target:
                        authorized = True
                        break
            
            # 2. Check Delegate (publicKeyHex)
            if "publicKeyHex" in method:
                pub_key = method["publicKeyHex"].lower().replace("0x", "")
                if pub_key == target:
                    authorized = True
                    break
        
        return authorized

    def verify_request_signature(self, text_payload, signature, claimed_did):
        """
        Generic signature verification
        """
        if not signature or not claimed_did:
            return False, "Missing signature or DID"

        try:
            msg = encode_defunct(text=text_payload)
            recovered_addr = self.w3.eth.account.recover_message(msg, signature=signature)
            
            doc = self.resolve_did(claimed_did)
            if not doc:
                return False, f"DID document resolution failed: {claimed_did}"
            
            if self.check_authorization(doc, recovered_addr):
                return True, "Verification passed"
            
                 # === Cache Invalidation Retry Mechanism ===
            if claimed_did in self.did_cache:
                print(f"⚠️ [Validator] Cached document validation failed, clearing cache and retrying on-chain query: {claimed_did}")
                del self.did_cache[claimed_did]
                
                # Re-resolve (force network)
                doc_fresh = self.resolve_did(claimed_did)
                if doc_fresh and self.check_authorization(doc_fresh, recovered_addr):
                    print(f"✅ [Validator] Passed after retry!")
                    return True, "Retry passed"
            
            else:
                return False, f"Signer {recovered_addr} is not authorized by {claimed_did} "
                
            return False, f"Signer {recovered_addr} is not authorized by {claimed_did}"
        except Exception as e:
            return False, f"Exception during signature verification: {str(e)}"

    def verify_vp(self, vp_json, expected_nonce, expected_holder=None):
        """
        Verify VP (adapts to Runtime interface: returns bool, reason)
        """
        if not isinstance(vp_json, dict):
            return False, "VP must be a JSON object"

        # 1. Nonce Check (from Proof)
        proof = vp_json.get("proof", {})
        if not isinstance(proof, dict):
            return False, "VP proof is missing or malformed"
        if proof.get("challenge") != expected_nonce:
            return False, f"Nonce mismatch: expected {expected_nonce}, got {proof.get('challenge')}"

        # 2. Prepare data for signature verification
        payload = vp_json.copy()
        if "proof" in payload:
            del payload["proof"] # Remove proof, the rest is the body
        
        # 3. Serialize (must be consistent with Wallet.create_vp)
        serialized = canonical_json(payload)
        signature = proof.get("jws")
        
        # 4. Recover signer
        holder_did = vp_json.get("holder")
        if isinstance(holder_did, dict): holder_did = holder_did.get("id") # Compatible with object format

        if not holder_did:
            return False, "VP holder is missing"
        if expected_holder and holder_did != expected_holder:
            return False, f"Holder mismatch: expected {expected_holder}, got {holder_did}"

        valid_sig, reason = self.verify_request_signature(serialized, signature, holder_did)
        
        if not valid_sig:
            return False, f"VP Signature Invalid: {reason}"
        
        # 5. VC Verification
        vcs = vp_json.get("verifiableCredential", [])
        if not isinstance(vcs, list):
            return False, "verifiableCredential must be a list"

        seen_credentials = set()
        for vc in vcs:
            fingerprint = sha256_json(vc)
            if fingerprint in seen_credentials:
                return False, "VC Invalid: Duplicate credential in presentation"
            seen_credentials.add(fingerprint)
            vc_res = self._verify_single_vc(vc, holder_did)
            if not vc_res["valid"]:
                 return False, f"VC Invalid: {vc_res['error']}"

        return True, "VP Valid"

    def _verify_single_vc(self, vc, expected_holder):
        res = {"valid": False, "error": ""}

        if not isinstance(vc, dict):
            res["error"] = "Credential must be a JSON object"
            return res

        # Subject
        subject = vc.get("credentialSubject")
        if not isinstance(subject, dict) or subject.get("id") != expected_holder:
            res["error"] = "Subject ID mismatch"
            return res

        now = datetime.datetime.now(datetime.timezone.utc)
        if "validFrom" in vc:
            try:
                valid_from = datetime.datetime.fromisoformat(vc["validFrom"].replace("Z", "+00:00"))
                if now < valid_from:
                    res["error"] = "VC is not yet valid"
                    return res
            except Exception as e:
                res["error"] = f"Invalid validFrom timestamp: {e}"
                return res

        # Time
        if "validUntil" in vc:
            try:
                # Parse time string
                exp_str = vc["validUntil"].replace("Z", "+00:00")
                exp = datetime.datetime.fromisoformat(exp_str)
                
                # Get current timezone-aware time
                if now > exp:
                    res["error"] = "VC has expired"
                    return res
            except Exception as e:
                res["error"] = f"Invalid validUntil timestamp: {e}"
                return res

        credential_status = vc.get("credentialStatus")
        if isinstance(credential_status, dict):
            status_value = str(credential_status.get("status", "")).lower()
            if credential_status.get("revoked") is True or status_value in {"revoked", "suspended"}:
                res["error"] = f"Credential status is {status_value or 'revoked'}"
                return res

        # Issuer Check
        issuer_did = vc.get("issuer")
        if not issuer_did:
            res["error"] = "Missing issuer"
            return res
        issuer_addr = issuer_did.split(":")[-1].lower() if ":" in issuer_did else ""
        if self.strict_issuer and issuer_addr not in self.trusted_issuers:
            res["error"] = f"Issuer {issuer_addr} not in trusted issuer list"
            return res

        # Signature
        vc_payload = vc.copy()
        if "proof" in vc_payload:
            del vc_payload["proof"]
        serialized = canonical_json(vc_payload)

        proof = vc.get("proof")
        if not isinstance(proof, dict) or not proof.get("jws"):
            res["error"] = "Missing VC proof"
            return res
        valid_sig, reason = self.verify_request_signature(serialized, proof["jws"], issuer_did)
        if not valid_sig:
            res["error"] = f"VC signature invalid: {reason}"
            return res
            
        res["valid"] = True
        return res
