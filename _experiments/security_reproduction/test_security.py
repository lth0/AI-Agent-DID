from __future__ import annotations

import hashlib
import time
import unittest

from agents.holder.attack_profiles import AttackInjector, AttackProfile
from infrastructure.evidence_anchor import decode_anchor_data, encode_anchor_data
from infrastructure.security import (
    ReplayGuard,
    SecurityAuditRecorder,
    canonical_json,
    verify_evidence_event,
    verify_signed_payload,
)


class FakeWallet:
    did = "did:example:attacker"
    my_vcs = [
        {
            "type": ["VerifiableCredential", "AgentCapabilityCredential"],
            "credentialSubject": {
                "id": did,
                "evaluation": {"ratingValue": "0.250"},
            },
            "proof": {"jws": "issuer-signature"},
        }
    ]

    def sign_message(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()


class FakeValidator:
    def verify_request_signature(self, text, signature, claimed_did):
        expected = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return signature == expected, "offline signature check"


class SecurityPrimitiveTests(unittest.TestCase):
    def test_canonical_json_is_order_independent(self):
        self.assertEqual(canonical_json({"b": 2, "a": 1}), canonical_json({"a": 1, "b": 2}))

    def test_replay_guard_consumes_token_once(self):
        guard = ReplayGuard(ttl_seconds=60)
        self.assertTrue(guard.consume("auth", "nonce-1", now=100))
        self.assertFalse(guard.consume("auth", "nonce-1", now=101))
        self.assertTrue(guard.consume("auth", "nonce-1", now=200))

    def test_signed_payload_binding(self):
        body = {
            "holder_did": FakeWallet.did,
            "task_id": "task-1",
            "timestamp": time.time(),
        }
        payload = dict(body)
        payload["signature"] = FakeWallet().sign_message(canonical_json(body))
        result = verify_signed_payload(
            FakeValidator(), payload, FakeWallet.did,
            expected_task_id="task-1",
            required_fields=("holder_did", "task_id", "timestamp", "signature"),
        )
        self.assertTrue(result.valid, result.reason)

    def test_vp_replay_keeps_old_challenge(self):
        injector = AttackInjector(AttackProfile(mode="vp_replay"))
        first, _ = injector.create_vp(FakeWallet(), "nonce-1")
        second, behavior = injector.create_vp(FakeWallet(), "nonce-2")
        self.assertEqual(first, second)
        self.assertEqual(second["proof"]["challenge"], "nonce-1")
        self.assertEqual(behavior, "replayed_previous_vp")

    def test_impersonation_claim_is_signed_by_attacker(self):
        injector = AttackInjector(
            AttackProfile(mode="impersonation", impersonated_did="did:example:victim")
        )
        vp, _ = injector.create_vp(FakeWallet(), "nonce")
        self.assertEqual(vp["holder"], "did:example:victim")
        self.assertNotEqual(vp["holder"], FakeWallet.did)

    def test_duplicate_vc_and_false_capability_profiles(self):
        duplicate = AttackInjector(AttackProfile(mode="vc_replay_duplicate"))
        duplicate_vp, _ = duplicate.create_vp(FakeWallet(), "nonce")
        self.assertEqual(len(duplicate_vp["verifiableCredential"]), 2)

        false_capability = AttackInjector(AttackProfile(mode="false_capability"))
        capability_vp, _ = false_capability.create_vp(FakeWallet(), "nonce")
        evaluation = capability_vp["verifiableCredential"][0]["credentialSubject"]["evaluation"]
        self.assertEqual(evaluation["ratingValue"], "1.000")

    def test_false_state_replays_initial_hash(self):
        injector = AttackInjector(AttackProfile(mode="false_state"))
        self.assertEqual(injector.context_hash("hash-1")[0], "hash-1")
        self.assertEqual(injector.context_hash("hash-2")[0], "hash-1")

    def test_anchor_encoding_round_trip(self):
        evidence_hash = "ab" * 32
        self.assertEqual(decode_anchor_data(encode_anchor_data(evidence_hash)), evidence_hash)

    def test_evidence_hash_detects_tampering(self):
        import os

        output = os.path.join(".codex", "test_output", "agentdid-security-test.jsonl")
        recorder = SecurityAuditRecorder(output)
        event = recorder.record("test", "did:example:a", {"x": 1}, {"y": 2}, False, "test")
        self.assertTrue(verify_evidence_event(event)[0])
        event["reason"] = "tampered"
        self.assertFalse(verify_evidence_event(event)[0])


if __name__ == "__main__":
    unittest.main()
