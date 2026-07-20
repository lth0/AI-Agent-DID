from __future__ import annotations

import dataclasses
import time
import unittest

from eth_account import Account

from infrastructure.lineage import (
    AgentType,
    BudgetLimits,
    InMemoryStateProvider,
    LineageVerifier,
    LineageWallet,
    PermissionEnvelope,
    PolicyEngine,
    PolicyViolation,
    RootKeyManager,
    create_delegation_credential,
    create_epoch_certificate,
    credential_hash,
    verify_enrollment_proof,
    replica_group_id,
    version_did,
)
from infrastructure.lineage.crypto import ZERO_ADDRESS, did_from_address, sign_typed_payload
from infrastructure.lineage.models import LineageInvocation
from infrastructure.security import sha256_json


CHAIN_ID = 11155111
VERSION = "urn:agentlineage:version:sha256:" + "ab" * 32


class LineageFixture:
    def __init__(self) -> None:
        self.now = int(time.time())
        self.root = Account.create(b"root")
        self.root_did = did_from_address(self.root.address)
        self.manager = RootKeyManager(self.root_did, b"root-seed" * 8)
        self.epoch_key = self.manager.derive(1)
        self.epoch = create_epoch_certificate(
            root_did=self.root_did,
            epoch=1,
            delegation_key=Account.from_key(self.epoch_key).address,
            not_before=self.now - 10,
            expires_at=self.now + 86400,
            status_ref={"contract": ZERO_ADDRESS, "epoch": 1},
            root_identity_private_key=self.root.key.hex(),
            chain_id=CHAIN_ID,
        )
        self.persistent = LineageWallet.generate(AgentType.PERSISTENT, delegable=True)
        self.session = LineageWallet.generate(AgentType.SESSION, delegable=False)
        self.parent_permission = PermissionEnvelope(
            actions=("read", "write"), resources=("urn:tool:a", "urn:tool:b"),
            tasks=("task-1",), audiences=("urn:gateway:test",), versions=(VERSION,),
            not_before=self.now - 5, expires_at=self.now + 7200,
            remaining_depth=3, delegable=True,
        )
        self.first = create_delegation_credential(
            root_did=self.root_did, parent_did=self.root_did,
            parent_credential_hash=credential_hash(self.epoch),
            parent_lineage_commitment=credential_hash(self.epoch),
            child_did=self.persistent.did, child_operation_key=self.persistent.operation_address,
            child_delegation_key=self.persistent.delegation_address,
            agent_type=AgentType.PERSISTENT, version_id=VERSION, replica_group_id=None,
            permission=self.parent_permission, budget_id="0x" + "11" * 32,
            reservation=BudgetLimits(100, 1000, 5), epoch=1,
            status_ref={"contract": ZERO_ADDRESS, "credential": "first"},
            issuer_delegation_private_key=self.epoch_key, chain_id=CHAIN_ID,
        )
        child_permission = PolicyEngine().attenuate(
            self.parent_permission,
            {
                "actions": ["read"], "resources": ["urn:tool:a"],
                "remaining_depth": 0, "delegable": False,
                "expires_at": self.now + 1800,
            },
            AgentType.SESSION,
            now=self.now,
        )
        self.second = create_delegation_credential(
            root_did=self.root_did, parent_did=self.persistent.did,
            parent_credential_hash=credential_hash(self.first),
            parent_lineage_commitment=self.first.lineage_commitment,
            child_did=self.session.did, child_operation_key=self.session.operation_address,
            child_delegation_key=None, agent_type=AgentType.SESSION, version_id=VERSION,
            replica_group_id=None, permission=child_permission,
            budget_id="0x" + "22" * 32, reservation=BudgetLimits(10, 100, 1), epoch=1,
            status_ref={"contract": ZERO_ADDRESS, "credential": "second"},
            issuer_delegation_private_key=self.persistent.delegation_private_key,
            chain_id=CHAIN_ID,
        )

    def invocation(self, wallet: LineageWallet | None = None) -> LineageInvocation:
        wallet = wallet or self.session
        body_hash = sha256_json({"input": "hello"})
        request = LineageInvocation(
            leaf_did=self.session.did, credential_jti=self.second.jti,
            origin_did=self.session.did, on_behalf_of=self.root_did,
            audience="urn:gateway:test", task_id="task-1", action="read",
            resource="urn:tool:a", version_id=VERSION, body_hash=body_hash,
            challenge="nonce-1", sequence=1, timestamp=self.now,
            budget_id=self.second.budget_id, cost_units=2, lease_seconds=30,
        )
        return wallet.sign_invocation(request, chain_id=CHAIN_ID)


class AgentLineageCoreTests(unittest.TestCase):
    def test_permission_dsl_normalizes_and_rejects_invalid_types(self):
        permission = PermissionEnvelope(
            actions=("write", " read ", "read"),
            resources=("urn:tool:a",),
            tasks=("task-1",),
            audiences=("urn:gateway:test",),
            versions=(VERSION,),
            not_before=1,
            expires_at=2,
            remaining_depth=0,
            delegable=False,
        )
        self.assertEqual(permission.actions, ("read", "write"))
        with self.assertRaisesRegex(ValueError, "cannot combine"):
            dataclasses.replace(permission, actions=("*", "read"))
        with self.assertRaisesRegex(ValueError, "only strings"):
            dataclasses.replace(permission, actions=(1,))
        with self.assertRaisesRegex(ValueError, "must be a boolean"):
            PermissionEnvelope.from_dict({**permission.to_dict(), "delegable": "false"})
        with self.assertRaisesRegex(ValueError, "positive integer"):
            BudgetLimits.from_dict({"calls": "1", "cost_units": 1, "concurrency": 1})

    def test_child_wildcard_is_rejected_under_finite_parent(self):
        fixture = LineageFixture()
        with self.assertRaisesRegex(PolicyViolation, "wildcard exceeds"):
            PolicyEngine().attenuate(
                fixture.parent_permission,
                {"actions": ["*"]},
                AgentType.CHILD,
                now=fixture.now,
            )

    def test_requested_permission_rejects_ambiguous_schema(self):
        fixture = LineageFixture()
        engine = PolicyEngine()
        with self.assertRaisesRegex(PolicyViolation, "must be an integer"):
            engine.attenuate(
                fixture.parent_permission,
                {"remaining_depth": "0"},
                AgentType.CHILD,
                now=fixture.now,
            )
        with self.assertRaisesRegex(PolicyViolation, "unsupported permission fields"):
            engine.attenuate(
                fixture.parent_permission,
                {"natural_language_scope": "everything"},
                AgentType.CHILD,
                now=fixture.now,
            )

    def test_hkdf_is_domain_separated_and_stable(self):
        fixture = LineageFixture()
        self.assertEqual(fixture.manager.derive(1), fixture.manager.derive(1))
        self.assertNotEqual(fixture.manager.derive(1), fixture.manager.derive(2))
        self.assertNotEqual(fixture.manager.derive(1, "delegation"), fixture.manager.derive(1, "operation"))

    def test_child_keys_are_independent(self):
        first = LineageWallet.generate(AgentType.INSTANCE)
        second = LineageWallet.generate(AgentType.INSTANCE)
        self.assertNotEqual(first.operation_address, second.operation_address)

    def test_version_and_replica_identifiers_are_content_addressed(self):
        self.assertEqual(version_did("agent-v1"), version_did(b"agent-v1"))
        self.assertNotEqual(version_did("agent-v1"), version_did("agent-v2"))
        self.assertTrue(replica_group_id("workers").startswith("urn:agentlineage:replica:sha256:"))

    def test_enrollment_proof_binds_operation_key(self):
        fixture = LineageFixture()
        proof = fixture.session.create_enrollment_proof(
            root_did=fixture.root_did, parent_did=fixture.persistent.did,
            nonce="enroll-1", timestamp=fixture.now, chain_id=CHAIN_ID,
        )
        valid, reason = verify_enrollment_proof(
            proof, expected_root_did=fixture.root_did,
            expected_parent_did=fixture.persistent.did, expected_nonce="enroll-1",
            chain_id=CHAIN_ID, now=fixture.now,
        )
        self.assertTrue(valid, reason)

    def test_delegable_enrollment_requires_independent_delegation_key_proof(self):
        fixture = LineageFixture()
        proof = fixture.persistent.create_enrollment_proof(
            root_did=fixture.root_did, parent_did=fixture.root_did,
            nonce="enroll-del", timestamp=fixture.now, chain_id=CHAIN_ID,
        )
        proof.pop("delegation_signature")
        valid, reason = verify_enrollment_proof(
            proof, expected_root_did=fixture.root_did,
            expected_parent_did=fixture.root_did, expected_nonce="enroll-del",
            chain_id=CHAIN_ID, now=fixture.now,
        )
        self.assertFalse(valid)
        self.assertIn("delegation", reason)

    def test_valid_chain_and_request_are_accepted(self):
        fixture = LineageFixture()
        verifier = LineageVerifier(
            chain_id=CHAIN_ID, verifying_contract=ZERO_ADDRESS,
            state_provider=InMemoryStateProvider(),
        )
        decision = verifier.verify(
            fixture.epoch, [fixture.first, fixture.second], fixture.invocation(),
            expected_audience="urn:gateway:test",
            expected_body_hash=sha256_json({"input": "hello"}), now=fixture.now,
        )
        self.assertTrue(decision.accepted, decision)

    def test_legitimate_delegation_key_cannot_escalate_policy(self):
        fixture = LineageFixture()
        malicious = dataclasses.replace(
            fixture.second,
            permission=dataclasses.replace(fixture.second.permission, actions=("read", "delete")),
            signature="",
        )
        malicious = create_delegation_credential(
            root_did=malicious.root_did, parent_did=malicious.parent_did,
            parent_credential_hash=malicious.parent_credential_hash,
            parent_lineage_commitment=fixture.first.lineage_commitment,
            child_did=malicious.child_did, child_operation_key=malicious.operation_key,
            child_delegation_key=None, agent_type=malicious.agent_type,
            version_id=malicious.version_id, replica_group_id=None,
            permission=malicious.permission, budget_id=malicious.budget_id,
            reservation=malicious.reservation, epoch=malicious.epoch,
            status_ref=malicious.status_ref,
            issuer_delegation_private_key=fixture.persistent.delegation_private_key,
            chain_id=CHAIN_ID, jti=malicious.jti,
        )
        request = dataclasses.replace(fixture.invocation(), signature="")
        request = fixture.session.sign_invocation(request, chain_id=CHAIN_ID)
        decision = LineageVerifier(
            chain_id=CHAIN_ID, verifying_contract=ZERO_ADDRESS,
            state_provider=InMemoryStateProvider(),
        ).verify(
            fixture.epoch, [fixture.first, malicious], request,
            expected_audience="urn:gateway:test",
            expected_body_hash=request.body_hash, now=fixture.now,
        )
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.code, "POLICY_ESCALATION")

    def test_sibling_key_cannot_impersonate_leaf(self):
        fixture = LineageFixture()
        sibling = LineageWallet.generate(AgentType.SESSION)
        request = dataclasses.replace(fixture.invocation(), signature="")
        request = dataclasses.replace(
            request,
            signature=sign_typed_payload(
                sibling.operation_private_key,
                request.unsigned_dict(),
                purpose="AgentLineage/REQUEST/v1",
                chain_id=CHAIN_ID,
            ),
        )
        decision = LineageVerifier(
            chain_id=CHAIN_ID, verifying_contract=ZERO_ADDRESS,
            state_provider=InMemoryStateProvider(),
        ).verify(
            fixture.epoch, [fixture.first, fixture.second], request,
            expected_audience="urn:gateway:test",
            expected_body_hash=sha256_json({"input": "hello"}), now=fixture.now,
        )
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.code, "REQUEST_SIGNATURE_INVALID")

    def test_confused_deputy_origin_is_rejected(self):
        fixture = LineageFixture()
        request = dataclasses.replace(
            fixture.invocation(), origin_did=fixture.persistent.did, signature=""
        )
        request = fixture.session.sign_invocation(request, chain_id=CHAIN_ID)
        decision = LineageVerifier(
            chain_id=CHAIN_ID, verifying_contract=ZERO_ADDRESS,
            state_provider=InMemoryStateProvider(),
        ).verify(
            fixture.epoch, [fixture.first, fixture.second], request,
            expected_audience="urn:gateway:test", expected_body_hash=request.body_hash,
            now=fixture.now,
        )
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.code, "ORIGIN_MISMATCH")

    def test_rpc_failure_is_fail_closed(self):
        class FailingState:
            def validate_chain_state(self, epoch, credentials):
                raise ConnectionError("RPC unavailable")

        fixture = LineageFixture()
        decision = LineageVerifier(
            chain_id=CHAIN_ID, verifying_contract=ZERO_ADDRESS,
            state_provider=FailingState(),
        ).verify(
            fixture.epoch, [fixture.first, fixture.second], fixture.invocation(),
            expected_audience="urn:gateway:test",
            expected_body_hash=sha256_json({"input": "hello"}), now=fixture.now,
        )
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.code, "STATE_UNAVAILABLE")

    def test_revoked_ancestor_closes_descendant_chain(self):
        fixture = LineageFixture()
        state = InMemoryStateProvider(revoked_nodes={fixture.persistent.did})
        decision = LineageVerifier(
            chain_id=CHAIN_ID, verifying_contract=ZERO_ADDRESS, state_provider=state,
        ).verify(
            fixture.epoch, [fixture.first, fixture.second], fixture.invocation(),
            expected_audience="urn:gateway:test",
            expected_body_hash=sha256_json({"input": "hello"}), now=fixture.now,
        )
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.code, "STATUS_REVOKED")


if __name__ == "__main__":
    unittest.main()
