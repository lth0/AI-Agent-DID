from __future__ import annotations

import dataclasses
import unittest

from _experiments.lineage.test_lineage_core import CHAIN_ID, VERSION, LineageFixture
from _ops_services.lineage_server import create_app
from infrastructure.lineage import AgentType, InMemoryStateProvider, LineageVerifier, LineageWallet
from infrastructure.lineage import replica_group_id
from infrastructure.lineage.crypto import ZERO_ADDRESS
from infrastructure.lineage.service import (
    LineageAuthority,
    LineageGateway,
    ParentAuthority,
    ToolRouter,
)


class FakeRegistry(InMemoryStateProvider):
    def __init__(self):
        super().__init__(block_number=100)
        self.registered = []
        self.reserved = []
        self.begun = []
        self.finished = []
        self.revocations = []
        self.replica_groups = {}

    @staticmethod
    def _tx(name: str):
        return {"transaction_hash": "0x" + name.encode().hex().ljust(64, "0"), "block_number": 100}

    def latest_block_number(self):
        return self.block_number

    def register_delegation(self, credential, private_key, *, parent=None):
        self.registered.append(credential)
        return self._tx("register")

    def reserve_child_budget(self, parent_budget_id, credential, private_key):
        self.reserved.append((parent_budget_id, credential.budget_id))
        return self._tx("reserve")

    def ensure_replica_group_budget(
        self, parent_budget_id, replica_group_id, budget_id, limits, private_key
    ):
        existing = replica_group_id in self.replica_groups
        self.replica_groups.setdefault(replica_group_id, (budget_id, limits))
        return {**self._tx("replica"), "existing": existing}

    def begin_invocation(self, credential, invocation):
        self.begun.append(invocation)
        return self._tx("begin")

    def finish_invocation(self, invocation):
        self.finished.append(invocation)
        return self._tx("finish")

    def revoke(self, root_did, kind, subject, private_key):
        self.revocations.append((root_did, kind, subject))
        return self._tx("revoke")

    def get_status(self, identifier):
        return {"identifier": identifier, "block_number": self.block_number}


class AgentLineageServiceTests(unittest.TestCase):
    def setUp(self):
        self.fixture = LineageFixture()
        self.registry = FakeRegistry()
        self.authority = LineageAuthority(
            ParentAuthority(
                root_did=self.fixture.root_did,
                parent_did=self.fixture.root_did,
                epoch=self.fixture.epoch,
                delegation_private_key=self.fixture.epoch_key,
                permission=self.fixture.parent_permission,
                parent_budget_id="0x" + "33" * 32,
            ),
            self.registry,
            chain_id=CHAIN_ID,
            verifying_contract=ZERO_ADDRESS,
        )
        router = ToolRouter()
        router.register("read", "urn:tool:a", cost_units=2, handler=lambda body: body)
        verifier = LineageVerifier(
            chain_id=CHAIN_ID,
            verifying_contract=ZERO_ADDRESS,
            state_provider=self.registry,
            max_state_block_lag=0,
        )
        self.gateway = LineageGateway(
            verifier, self.registry, router, audience="urn:gateway:test"
        )
        self.app = create_app(
            authority=self.authority,
            gateway=self.gateway,
            registry=self.registry,
            root_did=self.fixture.root_did,
            governance_private_key=self.fixture.root.key.hex(),
            enabled=True,
            control_token="control",
        )
        self.client = self.app.test_client()

    def test_feature_flag_defaults_to_closed(self):
        app = create_app(
            authority=None, gateway=None, registry=self.registry,
            root_did=self.fixture.root_did, enabled=False,
        )
        response = app.test_client().post("/v1/lineage/challenge")
        self.assertEqual(response.status_code, 503)

    def test_spawn_consumes_challenge_and_registers_budget(self):
        challenge = self.client.post("/v1/lineage/challenge").get_json()
        wallet = LineageWallet.generate(AgentType.SESSION)
        proof = wallet.create_enrollment_proof(
            root_did=self.fixture.root_did,
            parent_did=self.fixture.root_did,
            nonce=challenge["nonce"],
            timestamp=self.fixture.now,
            chain_id=CHAIN_ID,
        )
        payload = {
            "enrollment_proof": proof,
            "version_id": VERSION,
            "requested_permission": {
                "actions": ["read"], "resources": ["urn:tool:a"],
                "remaining_depth": 0, "delegable": False,
                "expires_at": self.fixture.now + 600,
            },
            "reservation": {"calls": 5, "cost_units": 20, "concurrency": 1},
        }
        headers = {"X-AgentLineage-Control-Token": "control"}
        response = self.client.post("/v1/lineage/spawn", json=payload, headers=headers)
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(len(self.registry.registered), 1)
        self.assertEqual(len(self.registry.reserved), 1)
        replay = self.client.post("/v1/lineage/spawn", json=payload, headers=headers)
        self.assertEqual(replay.status_code, 400)

    def test_valid_invocation_debits_executes_and_releases(self):
        payload = {
            "epoch_certificate": self.fixture.epoch.to_dict(),
            "delegation_chain": [self.fixture.first.to_dict(), self.fixture.second.to_dict()],
            "invocation": self.fixture.invocation().to_dict(),
            "body": {"input": "hello"},
        }
        response = self.client.post("/v1/lineage/invoke", json=payload)
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertTrue(response.get_json()["decision"]["accepted"])
        self.assertEqual(len(self.registry.begun), 1)
        self.assertEqual(len(self.registry.finished), 1)

    def test_cost_tampering_is_rejected_before_budget_debit(self):
        request = dataclasses.replace(self.fixture.invocation(), cost_units=3, signature="")
        request = self.fixture.session.sign_invocation(request, chain_id=CHAIN_ID)
        response = self.client.post("/v1/lineage/invoke", json={
            "epoch_certificate": self.fixture.epoch.to_dict(),
            "delegation_chain": [self.fixture.first.to_dict(), self.fixture.second.to_dict()],
            "invocation": request.to_dict(),
            "body": {"input": "hello"},
        })
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["decision"]["code"], "COST_MISMATCH")
        self.assertEqual(self.registry.begun, [])

    def test_tool_failure_is_not_refunded_but_releases_lease(self):
        def fail(_body):
            raise RuntimeError("sensitive tool detail")

        router = ToolRouter()
        router.register("read", "urn:tool:a", cost_units=2, handler=fail)
        gateway = LineageGateway(
            self.gateway.verifier, self.registry, router, audience="urn:gateway:test"
        )
        app = create_app(
            authority=self.authority, gateway=gateway, registry=self.registry,
            root_did=self.fixture.root_did, enabled=True, control_token="control",
        )
        response = app.test_client().post("/v1/lineage/invoke", json={
            "epoch_certificate": self.fixture.epoch.to_dict(),
            "delegation_chain": [self.fixture.first.to_dict(), self.fixture.second.to_dict()],
            "invocation": self.fixture.invocation().to_dict(),
            "body": {"input": "hello"},
        })
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["decision"]["code"], "TOOL_EXECUTION_FAILED")
        self.assertEqual(len(self.registry.begun), 1)
        self.assertEqual(len(self.registry.finished), 1)
        self.assertNotIn("sensitive", str(response.get_json()))

    def test_revoke_requires_control_token(self):
        denied = self.client.post(
            "/v1/lineage/revoke", json={"kind": "node", "subject": "did:test"}
        )
        self.assertEqual(denied.status_code, 403)
        accepted = self.client.post(
            "/v1/lineage/revoke",
            json={"kind": "node", "subject": "did:test"},
            headers={"X-AgentLineage-Control-Token": "control"},
        )
        self.assertEqual(accepted.status_code, 200)

    def test_instances_share_one_replica_group_budget(self):
        group_id = replica_group_id("api-workers")
        headers = {"X-AgentLineage-Control-Token": "control"}
        budget_ids = []
        for _ in range(2):
            challenge = self.client.post("/v1/lineage/challenge").get_json()
            wallet = LineageWallet.generate(AgentType.INSTANCE)
            proof = wallet.create_enrollment_proof(
                root_did=self.fixture.root_did,
                parent_did=self.fixture.root_did,
                nonce=challenge["nonce"],
                timestamp=self.fixture.now,
                chain_id=CHAIN_ID,
            )
            response = self.client.post("/v1/lineage/spawn", json={
                "enrollment_proof": proof,
                "version_id": VERSION,
                "replica_group_id": group_id,
                "requested_permission": {
                    "actions": ["read"],
                    "resources": ["urn:tool:a"],
                    "remaining_depth": 0,
                    "delegable": False,
                    "expires_at": self.fixture.now + 600,
                },
                "reservation": {"calls": 5, "cost_units": 20, "concurrency": 2},
            }, headers=headers)
            self.assertEqual(response.status_code, 200, response.get_json())
            budget_ids.append(response.get_json()["credential"]["budget_id"])
        self.assertEqual(budget_ids[0], budget_ids[1])
        self.assertEqual(len(self.registry.replica_groups), 1)
        self.assertEqual(self.registry.reserved, [])


if __name__ == "__main__":
    unittest.main()
