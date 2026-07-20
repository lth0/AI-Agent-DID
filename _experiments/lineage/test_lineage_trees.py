from __future__ import annotations

import time
import unittest

from _experiments.lineage.test_lineage_core import CHAIN_ID, VERSION, LineageFixture
from infrastructure.lineage import (
    AgentType,
    BudgetLimits,
    InMemoryStateProvider,
    LineageInvocation,
    LineageVerifier,
    LineageWallet,
    PermissionEnvelope,
    PolicyEngine,
    create_delegation_credential,
    credential_hash,
    replica_group_id,
)
from infrastructure.lineage.crypto import ZERO_ADDRESS
from infrastructure.security import sha256_json


class AgentLineageTreeTests(unittest.TestCase):
    def test_root_persistent_child_session_tree(self):
        fixture = LineageFixture()
        child_wallet = LineageWallet.generate(AgentType.CHILD, delegable=True)
        child_permission = PolicyEngine().attenuate(
            fixture.first.permission,
            {
                "actions": ["read"],
                "resources": ["urn:tool:a"],
                "remaining_depth": 1,
                "delegable": True,
                "expires_at": fixture.now + 3600,
            },
            AgentType.CHILD,
            now=fixture.now,
        )
        child = create_delegation_credential(
            root_did=fixture.root_did,
            parent_did=fixture.persistent.did,
            parent_credential_hash=credential_hash(fixture.first),
            parent_lineage_commitment=fixture.first.lineage_commitment,
            child_did=child_wallet.did,
            child_operation_key=child_wallet.operation_address,
            child_delegation_key=child_wallet.delegation_address,
            agent_type=AgentType.CHILD,
            version_id=VERSION,
            replica_group_id=None,
            permission=child_permission,
            budget_id="0x" + "44" * 32,
            reservation=BudgetLimits(20, 200, 2),
            epoch=1,
            status_ref={"contract": ZERO_ADDRESS},
            issuer_delegation_private_key=fixture.persistent.delegation_private_key,
            chain_id=CHAIN_ID,
        )
        session_wallet = LineageWallet.generate(AgentType.SESSION)
        session_permission = PolicyEngine().attenuate(
            child.permission,
            {
                "remaining_depth": 0,
                "delegable": False,
                "expires_at": fixture.now + 1200,
            },
            AgentType.SESSION,
            now=fixture.now,
        )
        session = create_delegation_credential(
            root_did=fixture.root_did,
            parent_did=child_wallet.did,
            parent_credential_hash=credential_hash(child),
            parent_lineage_commitment=child.lineage_commitment,
            child_did=session_wallet.did,
            child_operation_key=session_wallet.operation_address,
            child_delegation_key=None,
            agent_type=AgentType.SESSION,
            version_id=VERSION,
            replica_group_id=None,
            permission=session_permission,
            budget_id="0x" + "55" * 32,
            reservation=BudgetLimits(5, 50, 1),
            epoch=1,
            status_ref={"contract": ZERO_ADDRESS},
            issuer_delegation_private_key=child_wallet.delegation_private_key,
            chain_id=CHAIN_ID,
        )
        body = {"input": "tree"}
        invocation = session_wallet.sign_invocation(
            LineageInvocation(
                leaf_did=session_wallet.did,
                credential_jti=session.jti,
                origin_did=session_wallet.did,
                on_behalf_of=fixture.root_did,
                audience="urn:gateway:test",
                task_id="task-1",
                action="read",
                resource="urn:tool:a",
                version_id=VERSION,
                body_hash=sha256_json(body),
                challenge="tree-challenge",
                sequence=1,
                timestamp=fixture.now,
                budget_id=session.budget_id,
                cost_units=1,
                lease_seconds=30,
            ),
            chain_id=CHAIN_ID,
        )
        decision = LineageVerifier(
            chain_id=CHAIN_ID,
            verifying_contract=ZERO_ADDRESS,
            state_provider=InMemoryStateProvider(),
        ).verify(
            fixture.epoch,
            [fixture.first, child, session],
            invocation,
            expected_audience="urn:gateway:test",
            expected_body_hash=sha256_json(body),
            now=fixture.now,
        )
        self.assertTrue(decision.accepted, decision)
        self.assertEqual(decision.chain_depth, 3)

    def test_root_replica_group_instance_tree_uses_independent_keys(self):
        fixture = LineageFixture()
        group_id = replica_group_id("replica-workers")
        group_budget_id = "0x" + "66" * 32
        permission = PermissionEnvelope(
            actions=("read",),
            resources=("urn:tool:a",),
            tasks=("task-1",),
            audiences=("urn:gateway:test",),
            versions=(VERSION,),
            not_before=fixture.now - 5,
            expires_at=fixture.now + 1800,
            remaining_depth=0,
            delegable=False,
        )
        instances = []
        for index in range(2):
            wallet = LineageWallet.generate(AgentType.INSTANCE)
            credential = create_delegation_credential(
                root_did=fixture.root_did,
                parent_did=fixture.root_did,
                parent_credential_hash=credential_hash(fixture.epoch),
                parent_lineage_commitment=credential_hash(fixture.epoch),
                child_did=wallet.did,
                child_operation_key=wallet.operation_address,
                child_delegation_key=None,
                agent_type=AgentType.INSTANCE,
                version_id=VERSION,
                replica_group_id=group_id,
                permission=permission,
                budget_id=group_budget_id,
                reservation=BudgetLimits(10, 100, 2),
                epoch=1,
                status_ref={"contract": ZERO_ADDRESS},
                issuer_delegation_private_key=fixture.epoch_key,
                chain_id=CHAIN_ID,
            )
            body = {"instance": index}
            invocation = wallet.sign_invocation(
                LineageInvocation(
                    leaf_did=wallet.did,
                    credential_jti=credential.jti,
                    origin_did=wallet.did,
                    on_behalf_of=fixture.root_did,
                    audience="urn:gateway:test",
                    task_id="task-1",
                    action="read",
                    resource="urn:tool:a",
                    version_id=VERSION,
                    body_hash=sha256_json(body),
                    challenge=f"instance-{index}",
                    sequence=index,
                    timestamp=fixture.now,
                    budget_id=group_budget_id,
                    cost_units=1,
                    lease_seconds=30,
                ),
                chain_id=CHAIN_ID,
            )
            decision = LineageVerifier(
                chain_id=CHAIN_ID,
                verifying_contract=ZERO_ADDRESS,
                state_provider=InMemoryStateProvider(),
            ).verify(
                fixture.epoch,
                [credential],
                invocation,
                expected_audience="urn:gateway:test",
                expected_body_hash=sha256_json(body),
                now=fixture.now,
            )
            self.assertTrue(decision.accepted, decision)
            instances.append((wallet, credential))
        self.assertNotEqual(instances[0][0].operation_address, instances[1][0].operation_address)
        self.assertEqual(instances[0][1].replica_group_id, instances[1][1].replica_group_id)
        self.assertEqual(instances[0][1].budget_id, instances[1][1].budget_id)


if __name__ == "__main__":
    unittest.main()
