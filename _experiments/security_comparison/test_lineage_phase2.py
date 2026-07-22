from __future__ import annotations

import dataclasses
import unittest

from _experiments.lineage.test_lineage_core import CHAIN_ID, LineageFixture
from _experiments.security_comparison.cases import (
    CASE_BY_ID,
    LINEAGE_L06_L14_ROBUSTNESS_CASE_IDS,
    LINEAGE_L06_L14_ROBUSTNESS_CHECKS,
    LINEAGE_PHASE1_CASE_IDS,
    LINEAGE_REJECTION_CODES,
    SCHEMES,
    expected_outcome,
)
from _experiments.security_comparison.lineage_cases import (
    OTHER_AUDIENCE,
    OTHER_VERSION,
    _rebuild_leaf,
    _resign,
)
from _experiments.security_comparison.run_lineage_phase1 import (
    build_lineage_robustness_plan,
)
from _experiments.security_comparison.scenarios import build_control_scenario
from infrastructure.lineage import (
    AgentType,
    InMemoryStateProvider,
    LineageVerifier,
    LineageWallet,
)
from infrastructure.lineage.crypto import ZERO_ADDRESS, recover_typed_signer


class _CountingState(InMemoryStateProvider):
    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    def validate_chain_state(self, epoch, credentials):
        self.calls += 1
        return super().validate_chain_state(epoch, credentials)


class LineagePhase2RobustnessTests(unittest.TestCase):
    def test_l06_to_l14_are_explicit_robustness_checks(self) -> None:
        self.assertEqual(
            tuple(f"L{index:02d}" for index in range(6, 15)),
            LINEAGE_L06_L14_ROBUSTNESS_CASE_IDS,
        )
        for case_id in LINEAGE_L06_L14_ROBUSTNESS_CASE_IDS:
            with self.subTest(case_id=case_id):
                case = CASE_BY_ID[case_id]
                definition = LINEAGE_L06_L14_ROBUSTNESS_CHECKS[case_id]
                self.assertEqual("robustness_lineage", case.family)
                self.assertIn("robustness", case.name)
                self.assertNotIn("attack", case.description.lower())
                self.assertTrue(all(definition.values()))

    def test_phase_plans_remain_15_and_27_independent_experiments(self) -> None:
        phase1 = build_lineage_robustness_plan(
            "unit-phase1",
            LINEAGE_PHASE1_CASE_IDS,
        )
        phase2 = build_lineage_robustness_plan(
            "unit-phase2",
            LINEAGE_L06_L14_ROBUSTNESS_CASE_IDS,
        )
        self.assertEqual(15, len(phase1))
        self.assertEqual(27, len(phase2))
        self.assertEqual(27, len({item["experiment_id"] for item in phase2}))
        self.assertEqual(27, len({item["lineage_epoch"] for item in phase2}))
        self.assertEqual(
            {
                (case_id, scheme)
                for case_id in LINEAGE_L06_L14_ROBUSTNESS_CASE_IDS
                for scheme in SCHEMES
            },
            {(item["case_id"], item["scheme"]) for item in phase2},
        )

    def test_l06_to_l14_preserve_the_three_scheme_response_vector(self) -> None:
        for case_id in LINEAGE_L06_L14_ROBUSTNESS_CASE_IDS:
            with self.subTest(case_id=case_id):
                self.assertTrue(expected_outcome("original", case_id).accepted)
                self.assertTrue(expected_outcome("baseline", case_id).accepted)
                lineage = expected_outcome("lineage", case_id)
                self.assertFalse(lineage.accepted)
                self.assertEqual(LINEAGE_REJECTION_CODES[case_id], lineage.code)
                self.assertEqual("lineage-agentdid", lineage.detection_layer)

    def test_control_scenarios_publish_robustness_semantics(self) -> None:
        hashes = set()
        for case_id in LINEAGE_L06_L14_ROBUSTNESS_CASE_IDS:
            scenario = build_control_scenario(
                case_id,
                experiment_id=f"semantics-{case_id.lower()}",
                chain_id=CHAIN_ID,
                audience="urn:gateway:test",
            )
            self.assertEqual(
                "agent-lineage-robustness",
                scenario["scenario_semantics"]["family"],
            )
            hashes.add(scenario["scenario_semantics_hash"])
        self.assertEqual(9, len(hashes))

    def test_real_verifier_returns_each_stable_phase2_code(self) -> None:
        expected_state_calls = {
            "L06": 0,
            "L07": 0,
            "L08": 1,
            "L09": 0,
            "L10": 1,
            "L11": 1,
            "L12": 1,
            "L13": 1,
            "L14": 1,
        }
        for case_id in LINEAGE_L06_L14_ROBUSTNESS_CASE_IDS:
            with self.subTest(case_id=case_id):
                fixture = LineageFixture()
                invocation = fixture.invocation()
                presented_chain = [fixture.first, fixture.second]
                expected_request_signer = fixture.session.operation_address
                state = _CountingState()

                if case_id == "L06":
                    rogue = LineageWallet.generate(AgentType.CHILD, delegable=True)
                    permission = dataclasses.replace(
                        fixture.second.permission,
                        remaining_depth=1,
                        delegable=True,
                    )
                    presented_chain = [fixture.first, _rebuild_leaf(
                        original=fixture.second,
                        first=fixture.first,
                        permission=permission,
                        issuer_private_key=fixture.persistent.delegation_private_key,
                        chain_id=CHAIN_ID,
                        contract=ZERO_ADDRESS,
                        delegation_key=rogue.delegation_address,
                    )]
                elif case_id == "L07":
                    presented_chain = [fixture.first, _rebuild_leaf(
                        original=fixture.second,
                        first=fixture.first,
                        permission=fixture.second.permission,
                        issuer_private_key=fixture.persistent.operation_private_key,
                        chain_id=CHAIN_ID,
                        contract=ZERO_ADDRESS,
                    )]
                elif case_id == "L08":
                    sibling = LineageWallet.generate(AgentType.SESSION, delegable=False)
                    unsigned = dataclasses.replace(
                        invocation,
                        leaf_did=sibling.did,
                        origin_did=sibling.did,
                        signature="",
                    )
                    invocation = sibling.sign_invocation(
                        unsigned,
                        chain_id=CHAIN_ID,
                        verifying_contract=ZERO_ADDRESS,
                    )
                    expected_request_signer = sibling.operation_address
                elif case_id == "L09":
                    other_parent = LineageWallet.generate(
                        AgentType.PERSISTENT,
                        delegable=True,
                    )
                    presented_chain = [
                        fixture.first,
                        dataclasses.replace(
                            fixture.second,
                            parent_did=other_parent.did,
                        ),
                    ]
                elif case_id == "L10":
                    invocation = _resign(
                        invocation,
                        fixture.session,
                        CHAIN_ID,
                        ZERO_ADDRESS,
                        task_id="task-2",
                    )
                elif case_id == "L11":
                    invocation = _resign(
                        invocation,
                        fixture.session,
                        CHAIN_ID,
                        ZERO_ADDRESS,
                        audience=OTHER_AUDIENCE,
                    )
                elif case_id == "L12":
                    state.revoked_nodes.add(fixture.persistent.did)
                elif case_id == "L13":
                    invocation = _resign(
                        invocation,
                        fixture.session,
                        CHAIN_ID,
                        ZERO_ADDRESS,
                        origin_did=fixture.persistent.did,
                    )
                elif case_id == "L14":
                    invocation = _resign(
                        invocation,
                        fixture.session,
                        CHAIN_ID,
                        ZERO_ADDRESS,
                        version_id=OTHER_VERSION,
                    )

                recovered = recover_typed_signer(
                    invocation.unsigned_dict(),
                    invocation.signature,
                    purpose="AgentLineage/REQUEST/v1",
                    chain_id=CHAIN_ID,
                    verifying_contract=ZERO_ADDRESS,
                )
                self.assertEqual(
                    expected_request_signer.lower(),
                    recovered.lower(),
                )

                decision = LineageVerifier(
                    chain_id=CHAIN_ID,
                    verifying_contract=ZERO_ADDRESS,
                    state_provider=state,
                ).verify(
                    fixture.epoch,
                    presented_chain,
                    invocation,
                    expected_audience="urn:gateway:test",
                    expected_body_hash=invocation.body_hash,
                    now=fixture.now,
                )
                self.assertFalse(decision.accepted)
                self.assertEqual(LINEAGE_REJECTION_CODES[case_id], decision.code)
                self.assertEqual(2, decision.chain_depth)
                self.assertEqual(expected_state_calls[case_id], state.calls)


if __name__ == "__main__":
    unittest.main()
