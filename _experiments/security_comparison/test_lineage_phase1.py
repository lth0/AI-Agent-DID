from __future__ import annotations

import dataclasses
import unittest

from _experiments.lineage.test_lineage_core import CHAIN_ID, LineageFixture
from _experiments.security_comparison.cases import (
    LINEAGE_PHASE1_CASE_IDS,
    LINEAGE_PHASE1_CHECKS,
    LINEAGE_REJECTION_CODES,
    SCHEMES,
    expected_outcome,
)
from _experiments.security_comparison.lineage_cases import _rebuild_leaf, _resign
from _experiments.security_comparison.run_lineage_phase1 import (
    build_lineage_phase1_plan,
)
from infrastructure.lineage import InMemoryStateProvider, LineageVerifier
from infrastructure.lineage.crypto import ZERO_ADDRESS
from infrastructure.lineage.registry_client import LineageRegistryClient


class _CountingState(InMemoryStateProvider):
    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    def validate_chain_state(self, epoch, credentials):
        self.calls += 1
        return super().validate_chain_state(epoch, credentials)


class LineageRobustnessTests(unittest.TestCase):
    def test_l01_to_l05_have_explicit_robustness_definitions(self) -> None:
        self.assertEqual(("L01", "L02", "L03", "L04", "L05"), LINEAGE_PHASE1_CASE_IDS)
        for case_id in LINEAGE_PHASE1_CASE_IDS:
            with self.subTest(case_id=case_id):
                definition = LINEAGE_PHASE1_CHECKS[case_id]
                self.assertTrue(definition["dimension"])
                self.assertTrue(definition["target"])
                self.assertTrue(definition["control"])
                self.assertTrue(definition["variation"])

    def test_l01_to_l05_preserve_the_three_scheme_vector(self) -> None:
        for case_id in LINEAGE_PHASE1_CASE_IDS:
            self.assertTrue(expected_outcome("original", case_id).accepted)
            self.assertTrue(expected_outcome("baseline", case_id).accepted)
            lineage = expected_outcome("lineage", case_id)
            self.assertFalse(lineage.accepted)
            self.assertEqual(LINEAGE_REJECTION_CODES[case_id], lineage.code)
            self.assertEqual("lineage-agentdid", lineage.detection_layer)

    def test_runner_builds_15_unique_subprocess_experiments(self) -> None:
        plan = build_lineage_phase1_plan("unit-lineage-phase1")
        self.assertEqual(15, len(plan))
        self.assertEqual(
            {(case_id, scheme) for case_id in LINEAGE_PHASE1_CASE_IDS for scheme in SCHEMES},
            {(item["case_id"], item["scheme"]) for item in plan},
        )
        self.assertEqual(15, len({item["experiment_id"] for item in plan}))
        self.assertEqual(15, len({item["lineage_epoch"] for item in plan}))

    def test_real_verifier_rejects_each_target_constraint_with_stable_code(self) -> None:
        for case_id in LINEAGE_PHASE1_CASE_IDS:
            with self.subTest(case_id=case_id):
                fixture = LineageFixture()
                invocation = fixture.invocation()
                presented_chain = [fixture.first, fixture.second]

                if case_id == "L01":
                    invocation = _resign(
                        invocation,
                        fixture.session,
                        CHAIN_ID,
                        ZERO_ADDRESS,
                        action="write",
                    )
                elif case_id == "L02":
                    invocation = _resign(
                        invocation,
                        fixture.session,
                        CHAIN_ID,
                        ZERO_ADDRESS,
                        resource="urn:tool:b",
                    )
                else:
                    permission = fixture.second.permission
                    if case_id == "L03":
                        permission = dataclasses.replace(
                            permission,
                            actions=("delete", "read"),
                        )
                        invocation = _resign(
                            invocation,
                            fixture.session,
                            CHAIN_ID,
                            ZERO_ADDRESS,
                            action="delete",
                        )
                    elif case_id == "L04":
                        permission = dataclasses.replace(
                            permission,
                            expires_at=fixture.first.permission.expires_at + 60,
                        )
                    elif case_id == "L05":
                        permission = dataclasses.replace(
                            permission,
                            remaining_depth=fixture.first.permission.remaining_depth,
                        )
                    presented_chain = [
                        fixture.first,
                        _rebuild_leaf(
                            original=fixture.second,
                            first=fixture.first,
                            permission=permission,
                            issuer_private_key=(
                                fixture.persistent.delegation_private_key
                            ),
                            chain_id=CHAIN_ID,
                            contract=ZERO_ADDRESS,
                        ),
                    ]

                state = _CountingState()
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
                if case_id in {"L01", "L02"}:
                    self.assertEqual(1, state.calls)
                else:
                    self.assertEqual(0, state.calls)

    def test_registry_state_binds_presented_credential_hash(self) -> None:
        fixture = LineageFixture()

        class _Call:
            def __init__(self, value):
                self.value = value

            def call(self, *, block_identifier):
                return self.value

        class _Functions:
            def delegations(self, _credential_id):
                record = [bytes(32)] * 16
                record[2] = bytes.fromhex("ff" * 32)
                record[14] = True
                return _Call(tuple(record))

            def getValidationState(self, *_args):
                raise AssertionError("hash mismatch must fail before status lookup")

        client = object.__new__(LineageRegistryClient)
        client.w3 = type("_W3", (), {
            "eth": type("_Eth", (), {"block_number": 77})(),
        })()
        client.contract = type("_Contract", (), {"functions": _Functions()})()

        active, reason, block = client.validate_chain_state(
            fixture.epoch,
            [fixture.first],
        )
        self.assertFalse(active)
        self.assertEqual("CREDENTIAL_HASH_MISMATCH", reason)
        self.assertEqual(77, block)


if __name__ == "__main__":
    unittest.main()
