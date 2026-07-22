from __future__ import annotations

import itertools
import unittest
from typing import Any

from _experiments.security_comparison.adapters import (
    ADAPTERS,
    BaselineAgentDidAdapter,
    ExperimentBundle,
    LineageAgentDidAdapter,
    OriginalAgentDidAdapter,
    SchemeAdapter,
    build_experiment_bundle,
    get_adapter,
)
from _experiments.security_comparison.cases import (
    CASES,
    CASE_BY_ID,
    SCHEMES,
)
from _experiments.security_comparison.chain import (
    ActorKeys,
    ChainConfig,
    load_actor_keys,
)


DUMMY_CHAIN_CONFIG = ChainConfig(
    backend="hardhat",
    rpc_url="http://127.0.0.1:0",
    chain_id=31337,
    did_registry_address="0x0000000000000000000000000000000000000001",
    lineage_registry_address="0x0000000000000000000000000000000000000002",
)

LINEAGE_CASE_IDS = frozenset(f"L{number:02d}" for number in range(1, 15))
EXPECTED_ACCEPTED_CASES = {
    "original": LINEAGE_CASE_IDS | {"H00", "A04", "A05", "A06"},
    "baseline": LINEAGE_CASE_IDS | {"H00"},
    "lineage": frozenset({"H00"}),
}
LINEAGE_CODES = {
    "L01": "PERMISSION_DENIED",
    "L02": "PERMISSION_DENIED",
    "L03": "POLICY_ESCALATION",
    "L04": "POLICY_ESCALATION",
    "L05": "POLICY_ESCALATION",
    "L06": "IDENTITY_POLICY_INVALID",
    "L07": "DELEGATION_SIGNATURE_INVALID",
    "L08": "LEAF_BINDING_MISMATCH",
    "L09": "PARENT_MISMATCH",
    "L10": "PERMISSION_DENIED",
    "L11": "AUDIENCE_MISMATCH",
    "L12": "STATUS_REVOKED",
    "L13": "ORIGIN_MISMATCH",
    "L14": "VERSION_MISMATCH",
}


def expected_terminal(scheme: str, case_id: str) -> tuple[str, str]:
    if case_id == "H00":
        return {
            "original": ("ORIGINAL_IDENTITY_ACCEPTED", "original-agentdid"),
            "baseline": ("BASELINE_ACCEPTED", "baseline-agentdid"),
            "lineage": ("ACCEPTED", "lineage-agentdid"),
        }[scheme]
    if case_id in {"A01", "A02", "A03"}:
        return {
            "A01": ("VP_SIGNATURE_INVALID", "did-vc-vp"),
            "A02": ("VP_CHALLENGE_MISMATCH", "did-vc-vp"),
            "A03": ("VC_SUBJECT_HOLDER_MISMATCH", "did-vc-vp"),
        }[case_id]
    if case_id in {"A04", "A05", "A06"}:
        if scheme == "original":
            return "ORIGINAL_IDENTITY_ACCEPTED", "original-agentdid"
        return {
            "A04": ("CAPABILITY_EVIDENCE_MISMATCH", "baseline-agentdid"),
            "A05": ("STATE_GROUND_TRUTH_MISMATCH", "baseline-agentdid"),
            "A06": ("CONTEXT_CONTINUITY_MISMATCH", "baseline-agentdid"),
        }[case_id]
    if scheme == "original":
        return "ORIGINAL_IDENTITY_ACCEPTED", "original-agentdid"
    if scheme == "baseline":
        return "BASELINE_ACCEPTED", "baseline-agentdid"
    return LINEAGE_CODES[case_id], "lineage-agentdid"


class FakeLineage:
    """Chain-free Lineage policy result used to isolate adapter ordering."""

    def __init__(self, case_id: str) -> None:
        self.case_id = case_id
        self.evaluate_calls = 0
        self.transactions: list[dict[str, Any]] = []

    def evaluate(self) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        self.evaluate_calls += 1
        if self.case_id == "H00":
            decision = {
                "accepted": True,
                "code": "ACCEPTED",
                "reason": "fake lineage policy accepted the legitimate request",
                "execution_output": {"sum": 42},
            }
        elif self.case_id.startswith("L"):
            decision = {
                "accepted": False,
                "code": LINEAGE_CODES[self.case_id],
                "reason": f"fake lineage policy rejected {self.case_id}",
            }
        else:
            # AgentDID robustness cases must be decided below Lineage.  Accepting here
            # makes any accidental fall-through visible to the tests.
            decision = {
                "accepted": True,
                "code": "ACCEPTED",
                "reason": "fake lineage policy intentionally did not mask a lower-layer bug",
            }
        return decision, list(self.transactions)


class ThreeSchemeAdapterTests(unittest.TestCase):
    _experiment_numbers = itertools.count(1)
    actor_keys: ActorKeys

    @classmethod
    def setUpClass(cls) -> None:
        cls.actor_keys = load_actor_keys("hardhat")

    def fresh_bundle(
        self,
        scheme: str,
        case_id: str,
    ) -> tuple[ExperimentBundle, FakeLineage | None]:
        """Build a new bundle so no ReplayGuard state crosses evaluations."""

        number = next(self._experiment_numbers)
        source_scheme = "baseline" if scheme == "lineage" else scheme
        bundle = build_experiment_bundle(
            CASE_BY_ID[case_id],
            source_scheme,
            experiment_id=f"unit-{scheme}-{case_id.lower()}-{number}",
            run_id="three-scheme-adapter-tests",
            lineage_epoch=number,
            chain_config=DUMMY_CHAIN_CONFIG,
            actor_keys=self.actor_keys,
        )
        fake_lineage = None
        if scheme == "lineage":
            fake_lineage = FakeLineage(case_id)
            bundle.scheme = "lineage"
            bundle.lineage = fake_lineage  # type: ignore[assignment]
        return bundle, fake_lineage

    def evaluate_fresh(
        self,
        scheme: str,
        case_id: str,
    ) -> tuple[Any, FakeLineage | None]:
        bundle, fake_lineage = self.fresh_bundle(scheme, case_id)
        return get_adapter(scheme).evaluate(bundle), fake_lineage

    def test_only_three_formal_adapters_are_registered(self) -> None:
        self.assertEqual(("original", "baseline", "lineage"), tuple(ADAPTERS))
        self.assertEqual(3, len(ADAPTERS))
        self.assertIsInstance(get_adapter("original"), OriginalAgentDidAdapter)
        self.assertIsInstance(get_adapter("baseline"), BaselineAgentDidAdapter)
        self.assertIsInstance(get_adapter("lineage"), LineageAgentDidAdapter)
        self.assertTrue(all(isinstance(adapter, SchemeAdapter) for adapter in ADAPTERS.values()))

    def test_h00_is_accepted_by_all_three_schemes_with_independent_state(self) -> None:
        expected = {
            "original": ("ORIGINAL_IDENTITY_ACCEPTED", "original-agentdid"),
            "baseline": ("BASELINE_ACCEPTED", "baseline-agentdid"),
            "lineage": ("ACCEPTED", "lineage-agentdid"),
        }
        replay_guards = set()
        challenges = set()
        vp_hashes = set()

        for scheme in SCHEMES:
            with self.subTest(scheme=scheme):
                bundle, fake_lineage = self.fresh_bundle(scheme, "H00")
                decision = get_adapter(scheme).evaluate(bundle)

                self.assertTrue(decision.accepted, decision.to_dict())
                self.assertEqual(expected[scheme][0], decision.code)
                self.assertEqual(expected[scheme][1], decision.detection_layer)
                self.assertTrue(decision.protocol["accepted"])
                if scheme in {"baseline", "lineage"}:
                    self.assertIsNotNone(decision.baseline)
                    self.assertTrue(decision.baseline["accepted"])
                if scheme == "lineage":
                    self.assertIsNotNone(decision.lineage)
                    self.assertTrue(decision.lineage["accepted"])
                    self.assertEqual({"sum": 42}, decision.lineage["execution_output"])
                    self.assertIsNotNone(fake_lineage)
                    self.assertEqual(1, fake_lineage.evaluate_calls)

                replay_guards.add(bundle.independent_state["replay_guard_id"])
                challenges.add(bundle.independent_state["vp_challenge"])
                vp_hashes.add(bundle.independent_state["vp_hash"])

        self.assertEqual(3, len(replay_guards))
        self.assertEqual(3, len(challenges))
        self.assertEqual(3, len(vp_hashes))

    def test_all_21_cases_across_three_schemes_match_the_63_item_vector(self) -> None:
        self.assertEqual(21, len(CASES))
        evaluated = 0
        for case in CASES:
            for scheme in SCHEMES:
                with self.subTest(scheme=scheme, case_id=case.case_id):
                    decision, _ = self.evaluate_fresh(scheme, case.case_id)
                    self.assertEqual(
                        case.case_id in EXPECTED_ACCEPTED_CASES[scheme],
                        decision.accepted,
                        decision.to_dict(),
                    )
                    expected_code, expected_layer = expected_terminal(
                        scheme, case.case_id
                    )
                    self.assertEqual(expected_code, decision.code)
                    self.assertEqual(expected_layer, decision.detection_layer)
                    if expected_layer != "did-vc-vp":
                        self.assertTrue(decision.protocol["accepted"])
                    if scheme == "lineage" and case.case_id.startswith("L"):
                        self.assertTrue(decision.baseline["accepted"])
                    evaluated += 1
        self.assertEqual(63, evaluated)

    def test_a02_is_rejected_by_the_protocol_layer_for_every_scheme(self) -> None:
        for scheme in SCHEMES:
            with self.subTest(scheme=scheme):
                decision, fake_lineage = self.evaluate_fresh(scheme, "A02")
                self.assertFalse(decision.accepted)
                self.assertEqual("VP_CHALLENGE_MISMATCH", decision.code)
                self.assertEqual("did-vc-vp", decision.detection_layer)
                self.assertEqual("VP_CHALLENGE_MISMATCH", decision.protocol["code"])
                if fake_lineage is not None:
                    self.assertEqual(0, fake_lineage.evaluate_calls)

    def test_a04_is_accepted_only_by_original_and_rejected_at_baseline(self) -> None:
        original, _ = self.evaluate_fresh("original", "A04")
        self.assertTrue(original.accepted)
        self.assertEqual("ORIGINAL_IDENTITY_ACCEPTED", original.code)

        for scheme in ("baseline", "lineage"):
            with self.subTest(scheme=scheme):
                decision, fake_lineage = self.evaluate_fresh(scheme, "A04")
                self.assertFalse(decision.accepted)
                self.assertTrue(decision.protocol["accepted"])
                self.assertEqual("CAPABILITY_EVIDENCE_MISMATCH", decision.code)
                self.assertEqual("baseline-agentdid", decision.detection_layer)
                self.assertIsNotNone(decision.baseline)
                self.assertFalse(decision.baseline["accepted"])
                if fake_lineage is not None:
                    self.assertEqual(0, fake_lineage.evaluate_calls)

    def test_a05_and_a06_have_stable_baseline_error_codes(self) -> None:
        expected_codes = {
            "A05": "STATE_GROUND_TRUTH_MISMATCH",
            "A06": "CONTEXT_CONTINUITY_MISMATCH",
        }
        for case_id, expected_code in expected_codes.items():
            for scheme in ("baseline", "lineage"):
                with self.subTest(scheme=scheme, case_id=case_id):
                    decision, fake_lineage = self.evaluate_fresh(scheme, case_id)
                    self.assertFalse(decision.accepted)
                    self.assertTrue(decision.protocol["accepted"])
                    self.assertEqual(expected_code, decision.code)
                    self.assertEqual("baseline-agentdid", decision.detection_layer)
                    if fake_lineage is not None:
                        self.assertEqual(0, fake_lineage.evaluate_calls)

    def test_l01_is_rejected_only_after_protocol_and_baseline_pass(self) -> None:
        original, _ = self.evaluate_fresh("original", "L01")
        baseline, _ = self.evaluate_fresh("baseline", "L01")
        lineage, fake_lineage = self.evaluate_fresh("lineage", "L01")

        self.assertTrue(original.accepted)
        self.assertTrue(original.protocol["accepted"])
        self.assertTrue(baseline.accepted)
        self.assertTrue(baseline.protocol["accepted"])
        self.assertTrue(baseline.baseline["accepted"])

        self.assertFalse(lineage.accepted)
        self.assertEqual("PERMISSION_DENIED", lineage.code)
        self.assertEqual("lineage-agentdid", lineage.detection_layer)
        self.assertTrue(lineage.protocol["accepted"])
        self.assertTrue(lineage.baseline["accepted"])
        self.assertEqual("BASELINE_ACCEPTED", lineage.baseline["code"])
        self.assertIsNotNone(fake_lineage)
        self.assertEqual(1, fake_lineage.evaluate_calls)

    def test_l01_to_l05_reach_only_the_intended_lineage_constraint(self) -> None:
        for case_id in ("L01", "L02", "L03", "L04", "L05"):
            with self.subTest(case_id=case_id):
                original, _ = self.evaluate_fresh("original", case_id)
                baseline, _ = self.evaluate_fresh("baseline", case_id)
                lineage, fake_lineage = self.evaluate_fresh("lineage", case_id)

                self.assertTrue(original.accepted)
                self.assertTrue(original.protocol["accepted"])
                self.assertTrue(baseline.accepted)
                self.assertTrue(baseline.protocol["accepted"])
                self.assertTrue(baseline.baseline["accepted"])

                self.assertFalse(lineage.accepted)
                self.assertEqual(LINEAGE_CODES[case_id], lineage.code)
                self.assertEqual("lineage-agentdid", lineage.detection_layer)
                self.assertTrue(lineage.protocol["accepted"])
                self.assertTrue(lineage.baseline["accepted"])
                self.assertIsNotNone(lineage.lineage)
                self.assertFalse(lineage.lineage["accepted"])
                self.assertIsNotNone(fake_lineage)
                self.assertEqual(1, fake_lineage.evaluate_calls)

    def test_lineage_is_not_called_when_baseline_fails(self) -> None:
        bundle, fake_lineage = self.fresh_bundle("lineage", "A04")
        self.assertIsNotNone(fake_lineage)

        decision = get_adapter("lineage").evaluate(bundle)

        self.assertFalse(decision.accepted)
        self.assertEqual("CAPABILITY_EVIDENCE_MISMATCH", decision.code)
        self.assertEqual("baseline-agentdid", decision.detection_layer)
        self.assertEqual(0, fake_lineage.evaluate_calls)


if __name__ == "__main__":
    unittest.main()
