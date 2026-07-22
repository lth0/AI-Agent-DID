from __future__ import annotations

import unittest

from _experiments.security_comparison.cases import (
    CASE_BY_ID,
    ROBUSTNESS_CASE_IDS,
    SCHEMES,
    expected_outcome,
)
from _experiments.security_comparison.run_robustness import build_robustness_plan


class RobustnessCaseTests(unittest.TestCase):
    def test_a01_to_a06_are_classified_as_robustness_checks(self) -> None:
        self.assertEqual(
            ("A01", "A02", "A03", "A04", "A05", "A06"),
            ROBUSTNESS_CASE_IDS,
        )
        for case_id in ROBUSTNESS_CASE_IDS:
            case = CASE_BY_ID[case_id]
            with self.subTest(case_id=case_id):
                self.assertTrue(case.family.startswith("robustness_"))
                self.assertIn("robustness", case.name)
                self.assertNotIn("attack", case.description.lower())
                self.assertNotIn("attacker", case.description.lower())

    def test_robustness_vector_preserves_the_target_detection_layers(self) -> None:
        for case_id in ("A01", "A02", "A03"):
            for scheme in SCHEMES:
                outcome = expected_outcome(scheme, case_id)
                self.assertFalse(outcome.accepted)
                self.assertEqual("did-vc-vp", outcome.detection_layer)
        for case_id in ("A04", "A05", "A06"):
            self.assertTrue(expected_outcome("original", case_id).accepted)
            for scheme in ("baseline", "lineage"):
                outcome = expected_outcome(scheme, case_id)
                self.assertFalse(outcome.accepted)
                self.assertEqual("baseline-agentdid", outcome.detection_layer)

    def test_runner_builds_18_unique_subprocess_experiments(self) -> None:
        plan = build_robustness_plan("unit-robustness")
        self.assertEqual(18, len(plan))
        self.assertEqual(
            {(case_id, scheme) for case_id in ROBUSTNESS_CASE_IDS for scheme in SCHEMES},
            {(item["case_id"], item["scheme"]) for item in plan},
        )
        self.assertEqual(18, len({item["experiment_id"] for item in plan}))
        self.assertEqual(18, len({item["lineage_epoch"] for item in plan}))


if __name__ == "__main__":
    unittest.main()
