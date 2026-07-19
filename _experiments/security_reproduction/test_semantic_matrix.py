from __future__ import annotations

import unittest

from _experiments.security_reproduction.semantic_matrix_core import (
    CASE_SPECS,
    merkle_root,
    run_case,
)
from infrastructure.semantic_benchmark import artifact_digest, evaluate, execute


class SemanticMatrixTests(unittest.TestCase):
    def test_artifacts_are_stable_and_distinct(self):
        self.assertNotEqual(artifact_digest("correct"), artifact_digest("faulty"))
        self.assertEqual(execute("correct", 2, 3), 5)
        self.assertEqual(execute("faulty", 2, 3), 6)

    def test_ground_truth_benchmark(self):
        good = evaluate("correct")
        bad = evaluate("faulty")
        self.assertEqual(good.observed_score, 1.0)
        self.assertEqual(bad.observed_score, 0.0)
        self.assertTrue(good.qualified)
        self.assertFalse(bad.qualified)

    def test_full_acceptance_vector(self):
        for case_id, spec in CASE_SPECS.items():
            with self.subTest(case_id=case_id):
                result = run_case(case_id)
                self.assertEqual(result["case_result"]["classification"], spec.expected)
                self.assertTrue(result["case_result"]["passed"])

    def test_target_cases_have_valid_crypto_and_wrong_actions(self):
        for case_id in ("C1", "H1"):
            result = run_case(case_id)
            self.assertTrue(result["case_result"]["cryptoOK"])
            self.assertTrue(result["case_result"]["wrongAction"])

    def test_merkle_root_changes_with_leaf(self):
        first = merkle_root(["00" * 32, "11" * 32])
        second = merkle_root(["00" * 32, "12" * 32])
        self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()
