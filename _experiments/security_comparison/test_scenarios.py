from __future__ import annotations

import unittest
from typing import Any

from _experiments.security_comparison.cases import CASES
from _experiments.security_comparison.scenarios import build_control_scenario
from infrastructure.agentdid_protocol import recover_json
from infrastructure.security import canonical_json


AUDIENCE = "urn:agentdid:comparison:test-gateway"


def _contains_private_material(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = str(key).lower()
            if "private" in lowered or "secret" in lowered or "rpc_token" in lowered:
                return True
            if _contains_private_material(child):
                return True
    elif isinstance(value, list):
        return any(_contains_private_material(item) for item in value)
    return False


class ControlScenarioTests(unittest.TestCase):
    def build(self, case_id: str, suffix: str = "one") -> dict[str, Any]:
        return build_control_scenario(
            case_id,
            experiment_id=f"scenario-test-{case_id.lower()}-{suffix}",
            chain_id=31_337,
            audience=AUDIENCE,
        )

    def test_all_scenarios_are_signed_and_contain_no_private_material(self) -> None:
        for case in CASES:
            with self.subTest(case_id=case.case_id):
                scenario = self.build(case.case_id)
                signature = scenario.pop("signature")
                recovered = recover_json(scenario, signature)
                self.assertEqual(
                    scenario["leaf_operation_address"].lower(), recovered.lower()
                )
                self.assertFalse(_contains_private_material(scenario))

    def test_only_lineage_cases_mutate_the_legitimate_control_artifacts(self) -> None:
        for case in CASES:
            with self.subTest(case_id=case.case_id):
                scenario = self.build(case.case_id)
                current = {
                    "invocation": scenario["invocation"],
                    "delegation": scenario["delegation"],
                    "registry_state": scenario["registry_state"],
                }
                if case.case_id.startswith("L"):
                    self.assertNotEqual(
                        canonical_json(scenario["baseline"]), canonical_json(current)
                    )
                    self.assertNotEqual("legitimate", scenario["mutation"])
                else:
                    self.assertEqual(
                        canonical_json(scenario["baseline"]), canonical_json(current)
                    )
                    self.assertEqual("legitimate", scenario["mutation"])

    def test_attack_semantics_hash_is_stable_across_experiment_instances(self) -> None:
        for case in CASES:
            with self.subTest(case_id=case.case_id):
                first = self.build(case.case_id, "first")
                second = self.build(case.case_id, "second")
                self.assertEqual(
                    first["attack_semantics_hash"], second["attack_semantics_hash"]
                )

    def test_experiment_isolation_identifiers_are_unique(self) -> None:
        fields = (
            "leaf_did",
            "credential_jti",
            "epoch",
            "budget_id",
            "request_hash",
        )
        observed = {field: set() for field in fields}
        for case in CASES:
            scenario = self.build(case.case_id, "isolation")
            for field in fields:
                self.assertNotIn(scenario[field], observed[field])
                observed[field].add(scenario[field])
        for field in fields:
            self.assertEqual(len(CASES), len(observed[field]))


if __name__ == "__main__":
    unittest.main()
