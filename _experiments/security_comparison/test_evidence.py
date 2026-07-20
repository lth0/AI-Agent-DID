from __future__ import annotations

import json
import unittest
import uuid
from pathlib import Path

from _experiments.security_comparison.evidence import (
    ComparisonAuditRecorder,
    build_evidence_manifest,
)
from infrastructure.security import sha256_json, verify_evidence_event


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class ComparisonEvidenceTests(unittest.TestCase):
    def output_directory(self, label: str) -> Path:
        directory = (
            PROJECT_ROOT
            / ".codex"
            / "test_evidence"
            / f"{label}-{uuid.uuid4().hex}"
        )
        directory.mkdir(parents=True, exist_ok=False)
        return directory

    def test_merkle_root_binds_each_hash_to_its_relative_path(self) -> None:
        directory = self.output_directory("path-binding")
        first = directory / "first.json"
        second = directory / "second.json"
        first.write_text('{"value":"A"}\n', encoding="utf-8")
        second.write_text('{"value":"B"}\n', encoding="utf-8")
        before = build_evidence_manifest(
            directory, run_id="evidence-test", experiment_id="before"
        )

        first.write_text('{"value":"B"}\n', encoding="utf-8")
        second.write_text('{"value":"A"}\n', encoding="utf-8")
        after = build_evidence_manifest(
            directory, run_id="evidence-test", experiment_id="after"
        )

        self.assertNotEqual(before["merkle_root"], after["merkle_root"])
        self.assertEqual(
            set(before["files"]), set(before["merkle_leaves"])
        )

    def test_audit_events_form_a_verifiable_previous_hash_chain(self) -> None:
        directory = self.output_directory("audit-chain")
        audit_path = directory / "audit.jsonl"
        recorder = ComparisonAuditRecorder(
            audit_path,
            run_id="evidence-test",
            experiment_id="audit-chain",
            scheme="Baseline-AgentDID",
            case_id="A04",
        )
        first = recorder.record(
            "first", accepted=True, code="FIRST", detection_layer="test"
        )
        second = recorder.record(
            "second", accepted=False, code="SECOND", detection_layer="test"
        )

        events = [
            json.loads(line)
            for line in audit_path.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(2, len(events))
        self.assertIsNone(events[0]["previous_evidence_hash"])
        self.assertEqual(first["evidence_hash"], events[1]["previous_evidence_hash"])
        self.assertEqual(second["evidence_hash"], events[1]["evidence_hash"])
        for event in events:
            valid, reason = verify_evidence_event(event)
            self.assertTrue(valid, reason)
            body = dict(event)
            claimed = body.pop("evidence_hash")
            self.assertEqual(claimed, sha256_json(body))


if __name__ == "__main__":
    unittest.main()
