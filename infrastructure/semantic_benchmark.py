"""Deterministic benchmark primitives for semantic-soundness experiments.

The two profiles deliberately have stable, human-reviewable artifact identities.
No model sampling or network access is involved in the ground-truth result.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Iterable


BENCHMARK_ID = "integer-addition-v1"
DEFAULT_THRESHOLD = 0.80
ARTIFACT_SOURCES = {
    "correct": "integer-addition-v1:correct:return a + b",
    "faulty": "integer-addition-v1:faulty:return a + b + 1",
}


def artifact_digest(profile: str) -> str:
    try:
        source = ARTIFACT_SOURCES[profile]
    except KeyError as exc:
        raise ValueError(f"Unknown artifact profile: {profile}") from exc
    return "sha256:" + hashlib.sha256(source.encode("utf-8")).hexdigest()


def execute(profile: str, a: int, b: int) -> int:
    if profile == "correct":
        return int(a) + int(b)
    if profile == "faulty":
        return int(a) + int(b) + 1
    raise ValueError(f"Unknown artifact profile: {profile}")


def benchmark_inputs(count: int = 100) -> list[dict[str, int]]:
    """Return a stable set containing positive, negative and zero operands."""

    if count <= 0:
        raise ValueError("count must be positive")
    return [
        {
            "case": index,
            "a": ((index * 37) % 211) - 105,
            "b": ((index * 61 + 17) % 223) - 111,
        }
        for index in range(count)
    ]


def sha256_json(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class BenchmarkResult:
    benchmark_id: str
    artifact_digest: str
    observed_score: float
    threshold: float
    qualified: bool
    input_count: int
    outputs_hash: str
    outputs: list[dict[str, int | bool]]

    def report(self) -> dict[str, object]:
        return {
            "benchmarkId": self.benchmark_id,
            "artifactDigest": self.artifact_digest,
            "observedScore": self.observed_score,
            "threshold": self.threshold,
            "qualified": self.qualified,
            "inputCount": self.input_count,
            "outputsHash": self.outputs_hash,
        }


def evaluate(
    profile: str,
    inputs: Iterable[dict[str, int]] | None = None,
    threshold: float = DEFAULT_THRESHOLD,
) -> BenchmarkResult:
    cases = list(inputs if inputs is not None else benchmark_inputs())
    if not cases:
        raise ValueError("inputs must not be empty")
    outputs: list[dict[str, int | bool]] = []
    correct_count = 0
    for case in cases:
        a, b = int(case["a"]), int(case["b"])
        expected = a + b
        actual = execute(profile, a, b)
        correct = actual == expected
        correct_count += int(correct)
        outputs.append({
            "case": int(case.get("case", len(outputs))),
            "a": a,
            "b": b,
            "expected": expected,
            "actual": actual,
            "correct": correct,
        })
    score = correct_count / len(outputs)
    return BenchmarkResult(
        benchmark_id=BENCHMARK_ID,
        artifact_digest=artifact_digest(profile),
        observed_score=score,
        threshold=float(threshold),
        qualified=score >= threshold,
        input_count=len(outputs),
        outputs_hash=sha256_json(outputs),
        outputs=outputs,
    )
