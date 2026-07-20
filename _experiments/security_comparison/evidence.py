from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import threading
import uuid
from pathlib import Path
from typing import Any

from infrastructure.security import canonical_json, sha256_json


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def merkle_root(hex_hashes: list[str]) -> str:
    if not hex_hashes:
        return hashlib.sha256(b"").hexdigest()
    level = [bytes.fromhex(value) for value in hex_hashes]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(level[index] + level[index + 1]).digest()
            for index in range(0, len(level), 2)
        ]
    return level[0].hex()


class ComparisonAuditRecorder:
    def __init__(self, output_file: Path, *, run_id: str, experiment_id: str, scheme: str, case_id: str):
        self.output_file = output_file
        self.run_id = run_id
        self.experiment_id = experiment_id
        self.scheme = scheme
        self.case_id = case_id
        self.previous_hash: str | None = None
        self._lock = threading.Lock()
        output_file.parent.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        event_type: str,
        *,
        accepted: bool | None,
        code: str,
        detection_layer: str,
        request_hash: str | None = None,
        response_hash: str | None = None,
        **metadata: Any,
    ) -> dict[str, Any]:
        event = {
            "schema_version": "agentdid-comparison-security-v1",
            "event_id": str(uuid.uuid4()),
            "run_id": self.run_id,
            "experiment_id": self.experiment_id,
            "scheme": self.scheme,
            "case_id": self.case_id,
            "event_type": event_type,
            "accepted": accepted,
            "code": code,
            "detection_layer": detection_layer,
            "request_hash": request_hash,
            "response_hash": response_hash,
            "previous_evidence_hash": self.previous_hash,
            "observed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "metadata": metadata,
        }
        event["evidence_hash"] = sha256_json(event)
        with self._lock:
            with self.output_file.open("a", encoding="utf-8") as handle:
                handle.write(canonical_json(event) + "\n")
        self.previous_hash = event["evidence_hash"]
        return event


def build_evidence_manifest(directory: Path, *, run_id: str, experiment_id: str) -> dict[str, Any]:
    excluded = {"evidence-manifest.json", "chain-anchor.json"}
    files: dict[str, str] = {}
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.name in excluded:
            continue
        relative = path.relative_to(directory).as_posix()
        files[relative] = file_sha256(path)
    leaves = {
        name: sha256_json({"path": name, "sha256": files[name]})
        for name in sorted(files)
    }
    manifest = {
        "schema_version": "agentdid-comparison-evidence-v2",
        "run_id": run_id,
        "experiment_id": experiment_id,
        "files": files,
        "merkle_leaves": leaves,
        "merkle_root": merkle_root([leaves[name] for name in sorted(leaves)]),
    }
    write_json(directory / "evidence-manifest.json", manifest)
    return manifest


def finalize_experiment(temp_directory: Path, final_directory: Path) -> None:
    temp_resolved = temp_directory.resolve()
    final_resolved = final_directory.resolve()
    if temp_resolved == final_resolved:
        return
    if final_resolved.exists():
        raise FileExistsError(f"experiment output already exists: {final_resolved}")
    final_resolved.parent.mkdir(parents=True, exist_ok=True)
    if os.path.splitdrive(str(temp_resolved))[0].lower() != os.path.splitdrive(str(final_resolved))[0].lower():
        raise ValueError("temporary and final experiment directories must share one volume")
    temp_resolved.replace(final_resolved)
