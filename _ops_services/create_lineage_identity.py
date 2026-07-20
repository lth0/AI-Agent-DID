from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import requests

from infrastructure.lineage import AgentType, LineageWallet
from infrastructure.lineage.runtime import DEFAULT_CONFIG, LineageRuntimeConfig, PROJECT_ROOT


def main() -> None:
    parser = argparse.ArgumentParser(description="Create an encrypted AgentLineage child identity")
    parser.add_argument("--type", choices=[item.value for item in AgentType], required=True)
    parser.add_argument("--delegable", action="store_true")
    parser.add_argument("--challenge-url", help="Gateway base URL, for example http://127.0.0.1:8100")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument(
        "--key-dir", default=str(PROJECT_ROOT / ".codex" / "lineage" / "keys")
    )
    args = parser.parse_args()

    agent_type = AgentType(args.type)
    if args.delegable and agent_type in {AgentType.SESSION, AgentType.INSTANCE}:
        raise SystemExit(f"{agent_type.value} identities cannot delegate")
    password = os.getenv("AGENTLINEAGE_KEYSTORE_PASSWORD", "")
    if not password:
        raise SystemExit("AGENTLINEAGE_KEYSTORE_PASSWORD is required")

    wallet = LineageWallet.generate(agent_type, delegable=args.delegable)
    key_file = wallet.save_keystore(args.key_dir, password)
    summary = {"did": wallet.did, "agent_type": agent_type.value, "keystore": key_file}

    if args.challenge_url:
        base_url = args.challenge_url.rstrip("/")
        health = requests.get(f"{base_url}/health", timeout=10)
        health.raise_for_status()
        challenge = requests.post(f"{base_url}/v1/lineage/challenge", timeout=10)
        challenge.raise_for_status()
        config = LineageRuntimeConfig.load(args.config)
        root_did = health.json()["root_did"]
        challenge_body = challenge.json()
        proof = wallet.create_enrollment_proof(
            root_did=root_did,
            parent_did=challenge_body["parent_did"],
            nonce=challenge_body["nonce"],
            timestamp=int(time.time()),
            chain_id=config.chain_id,
            verifying_contract=config.registry_address,
        )
        enrollment_dir = PROJECT_ROOT / ".codex" / "lineage" / "enrollments"
        enrollment_dir.mkdir(parents=True, exist_ok=True)
        enrollment_file = enrollment_dir / f"{wallet.operation_address.lower()}.json"
        with enrollment_file.open("w", encoding="utf-8") as handle:
            json.dump({"enrollment_proof": proof}, handle, indent=2, sort_keys=True)
        summary["enrollment_request"] = str(enrollment_file)

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
