"""Send a signed reset request, or an explicit legacy unsigned attack request."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid

import requests


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from infrastructure.security import canonical_json  # noqa: E402
from infrastructure.wallet import IdentityWallet  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--holder-url", default="http://localhost:5000")
    parser.add_argument("--verifier-role", default="agent_c_op")
    parser.add_argument(
        "--unsigned",
        action="store_true",
        help="Reproduce the legacy unauthenticated reset; requires the Holder unsafe flag.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    wallet = IdentityWallet(args.verifier_role)
    payload = {
        "verifier_did": wallet.did,
        "type": "ResetMemory",
        "nonce": str(uuid.uuid4()),
        "timestamp": time.time(),
    }
    if args.unsigned:
        payload = {"verifier_did": wallet.did}
    else:
        payload["verifier_signature"] = wallet.sign_message(canonical_json(payload))

    response = requests.post(
        f"{args.holder_url.rstrip('/')}/reset_memory",
        json=payload,
        timeout=30,
    )
    print(json.dumps({
        "http_status": response.status_code,
        "response": response.json(),
        "unsigned": args.unsigned,
    }, indent=2, ensure_ascii=False))
    return 0 if response.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
