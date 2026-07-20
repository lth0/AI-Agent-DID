from __future__ import annotations

import argparse
import json
from pathlib import Path

from web3 import Web3


def main() -> None:
    parser = argparse.ArgumentParser(description="Create ignored AgentLineage runtime config")
    parser.add_argument("--template", default="config/lineage_example.json")
    parser.add_argument("--key-config", default="config/key.json")
    parser.add_argument("--output", default="config/lineage.json")
    parser.add_argument(
        "--registry-address",
        default="0x0000000000000000000000000000000000000000",
    )
    parser.add_argument("--enable", action="store_true")
    args = parser.parse_args()

    with Path(args.template).open("r", encoding="utf-8") as handle:
        config = json.load(handle)
    with Path(args.key_config).open("r", encoding="utf-8") as handle:
        key_config = json.load(handle)
    rpc_url = key_config.get("api_url", "")
    if not rpc_url:
        raise SystemExit("source key config does not contain api_url")
    if not Web3.is_address(args.registry_address):
        raise SystemExit("registry address is invalid")
    config["rpc_url"] = rpc_url
    config["registry_address"] = Web3.to_checksum_address(args.registry_address)
    config["enabled"] = bool(args.enable)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2, sort_keys=True)
    print(json.dumps({
        "output": str(output.resolve()),
        "enabled": config["enabled"],
        "registry_address": config["registry_address"],
        "rpc_configured": True,
    }, indent=2))


if __name__ == "__main__":
    main()
