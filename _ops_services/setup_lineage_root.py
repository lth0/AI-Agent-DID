from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from eth_account import Account

from infrastructure.lineage import BudgetLimits, PermissionEnvelope, RootKeyManager, create_epoch_certificate
from infrastructure.lineage.crypto import did_from_address
from infrastructure.lineage.registry_client import bytes32_hex
from infrastructure.lineage.runtime import (
    DEFAULT_CONFIG,
    DEFAULT_STATE,
    LineageRuntimeConfig,
    load_public_state,
    require_private_key,
    save_public_state,
)


def _root_permission(config: LineageRuntimeConfig, now: int, epoch_expires_at: int):
    policy = dict(config.raw["root_permission"])
    policy["not_before"] = now - 60
    policy["expires_at"] = min(
        now + int(policy.pop("ttl_seconds", 30 * 24 * 60 * 60)),
        epoch_expires_at,
    )
    return PermissionEnvelope.from_dict(policy)


def initialize_root(config_path: str, state_path: str, epoch_number: int) -> dict:
    config = LineageRuntimeConfig.load(config_path)
    registry = config.registry(require_relayer=False)
    root_private_key = require_private_key("AGENTLINEAGE_ROOT_IDENTITY_KEY")
    root_did = did_from_address(Account.from_key(root_private_key).address)
    manager = RootKeyManager.from_environment(root_did)
    epoch_private_key = manager.derive(epoch_number)
    now = int(time.time())
    epoch_ttl = int(config.raw.get("epoch_ttl_seconds", 30 * 24 * 60 * 60))
    epoch = create_epoch_certificate(
        root_did=root_did,
        epoch=epoch_number,
        delegation_key=Account.from_key(epoch_private_key).address,
        not_before=now - 60,
        expires_at=now + epoch_ttl,
        status_ref={"chain_id": config.chain_id, "contract": config.registry_address},
        root_identity_private_key=root_private_key,
        chain_id=config.chain_id,
        verifying_contract=config.registry_address,
    )
    permission = _root_permission(config, now, epoch.expires_at)
    budget_id = config.raw.get("root_budget_id") or bytes32_hex(
        f"{root_did}:epoch:{epoch_number}:root-budget"
    )
    root_tx = registry.register_root(epoch, root_private_key)
    budget_tx = registry.create_root_budget(
        root_did,
        budget_id,
        BudgetLimits.from_dict(config.raw["root_budget"]),
        root_private_key,
    )
    state = {
        "schema": "agentlineage-root-state-v1",
        "root_did": root_did,
        "parent_did": root_did,
        "epoch_certificate": epoch.to_dict(),
        "permission": permission.to_dict(),
        "parent_budget_id": budget_id,
        "parent_credential": None,
        "registry_address": config.registry_address,
        "chain_id": config.chain_id,
        "transactions": {"register_root": root_tx, "create_root_budget": budget_tx},
    }
    save_public_state(state, state_path)
    return state


def rotate_root(config_path: str, state_path: str, epoch_number: int | None = None) -> dict:
    config = LineageRuntimeConfig.load(config_path)
    previous = load_public_state(state_path)
    if previous["registry_address"].lower() != config.registry_address.lower():
        raise ValueError("public state registry does not match lineage config")
    root_private_key = require_private_key("AGENTLINEAGE_ROOT_IDENTITY_KEY")
    root_did = did_from_address(Account.from_key(root_private_key).address)
    if root_did != previous["root_did"]:
        raise ValueError("root identity key does not match public state")
    current_epoch = int(previous["epoch_certificate"]["epoch"])
    next_epoch = epoch_number if epoch_number is not None else current_epoch + 1
    if next_epoch <= current_epoch:
        raise ValueError("new epoch must be greater than current epoch")

    manager = RootKeyManager.from_environment(root_did)
    epoch_private_key = manager.derive(next_epoch)
    now = int(time.time())
    epoch_ttl = int(config.raw.get("epoch_ttl_seconds", 30 * 24 * 60 * 60))
    epoch = create_epoch_certificate(
        root_did=root_did,
        epoch=next_epoch,
        delegation_key=Account.from_key(epoch_private_key).address,
        not_before=now - 60,
        expires_at=now + epoch_ttl,
        status_ref={"chain_id": config.chain_id, "contract": config.registry_address},
        root_identity_private_key=root_private_key,
        chain_id=config.chain_id,
        verifying_contract=config.registry_address,
    )
    budget_id = bytes32_hex(f"{root_did}:epoch:{next_epoch}:root-budget")
    registry = config.registry(require_relayer=False)
    rotate_tx = registry.rotate_epoch(epoch, root_private_key, revoke_previous=True)
    budget_tx = registry.create_root_budget(
        root_did,
        budget_id,
        BudgetLimits.from_dict(config.raw["root_budget"]),
        root_private_key,
    )
    state = {
        "schema": "agentlineage-root-state-v1",
        "root_did": root_did,
        "parent_did": root_did,
        "epoch_certificate": epoch.to_dict(),
        "permission": _root_permission(config, now, epoch.expires_at).to_dict(),
        "parent_budget_id": budget_id,
        "parent_credential": None,
        "registry_address": config.registry_address,
        "chain_id": config.chain_id,
        "transactions": {"rotate_epoch": rotate_tx, "create_root_budget": budget_tx},
    }
    save_public_state(state, state_path)
    return state


def main() -> None:
    parser = argparse.ArgumentParser(description="Register an AgentLineage root and root budget")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--state", default=str(DEFAULT_STATE))
    parser.add_argument("--epoch", type=int)
    parser.add_argument("--rotate", action="store_true")
    args = parser.parse_args()
    state_file = Path(args.state)
    if state_file.exists():
        if not args.rotate:
            raise SystemExit(f"public root state already exists: {state_file}; use --rotate")
        state = rotate_root(args.config, args.state, args.epoch)
    else:
        state = initialize_root(args.config, args.state, args.epoch or 1)
    print(json.dumps({
        "root_did": state["root_did"],
        "registry_address": state["registry_address"],
        "parent_budget_id": state["parent_budget_id"],
        "state_file": str(state_file.resolve()),
    }, indent=2))


if __name__ == "__main__":
    main()
