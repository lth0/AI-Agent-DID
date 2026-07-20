from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from eth_account import Account
from web3 import Web3

from .crypto import LineageWallet, RootKeyManager, did_from_address
from .models import BudgetLimits, DelegationCredential, EpochKeyCertificate, PermissionEnvelope
from .registry_client import LineageRegistryClient


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = PROJECT_ROOT / "config" / "lineage.json"
DEFAULT_STATE = PROJECT_ROOT / ".codex" / "lineage" / "root_state.json"


@dataclass(frozen=True)
class LineageRuntimeConfig:
    raw: dict[str, Any]

    @classmethod
    def load(cls, path: str | os.PathLike[str] = DEFAULT_CONFIG) -> "LineageRuntimeConfig":
        with Path(path).open("r", encoding="utf-8") as handle:
            return cls(json.load(handle))

    @property
    def enabled(self) -> bool:
        value = os.getenv("AGENTLINEAGE_ENABLED")
        if value is not None:
            return value.lower() == "true"
        return bool(self.raw.get("enabled", False))

    @property
    def chain_id(self) -> int:
        return int(self.raw.get("chain_id", 11155111))

    @property
    def registry_address(self) -> str:
        return Web3.to_checksum_address(self.raw["registry_address"])

    @property
    def rpc_url(self) -> str:
        value = os.getenv("AGENTLINEAGE_RPC_URL", self.raw.get("rpc_url", ""))
        if not value:
            raise ValueError("AGENTLINEAGE_RPC_URL is required")
        return value

    def registry(self, *, require_relayer: bool = True) -> LineageRegistryClient:
        relayer_key = (
            require_private_key("AGENTLINEAGE_RELAYER_KEY")
            if require_relayer else os.getenv("AGENTLINEAGE_RELAYER_KEY") or None
        )
        return LineageRegistryClient(
            Web3(Web3.HTTPProvider(self.rpc_url)),
            self.registry_address,
            relayer_private_key=relayer_key,
            confirmations=int(self.raw.get("confirmations", 1)),
            receipt_timeout_seconds=int(self.raw.get("transaction_timeout_seconds", 600)),
            priority_fee_gwei=str(self.raw.get("priority_fee_gwei", "0.1")),
        )


def require_private_key(variable: str) -> str:
    value = os.getenv(variable, "")
    if not value:
        raise ValueError(f"{variable} is required")
    try:
        Account.from_key(value)
    except Exception as exc:
        raise ValueError(f"{variable} is not a valid secp256k1 private key") from exc
    return value


def root_did_from_environment() -> str:
    key = require_private_key("AGENTLINEAGE_ROOT_IDENTITY_KEY")
    return did_from_address(Account.from_key(key).address)


def load_public_state(path: str | os.PathLike[str] = DEFAULT_STATE) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def save_public_state(value: dict[str, Any], path: str | os.PathLike[str] = DEFAULT_STATE) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
    return target


def load_parent_authority_material(
    state: dict[str, Any], epoch: EpochKeyCertificate
) -> tuple[str, str, DelegationCredential | None]:
    parent_data = state.get("parent_credential")
    if parent_data:
        keystore_path = os.getenv("AGENTLINEAGE_PARENT_KEYSTORE", "")
        password = os.getenv("AGENTLINEAGE_KEYSTORE_PASSWORD", "")
        if not keystore_path or not password:
            raise ValueError(
                "AGENTLINEAGE_PARENT_KEYSTORE and AGENTLINEAGE_KEYSTORE_PASSWORD are required"
            )
        wallet = LineageWallet.load_keystore(keystore_path, password)
        credential = DelegationCredential.from_dict(parent_data)
        if wallet.did != credential.child_did or not wallet.delegation_private_key:
            raise ValueError("parent keystore does not match delegable parent credential")
        if wallet.delegation_address.lower() != credential.delegation_key.lower():
            raise ValueError("parent delegation key does not match credential")
        return wallet.did, wallet.delegation_private_key, credential

    manager = RootKeyManager.from_environment(epoch.root_did)
    epoch_key = manager.derive(epoch.epoch)
    if Account.from_key(epoch_key).address.lower() != epoch.delegation_key.lower():
        raise ValueError("derived epoch key does not match public root state")
    return epoch.root_did, epoch_key, None


def permission_from_state(state: dict[str, Any]) -> PermissionEnvelope:
    return PermissionEnvelope.from_dict(state["permission"])


def budget_from_config(config: LineageRuntimeConfig) -> BudgetLimits:
    return BudgetLimits.from_dict(config.raw["root_budget"])
