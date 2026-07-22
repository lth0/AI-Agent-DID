"""Strict Sepolia preflight checks for the AgentDID comparison runner."""

from __future__ import annotations

import hashlib
import os
import shutil
from collections import defaultdict
from collections.abc import Mapping
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable

from eth_abi import encode
from eth_account import Account
from web3 import Web3

from _experiments.security_comparison.chain import (
    ActorKeys,
    ChainConfig,
    DID_REGISTRY_ABI,
    load_actor_keys,
    resolve_did_document,
)
from _experiments.security_comparison.cli_common import redact_rpc_text
from infrastructure.agentdid_protocol import did_network, relationship_addresses
from infrastructure.lineage.crypto import did_from_address
from infrastructure.lineage.registry_client import bytes32_id, load_registry_abi
from infrastructure.security import sha256_json


SEPOLIA_CHAIN_ID = 11155111
FULL_EXPERIMENT_COUNT = 63
FULL_LINEAGE_EXPERIMENT_COUNT = 21
FULL_ONCHAIN_LINEAGE_EXPERIMENT_COUNT = 15
FULL_LINEAGE_TRANSACTION_COUNT = 97
FULL_ANCHOR_TRANSACTION_COUNT = 63
MAX_SHARED_DID_SETUP_TRANSACTIONS = 4
FULL_REMOTE_TRANSACTION_UPPER_BOUND = 164

# Every full-run sender enforces these limits before signing.  The relayer
# allowance covers 97 x 450k Lineage gas plus 63 x 70k anchor gas, rounded up
# to 50M.  Each possible DID controller receives a separate 100k allowance.
FULL_LINEAGE_GAS_LIMIT_PER_TRANSACTION = 450_000
FULL_ANCHOR_GAS_LIMIT_PER_TRANSACTION = 70_000
FULL_RELAYER_GAS_UPPER_BOUND = 50_000_000
DID_SETUP_GAS_UPPER_BOUND_PER_CONTROLLER = 100_000
MINIMUM_SEPOLIA_CHILD_TIMEOUT_SECONDS = 900.0
UINT64_MAX = (1 << 64) - 1


class _PreflightFailure(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _default_web3(config: ChainConfig) -> Web3:
    provider = Web3.HTTPProvider(
        config.rpc_url,
        request_kwargs={"timeout": config.rpc_timeout_seconds},
    )
    return Web3(provider)


def _timeout_error(exc: BaseException) -> bool:
    return isinstance(exc, TimeoutError) or "timeout" in type(exc).__name__.lower()


def _safe_reason(
    exc: BaseException,
    config: ChainConfig,
    private_values: list[str] | None = None,
) -> str:
    reason = redact_rpc_text(str(exc), config.rpc_url)
    for value in private_values or []:
        if value:
            reason = reason.replace(value, "<redacted-key>")
            reason = reason.replace(value.removeprefix("0x"), "<redacted-key>")
    return reason


def _checksum_nonzero(address: str, *, code: str, label: str) -> None:
    if not Web3.is_checksum_address(address) or int(address, 16) == 0:
        raise _PreflightFailure(code, f"{label} must be a non-zero checksum address")


def _expected_domain_separator(chain_id: int, contract: str) -> bytes:
    domain_typehash = Web3.keccak(
        text="EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    )
    return Web3.keccak(encode(
        ["bytes32", "bytes32", "bytes32", "uint256", "address"],
        [
            domain_typehash,
            Web3.keccak(text="AgentLineage-DID"),
            Web3.keccak(text="1"),
            chain_id,
            Web3.to_checksum_address(contract),
        ],
    ))


def _max_cost_wei(environment: Mapping[str, str]) -> int | None:
    raw = str(environment.get("AGENTDID_FULL_MAX_COST_ETH", "")).strip()
    if not raw:
        return None
    try:
        value = Decimal(raw)
    except InvalidOperation as exc:
        raise _PreflightFailure(
            "SEPOLIA_COST_CAP_INVALID",
            "AGENTDID_FULL_MAX_COST_ETH must be a positive decimal",
        ) from exc
    if value <= 0:
        raise _PreflightFailure(
            "SEPOLIA_COST_CAP_INVALID",
            "AGENTDID_FULL_MAX_COST_ETH must be greater than zero",
        )
    return int(value * Decimal(10**18))


def _fee_safety_bps(environment: Mapping[str, str]) -> int:
    raw = str(environment.get("AGENTDID_FULL_FEE_SAFETY_BPS", "20000")).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise _PreflightFailure(
            "SEPOLIA_FEE_SAFETY_INVALID",
            "AGENTDID_FULL_FEE_SAFETY_BPS must be an integer",
        ) from exc
    if not 10_000 <= value <= 50_000:
        raise _PreflightFailure(
            "SEPOLIA_FEE_SAFETY_INVALID",
            "AGENTDID_FULL_FEE_SAFETY_BPS must be between 10000 and 50000",
        )
    return value


def _lineage_root_budget_ids(plan: list[dict[str, Any]]) -> list[str]:
    lineage_items = [item for item in plan if item.get("scheme") == "lineage"]
    if len(plan) != FULL_EXPERIMENT_COUNT or len(lineage_items) != FULL_LINEAGE_EXPERIMENT_COUNT:
        raise _PreflightFailure(
            "SEPOLIA_FULL_PLAN_INVALID",
            "full Sepolia execution requires exactly 63 items and 21 Lineage items",
        )
    onchain_items = [
        item for item in lineage_items
        if item.get("case_id") == "H00" or str(item.get("case_id", "")).startswith("L")
    ]
    if len(onchain_items) != FULL_ONCHAIN_LINEAGE_EXPERIMENT_COUNT:
        raise _PreflightFailure(
            "SEPOLIA_FULL_PLAN_INVALID",
            "full Sepolia execution requires exactly 15 post-Baseline Lineage items",
        )
    return [
        "0x" + hashlib.sha256(
            f"{item['experiment_id']}:root-budget".encode("utf-8")
        ).hexdigest()
        for item in onchain_items
    ]


def validate_full_preflight_attestation(
    report: dict[str, Any],
    *,
    expected_hash: str,
    config: ChainConfig,
    run_id: str,
    experiment_id: str,
) -> None:
    """Validate the parent preflight before a Sepolia child sends transactions."""

    if sha256_json(report) != expected_hash:
        raise RuntimeError("FULL_PREFLIGHT_HASH_MISMATCH")
    if report.get("schema_version") != "agentdid-sepolia-full-preflight-v1":
        raise RuntimeError("FULL_PREFLIGHT_SCHEMA_MISMATCH")
    if not report.get("passed") or report.get("code") != "SEPOLIA_FULL_PREFLIGHT_OK":
        raise RuntimeError("FULL_PREFLIGHT_NOT_PASSED")
    if report.get("run_id") != run_id:
        raise RuntimeError("FULL_PREFLIGHT_RUN_ID_MISMATCH")
    expected_case_ids = (
        "H00",
        *(f"A{number:02d}" for number in range(1, 7)),
        *(f"L{number:02d}" for number in range(1, 15)),
    )
    expected_experiment_ids = []
    ordinal = 0
    for case_id in expected_case_ids:
        for scheme in ("original", "baseline", "lineage"):
            ordinal += 1
            expected_experiment_ids.append(
                f"{run_id}-{ordinal:02d}-{scheme}-{case_id.lower()}"
            )
    experiment_ids = report.get("experiment_ids")
    if experiment_ids != expected_experiment_ids:
        raise RuntimeError("FULL_PREFLIGHT_PLAN_IDS_MISMATCH")
    if experiment_id not in experiment_ids:
        raise RuntimeError("FULL_PREFLIGHT_EXPERIMENT_NOT_AUTHORIZED")
    if (
        int(report.get("planned", -1)) != FULL_EXPERIMENT_COUNT
        or int(report.get("started", -1)) != 0
        or report.get("fallback") is not False
    ):
        raise RuntimeError("FULL_PREFLIGHT_EXECUTION_STATE_INVALID")
    plan_hash = str(report.get("plan_hash") or "")
    if len(plan_hash) != 64:
        raise RuntimeError("FULL_PREFLIGHT_PLAN_HASH_INVALID")
    try:
        int(plan_hash, 16)
    except ValueError as exc:
        raise RuntimeError("FULL_PREFLIGHT_PLAN_HASH_INVALID") from exc
    chain = report.get("chain") or {}
    expected_chain = config.public_dict()
    for field in (
        "backend",
        "chain_id",
        "did_registry_address",
        "lineage_registry_address",
        "confirmations",
        "rpc_timeout_seconds",
    ):
        if chain.get(field) != expected_chain.get(field):
            raise RuntimeError(f"FULL_PREFLIGHT_CHAIN_MISMATCH:{field}")
    required_checks = {
        "static_configuration",
        "actor_configuration",
        "did_resolver_available",
        "rpc_connected",
        "chain_id",
        "node_synced",
        "fee_data",
        "registry_bytecode",
        "did_registry_interface",
        "did_setup_plan",
        "lineage_registry_interface",
        "run_namespace_unused",
        "payer_nonce_and_balance",
        "gas_cost_cap",
    }
    passed_checks = {
        str(item.get("name"))
        for item in report.get("checks", [])
        if item.get("passed") is True
    }
    if not required_checks.issubset(passed_checks):
        raise RuntimeError("FULL_PREFLIGHT_REQUIRED_CHECK_MISSING")
    for registry_name in ("did_registry", "lineage_registry"):
        registry = report.get(registry_name) or {}
        code_hash = str(registry.get("code_sha256") or "")
        if len(code_hash) != 64 or int(code_hash, 16) < 0:
            raise RuntimeError(f"FULL_PREFLIGHT_CODE_HASH_INVALID:{registry_name}")
    actors = report.get("actors") or {}
    _checksum_nonzero(
        str(actors.get("relayer") or ""),
        code="FULL_PREFLIGHT_ACTOR_INVALID",
        label="relayer",
    )
    actor_roles = actors.get("roles") or {}
    for role in ("issuer", "holder", "verifier", "alternate", "evaluator"):
        addresses = actor_roles.get(role) or {}
        for key in ("controller", "operation"):
            _checksum_nonzero(
                str(addresses.get(key) or ""),
                code="FULL_PREFLIGHT_ACTOR_INVALID",
                label=f"{role} {key}",
            )
    current_actor_keys = load_actor_keys(config.backend)
    current_relayer = Account.from_key(current_actor_keys.chain_private_key).address
    if current_relayer.lower() != str(actors["relayer"]).lower():
        raise RuntimeError("FULL_PREFLIGHT_RELAYER_CHANGED")
    for role in ("issuer", "holder", "verifier", "alternate", "evaluator"):
        current_controller = Account.from_key(current_actor_keys.controllers[role]).address
        current_operation = Account.from_key(current_actor_keys.operations[role]).address
        if (
            current_controller.lower()
            != str(actor_roles[role]["controller"]).lower()
            or current_operation.lower()
            != str(actor_roles[role]["operation"]).lower()
        ):
            raise RuntimeError(f"FULL_PREFLIGHT_ACTOR_CHANGED:{role}")
    namespace = report.get("namespace") or {}
    if (
        int(namespace.get("root_budget_ids_checked", -1))
        != FULL_ONCHAIN_LINEAGE_EXPERIMENT_COUNT
        or int(namespace.get("collisions", -1)) != 0
    ):
        raise RuntimeError("FULL_PREFLIGHT_NAMESPACE_INVALID")
    gas_budget = report.get("gas_budget") or {}
    did_setup_count = int(gas_budget.get("did_setup_transactions_max", -1))
    if (
        int(gas_budget.get("lineage_transactions", -1))
        != FULL_LINEAGE_TRANSACTION_COUNT
        or int(gas_budget.get("anchor_transactions", -1))
        != FULL_ANCHOR_TRANSACTION_COUNT
        or int(gas_budget.get("protocol_transaction_upper_bound", -1))
        != FULL_REMOTE_TRANSACTION_UPPER_BOUND
        or not 0 <= did_setup_count <= 4
        or int(gas_budget.get("transaction_upper_bound", -1))
        != FULL_LINEAGE_TRANSACTION_COUNT + FULL_ANCHOR_TRANSACTION_COUNT + did_setup_count
        or int(gas_budget.get("fee_upper_bound_wei", 0)) <= 0
    ):
        raise RuntimeError("FULL_PREFLIGHT_GAS_BUDGET_INVALID")
    w3 = _default_web3(config)
    if not w3.is_connected() or int(w3.eth.chain_id) != config.chain_id:
        raise RuntimeError("FULL_PREFLIGHT_LIVE_CHAIN_MISMATCH")
    for registry_name, address in (
        ("did_registry", config.did_registry_address),
        ("lineage_registry", config.lineage_registry_address),
    ):
        current_code = bytes(w3.eth.get_code(address))
        current_hash = hashlib.sha256(current_code).hexdigest()
        approved_hash = str((report.get(registry_name) or {}).get("code_sha256"))
        if not current_code or current_hash != approved_hash:
            raise RuntimeError(f"FULL_PREFLIGHT_LIVE_CODE_MISMATCH:{registry_name}")


def run_sepolia_full_preflight(
    config: ChainConfig,
    *,
    run_id: str,
    plan: list[dict[str, Any]],
    child_timeout_seconds: float,
    web3_factory: Callable[[ChainConfig], Any] | None = None,
    actor_keys_loader: Callable[[str], ActorKeys] | None = None,
    did_resolver: Callable[[ChainConfig, str], dict[str, Any]] | None = None,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Perform the complete read-only gate for a paid 63-item Sepolia run."""

    env = environment if environment is not None else os.environ
    report: dict[str, Any] = {
        "schema_version": "agentdid-sepolia-full-preflight-v1",
        "status": "FAILED",
        "passed": False,
        "code": "SEPOLIA_FULL_PREFLIGHT_FAILED",
        "run_id": run_id,
        "planned": len(plan),
        "started": 0,
        "fallback": False,
        "chain": config.public_dict(),
        "experiment_ids": [str(item.get("experiment_id", "")) for item in plan],
        "plan_hash": sha256_json(plan),
        "checks": [],
    }
    private_values: list[str] = []
    try:
        if config.backend != "sepolia":
            raise _PreflightFailure(
                "SEPOLIA_BACKEND_REQUIRED",
                f"full Sepolia preflight cannot run for backend {config.backend!r}",
            )
        if config.chain_id != SEPOLIA_CHAIN_ID:
            raise _PreflightFailure(
                "SEPOLIA_CHAIN_ID_MISMATCH",
                f"configured chain ID must be {SEPOLIA_CHAIN_ID}",
            )
        if config.confirmations < 1:
            raise _PreflightFailure(
                "SEPOLIA_CONFIRMATIONS_INVALID",
                "at least one confirmation is required",
            )
        if child_timeout_seconds < MINIMUM_SEPOLIA_CHILD_TIMEOUT_SECONDS:
            raise _PreflightFailure(
                "SEPOLIA_CHILD_TIMEOUT_TOO_LOW",
                f"Sepolia full runs require at least {MINIMUM_SEPOLIA_CHILD_TIMEOUT_SECONDS:g} seconds per child",
            )
        _checksum_nonzero(
            config.did_registry_address,
            code="DID_REGISTRY_ADDRESS_INVALID",
            label="DID Registry",
        )
        _checksum_nonzero(
            config.lineage_registry_address,
            code="LINEAGE_REGISTRY_ADDRESS_INVALID",
            label="Lineage Registry",
        )
        budget_ids = _lineage_root_budget_ids(plan)
        report["checks"].append({"name": "static_configuration", "passed": True})

        explicit_chain_key = str(env.get("AGENTDID_EXPERIMENT_CHAIN_KEY", "")).strip()
        try:
            actor_keys = (actor_keys_loader or load_actor_keys)("sepolia")
            private_values.extend([
                actor_keys.chain_private_key,
                *actor_keys.controllers.values(),
                *actor_keys.operations.values(),
            ])
            configured_relayer = Account.from_key(actor_keys.chain_private_key)
            explicit_relayer = (
                Account.from_key(explicit_chain_key)
                if explicit_chain_key
                else configured_relayer
            )
        except Exception as exc:
            raise _PreflightFailure(
                "SEPOLIA_ACTOR_CONFIG_INVALID",
                f"Sepolia actor configuration is invalid: {type(exc).__name__}",
            ) from exc
        if explicit_chain_key:
            private_values.append(explicit_chain_key)
        if explicit_relayer.address.lower() != configured_relayer.address.lower():
            raise _PreflightFailure(
                "SEPOLIA_RELAYER_KEY_MISMATCH",
                "explicit transaction key does not match the configured chain payer",
            )
        required_roles = {"issuer", "holder", "verifier", "alternate", "evaluator"}
        if not required_roles.issubset(actor_keys.controllers) or not required_roles.issubset(
            actor_keys.operations
        ):
            raise _PreflightFailure(
                "SEPOLIA_ACTOR_CONFIG_INVALID",
                "actor configuration is missing a required comparison role",
            )
        actor_addresses = {
            role: {
                "controller": Account.from_key(actor_keys.controllers[role]).address,
                "operation": Account.from_key(actor_keys.operations[role]).address,
            }
            for role in sorted(required_roles)
        }
        report["actors"] = {
            "relayer": configured_relayer.address,
            "transaction_key_source": (
                "AGENTDID_EXPERIMENT_CHAIN_KEY"
                if explicit_chain_key
                else "merged-key-config"
            ),
            "roles": actor_addresses,
        }
        report["checks"].append({"name": "actor_configuration", "passed": True})

        if not shutil.which("node.exe") and not shutil.which("node"):
            raise _PreflightFailure(
                "DID_RESOLVER_UNAVAILABLE",
                "node is required for did:ethr resolution",
            )
        if not (Path(__file__).resolve().parents[2] / "infrastructure" / "real_resolve.js").is_file():
            raise _PreflightFailure(
                "DID_RESOLVER_UNAVAILABLE",
                "infrastructure/real_resolve.js is missing",
            )
        report["checks"].append({"name": "did_resolver_available", "passed": True})

        w3 = (web3_factory or _default_web3)(config)
        if not w3.is_connected():
            raise _PreflightFailure("SEPOLIA_RPC_UNAVAILABLE", "Sepolia RPC is unavailable")
        report["checks"].append({"name": "rpc_connected", "passed": True})
        actual_chain_id = int(w3.eth.chain_id)
        report["actual_chain_id"] = actual_chain_id
        if actual_chain_id != SEPOLIA_CHAIN_ID:
            raise _PreflightFailure(
                "SEPOLIA_CHAIN_ID_MISMATCH",
                f"RPC chain ID must be {SEPOLIA_CHAIN_ID}, got {actual_chain_id}",
            )
        report["checks"].append({"name": "chain_id", "passed": True})
        if w3.eth.syncing:
            raise _PreflightFailure("SEPOLIA_NODE_SYNCING", "Sepolia RPC node is still syncing")
        report["checks"].append({"name": "node_synced", "passed": True})

        latest = w3.eth.get_block("latest")
        base_fee = latest.get("baseFeePerGas")
        gas_price = int(w3.eth.gas_price)
        priority_fee = int(w3.eth.max_priority_fee) if base_fee is not None else 0
        if gas_price <= 0 or (base_fee is not None and (int(base_fee) < 0 or priority_fee < 0)):
            raise _PreflightFailure("SEPOLIA_FEE_DATA_INVALID", "RPC returned invalid fee data")
        eip1559_upper = (
            int(base_fee) * 2 + max(priority_fee, int(Web3.to_wei("0.1", "gwei")))
            if base_fee is not None
            else 0
        )
        fee_quote = max(gas_price, eip1559_upper)
        fee_safety_bps = _fee_safety_bps(env)
        fee_upper = (fee_quote * fee_safety_bps + 9_999) // 10_000
        report["latest_block"] = {
            "number": int(latest["number"]),
            "hash": Web3.to_hex(latest["hash"]) if latest.get("hash") is not None else None,
            "gas_limit": int(latest.get("gasLimit") or 0),
            "base_fee_per_gas": int(base_fee) if base_fee is not None else None,
            "priority_fee_per_gas": priority_fee,
            "legacy_gas_price": gas_price,
            "suggested_fee_per_gas": fee_quote,
            "fee_safety_bps": fee_safety_bps,
            "fee_upper_bound_wei": fee_upper,
        }
        report["checks"].append({"name": "fee_data", "passed": True})

        did_code = bytes(w3.eth.get_code(config.did_registry_address))
        if not did_code:
            raise _PreflightFailure("DID_REGISTRY_NO_CODE", "DID Registry has no bytecode")
        lineage_code = bytes(w3.eth.get_code(config.lineage_registry_address))
        if not lineage_code:
            raise _PreflightFailure(
                "LINEAGE_REGISTRY_NO_CODE",
                "Lineage Registry has no bytecode",
            )
        report["did_registry"] = {
            "address": config.did_registry_address,
            "code_size": len(did_code),
            "code_sha256": hashlib.sha256(did_code).hexdigest(),
        }
        report["lineage_registry"] = {
            "address": config.lineage_registry_address,
            "code_size": len(lineage_code),
            "code_sha256": hashlib.sha256(lineage_code).hexdigest(),
        }
        report["checks"].append({"name": "registry_bytecode", "passed": True})

        try:
            did_contract = w3.eth.contract(
                address=config.did_registry_address,
                abi=DID_REGISTRY_ABI,
            )
            did_controllers = []
            for role, addresses in actor_addresses.items():
                controller = addresses["controller"]
                owner = did_contract.functions.identityOwner(controller).call()
                changed_at = int(did_contract.functions.changed(controller).call())
                if str(owner).lower() != controller.lower():
                    raise _PreflightFailure(
                        "DID_CONTROLLER_OWNERSHIP_MISMATCH",
                        f"the {role} DID controller is owned by another address",
                    )
                did_controllers.append({
                    "role": role,
                    "controller": controller,
                    "identity_owner": str(owner),
                    "last_changed_block": changed_at,
                })
        except _PreflightFailure:
            raise
        except Exception as exc:
            raise _PreflightFailure(
                "DID_REGISTRY_ABI_MISMATCH",
                f"DID Registry interface check failed: {type(exc).__name__}",
            ) from exc
        report["did_registry"]["controllers"] = did_controllers
        report["checks"].append({"name": "did_registry_interface", "passed": True})

        identities = actor_keys.identities(config.chain_id)
        setup_roles: list[str] = []
        setup_plan: list[dict[str, Any]] = []
        resolver = did_resolver or resolve_did_document
        try:
            for role in sorted(required_roles):
                identity = identities[role]
                if identity.operation_address.lower() == identity.controller_address.lower():
                    setup_plan.append({
                        "role": role,
                        "did": identity.did,
                        "controller": identity.controller_address,
                        "operation": identity.operation_address,
                        "setup_required": False,
                        "reason": "operation key is the DID controller",
                    })
                    continue
                resolved = resolver(config, identity.did)
                authentication = relationship_addresses(
                    resolved["document"],
                    "authentication",
                )
                setup_required = identity.operation_address.lower() not in authentication
                if setup_required:
                    setup_roles.append(role)
                setup_plan.append({
                    "role": role,
                    "did": identity.did,
                    "controller": identity.controller_address,
                    "operation": identity.operation_address,
                    "setup_required": setup_required,
                    "reason": (
                        "operation delegate is missing"
                        if setup_required
                        else "operation delegate is already active"
                    ),
                    "resolved_at_block": (resolved.get("source") or {}).get(
                        "resolved_at_block"
                    ),
                })
        except Exception as exc:
            raise _PreflightFailure(
                "DID_RESOLUTION_PREFLIGHT_FAILED",
                f"DID setup planning failed: {type(exc).__name__}",
            ) from exc
        report["did_setup_plan"] = {
            "transaction_count": len(setup_roles),
            "roles_requiring_setup": setup_roles,
            "items": setup_plan,
        }
        report["checks"].append({"name": "did_setup_plan", "passed": True})

        try:
            contract = w3.eth.contract(
                address=config.lineage_registry_address,
                abi=load_registry_abi(),
            )
            domain_separator = bytes(contract.functions.domainSeparator().call())
            expected_domain = _expected_domain_separator(
                config.chain_id,
                config.lineage_registry_address,
            )
            if domain_separator != expected_domain:
                raise ValueError("domain separator mismatch")
            root_did = did_from_address(
                configured_relayer.address,
                did_network(config.chain_id),
            )
            root_state = contract.functions.roots(bytes32_id(root_did)).call()
            if len(root_state) != 5:
                raise ValueError("roots getter shape mismatch")
        except Exception as exc:
            raise _PreflightFailure(
                "LINEAGE_REGISTRY_ABI_MISMATCH",
                f"Lineage Registry interface check failed: {type(exc).__name__}",
            ) from exc
        governance, current_epoch, _delegation_key, _certificate_hash, active = root_state
        if bool(active) and str(governance).lower() != configured_relayer.address.lower():
            raise _PreflightFailure(
                "SEPOLIA_RELAYER_GOVERNANCE_MISMATCH",
                "the active Lineage root is governed by another account",
            )
        if int(current_epoch) + FULL_ONCHAIN_LINEAGE_EXPERIMENT_COUNT > UINT64_MAX:
            raise _PreflightFailure(
                "SEPOLIA_EPOCH_CAPACITY_INSUFFICIENT",
                "Lineage root cannot allocate 15 additional epochs",
            )
        report["lineage_registry"].update({
            "domain_separator": Web3.to_hex(domain_separator),
            "root_did": root_did,
            "root_active": bool(active),
            "root_governance": str(governance),
            "current_epoch": int(current_epoch),
        })
        report["checks"].append({"name": "lineage_registry_interface", "passed": True})

        collisions = []
        try:
            for budget_id in budget_ids:
                budget = contract.functions.budgets(bytes32_id(budget_id)).call()
                if len(budget) != 14:
                    raise ValueError("budgets getter shape mismatch")
                if bool(budget[12]):
                    collisions.append(budget_id)
        except Exception as exc:
            raise _PreflightFailure(
                "LINEAGE_REGISTRY_ABI_MISMATCH",
                f"Lineage budget interface check failed: {type(exc).__name__}",
            ) from exc
        if collisions:
            raise _PreflightFailure(
                "SEPOLIA_RUN_NAMESPACE_ALREADY_USED",
                "one or more deterministic root budget IDs already exist",
            )
        report["namespace"] = {
            "root_budget_ids_checked": len(budget_ids),
            "collisions": 0,
        }
        report["checks"].append({"name": "run_namespace_unused", "passed": True})

        payer_gas: dict[str, int] = defaultdict(int)
        payer_transactions: dict[str, int] = defaultdict(int)
        payer_roles: dict[str, set[str]] = defaultdict(set)
        relayer_address = configured_relayer.address
        payer_gas[relayer_address] += FULL_RELAYER_GAS_UPPER_BOUND
        payer_transactions[relayer_address] += (
            FULL_LINEAGE_TRANSACTION_COUNT + FULL_ANCHOR_TRANSACTION_COUNT
        )
        payer_roles[relayer_address].add("relayer")
        did_setup_roles = list(setup_roles)
        for role in did_setup_roles:
            addresses = actor_addresses[role]
            controller = addresses["controller"]
            payer_gas[controller] += DID_SETUP_GAS_UPPER_BOUND_PER_CONTROLLER
            payer_transactions[controller] += 1
            payer_roles[controller].add(f"{role}-did-controller")

        gas_budget_base = {
            "lineage_transactions": FULL_LINEAGE_TRANSACTION_COUNT,
            "anchor_transactions": FULL_ANCHOR_TRANSACTION_COUNT,
            "did_setup_transactions_max": len(did_setup_roles),
            "transaction_upper_bound": (
                FULL_LINEAGE_TRANSACTION_COUNT
                + FULL_ANCHOR_TRANSACTION_COUNT
                + len(did_setup_roles)
            ),
            "protocol_transaction_upper_bound": FULL_REMOTE_TRANSACTION_UPPER_BOUND,
            "relayer_gas_units_upper_bound": FULL_RELAYER_GAS_UPPER_BOUND,
            "lineage_gas_limit_per_transaction": FULL_LINEAGE_GAS_LIMIT_PER_TRANSACTION,
            "anchor_gas_limit_per_transaction": FULL_ANCHOR_GAS_LIMIT_PER_TRANSACTION,
            "did_gas_units_per_controller": DID_SETUP_GAS_UPPER_BOUND_PER_CONTROLLER,
            "fee_upper_bound_wei": fee_upper,
        }
        payer_reports = []
        for address in sorted(payer_gas, key=str.lower):
            latest_nonce = int(w3.eth.get_transaction_count(address, "latest"))
            pending_nonce = int(w3.eth.get_transaction_count(address, "pending"))
            if pending_nonce != latest_nonce:
                code = (
                    "SEPOLIA_RELAYER_PENDING_NONCE"
                    if address.lower() == relayer_address.lower()
                    else "SEPOLIA_ACTOR_PENDING_NONCE"
                )
                raise _PreflightFailure(
                    code,
                    f"payer {address} has outstanding pending transactions",
                )
            balance = int(w3.eth.get_balance(address))
            required = int(payer_gas[address]) * fee_upper
            payer_report = {
                "address": address,
                "roles": sorted(payer_roles[address]),
                "transactions_upper_bound": payer_transactions[address],
                "gas_units_upper_bound": payer_gas[address],
                "fee_upper_bound_wei": fee_upper,
                "required_wei": required,
                "balance_wei": balance,
                "shortfall_wei": max(0, required - balance),
                "latest_nonce": latest_nonce,
                "pending_nonce": pending_nonce,
            }
            payer_reports.append(payer_report)
            if balance < required:
                code = (
                    "SEPOLIA_RELAYER_BALANCE_INSUFFICIENT"
                    if address.lower() == relayer_address.lower()
                    else "SEPOLIA_ACTOR_BALANCE_INSUFFICIENT"
                )
                report["gas_budget"] = {
                    **gas_budget_base,
                    "payer_requirements": payer_reports,
                    "failed_payer": payer_report,
                }
                raise _PreflightFailure(code, f"payer {address} has insufficient balance")

        total_required = sum(int(item["required_wei"]) for item in payer_reports)
        cost_cap = _max_cost_wei(env)
        gas_budget = {
            **gas_budget_base,
            "required_wei": total_required,
            "max_cost_wei": cost_cap,
            "payer_requirements": payer_reports,
        }
        report["gas_budget"] = gas_budget
        if cost_cap is not None and total_required > cost_cap:
            raise _PreflightFailure(
                "SEPOLIA_GAS_COST_CAP_EXCEEDED",
                "the full-run cost upper bound exceeds AGENTDID_FULL_MAX_COST_ETH",
            )
        report["checks"].append({"name": "payer_nonce_and_balance", "passed": True})
        report["checks"].append({"name": "gas_cost_cap", "passed": True})

        report.update({
            "status": "PASSED",
            "passed": True,
            "code": "SEPOLIA_FULL_PREFLIGHT_OK",
        })
        return report
    except _PreflightFailure as exc:
        report["code"] = exc.code
        report["reason"] = _safe_reason(exc, config, private_values)
        return report
    except Exception as exc:
        report["code"] = (
            "SEPOLIA_RPC_TIMEOUT" if _timeout_error(exc) else "SEPOLIA_RPC_UNAVAILABLE"
        )
        report["reason"] = _safe_reason(exc, config, private_values)
        return report


def run_sepolia_did_preflight(
    config: ChainConfig,
    *,
    web3_factory: Callable[[ChainConfig], Any] | None = None,
) -> dict[str, Any]:
    """Validate the remote chain and ERC-1056 registry without sending a transaction.

    The returned report is safe to persist: it exposes only the RPC origin, never
    its path, query string, token, or any signing material.
    """

    report: dict[str, Any] = {
        "schema_version": "agentdid-sepolia-did-preflight-v1",
        "status": "FAILED",
        "passed": False,
        "code": "SEPOLIA_PREFLIGHT_FAILED",
        "chain": config.public_dict(),
        "checks": [],
    }
    try:
        if config.backend != "sepolia":
            raise _PreflightFailure(
                "SEPOLIA_BACKEND_REQUIRED",
                f"Sepolia preflight cannot run for backend {config.backend!r}",
            )
        if config.chain_id != SEPOLIA_CHAIN_ID:
            raise _PreflightFailure(
                "SEPOLIA_CHAIN_ID_MISMATCH",
                f"configured chain ID must be {SEPOLIA_CHAIN_ID}, got {config.chain_id}",
            )
        if config.confirmations < 1:
            raise _PreflightFailure(
                "SEPOLIA_CONFIRMATIONS_INVALID",
                "at least one confirmation is required",
            )
        if not Web3.is_checksum_address(config.did_registry_address):
            raise _PreflightFailure(
                "DID_REGISTRY_ADDRESS_INVALID",
                "DID Registry must be a checksum Ethereum address",
            )
        if int(config.did_registry_address, 16) == 0:
            raise _PreflightFailure(
                "DID_REGISTRY_ADDRESS_INVALID",
                "DID Registry cannot be the zero address",
            )

        factory = web3_factory or _default_web3
        w3 = factory(config)
        if not w3.is_connected():
            raise _PreflightFailure(
                "SEPOLIA_RPC_UNAVAILABLE",
                "Sepolia RPC is unavailable",
            )
        report["checks"].append({"name": "rpc_connected", "passed": True})

        actual_chain_id = int(w3.eth.chain_id)
        report["actual_chain_id"] = actual_chain_id
        if actual_chain_id != SEPOLIA_CHAIN_ID:
            raise _PreflightFailure(
                "SEPOLIA_CHAIN_ID_MISMATCH",
                f"RPC chain ID must be {SEPOLIA_CHAIN_ID}, got {actual_chain_id}",
            )
        report["checks"].append({"name": "chain_id", "passed": True})

        syncing = w3.eth.syncing
        if syncing:
            raise _PreflightFailure(
                "SEPOLIA_NODE_SYNCING",
                "Sepolia RPC node is still syncing",
            )
        report["checks"].append({"name": "node_synced", "passed": True})

        latest = w3.eth.get_block("latest")
        report["latest_block_number"] = int(latest["number"])
        block_hash = latest.get("hash")
        if block_hash is not None:
            report["latest_block_hash"] = Web3.to_hex(block_hash)
        report["checks"].append({"name": "latest_block", "passed": True})

        code = bytes(w3.eth.get_code(config.did_registry_address))
        if not code:
            raise _PreflightFailure(
                "DID_REGISTRY_NO_CODE",
                "DID Registry address has no deployed bytecode",
            )
        report["did_registry"] = {
            "address": config.did_registry_address,
            "code_size": len(code),
            "code_sha256": hashlib.sha256(code).hexdigest(),
        }
        report["checks"].append({"name": "did_registry_code", "passed": True})

        report.update({
            "status": "PASSED",
            "passed": True,
            "code": "SEPOLIA_DID_PREFLIGHT_OK",
        })
        return report
    except _PreflightFailure as exc:
        report["code"] = exc.code
        report["reason"] = str(exc)
        return report
    except Exception as exc:  # RPC clients expose several timeout subclasses.
        report["code"] = (
            "SEPOLIA_RPC_TIMEOUT" if _timeout_error(exc) else "SEPOLIA_RPC_UNAVAILABLE"
        )
        report["reason"] = str(exc).replace(config.rpc_url, "<redacted-rpc>")
        return report
