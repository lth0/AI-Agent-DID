"""Strict Sepolia preflight checks for the AgentDID comparison runner."""

from __future__ import annotations

import hashlib
from typing import Any, Callable

from web3 import Web3

from _experiments.security_comparison.chain import ChainConfig


SEPOLIA_CHAIN_ID = 11155111


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

