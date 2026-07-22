from __future__ import annotations

import json
import unittest
from dataclasses import dataclass
from typing import Any
from unittest.mock import patch

from eth_account import Account
from web3 import Web3

from _experiments.security_comparison.chain import (
    ActorKeys,
    ChainConfig,
    DEFAULT_SEPOLIA_DID_REGISTRY,
    DEFAULT_SEPOLIA_LINEAGE_REGISTRY,
)
from _experiments.security_comparison.preflight import (
    FULL_ANCHOR_TRANSACTION_COUNT,
    FULL_LINEAGE_TRANSACTION_COUNT,
    FULL_REMOTE_TRANSACTION_UPPER_BOUND,
    _expected_domain_separator,
    run_sepolia_full_preflight,
)
from _experiments.security_comparison.run_all import build_full_plan
from infrastructure.agentdid_protocol import ProtocolIdentity, make_did_document


RUN_ID = "unit-sepolia-full"
RPC_TOKEN = "unit-test-rpc-token-never-persist"
RPC_URL = f"https://rpc.example/v2/{RPC_TOKEN}?apiKey={RPC_TOKEN}"
ROLES = ("issuer", "holder", "verifier", "alternate", "evaluator")


def _key(byte: str) -> str:
    value = "0x" + byte * 64
    Account.from_key(value)
    return value


RELAYER_KEY = _key("1")
CONTROLLER_KEYS = {
    role: _key(byte)
    for role, byte in zip(ROLES, ("2", "3", "4", "5", "6"), strict=True)
}
OPERATION_KEYS = {
    "issuer": CONTROLLER_KEYS["issuer"],
    "holder": _key("7"),
    "verifier": _key("8"),
    "alternate": _key("9"),
    "evaluator": _key("a"),
}


def _actor_keys() -> ActorKeys:
    return ActorKeys(
        chain_private_key=RELAYER_KEY,
        controllers=dict(CONTROLLER_KEYS),
        operations=dict(OPERATION_KEYS),
    )


def _config() -> ChainConfig:
    return ChainConfig(
        backend="sepolia",
        rpc_url=RPC_URL,
        chain_id=11_155_111,
        did_registry_address=DEFAULT_SEPOLIA_DID_REGISTRY,
        lineage_registry_address=DEFAULT_SEPOLIA_LINEAGE_REGISTRY,
        confirmations=2,
        rpc_timeout_seconds=23.0,
    )


class _Call:
    def __init__(self, value: Any = None, error: BaseException | None = None):
        self.value = value
        self.error = error

    def call(self) -> Any:
        if self.error is not None:
            raise self.error
        return self.value


class _DidFunctions:
    def __init__(self, *, abi_error: bool = False):
        self.abi_error = abi_error

    def identityOwner(self, controller: str) -> _Call:  # noqa: N802 - ABI name
        if self.abi_error:
            return _Call(error=RuntimeError("identityOwner is unavailable"))
        return _Call(Web3.to_checksum_address(controller))

    def changed(self, _controller: str) -> _Call:
        return _Call(123_456)


class _DidContract:
    def __init__(self, *, abi_error: bool = False):
        self.functions = _DidFunctions(abi_error=abi_error)


class _LineageFunctions:
    def __init__(
        self,
        config: ChainConfig,
        relayer: str,
        *,
        abi_error: bool = False,
        namespace_collision: bool = False,
        root_active: bool = False,
        governance: str | None = None,
    ):
        self.config = config
        self.relayer = relayer
        self.abi_error = abi_error
        self.namespace_collision = namespace_collision
        self.root_active = root_active
        self.governance = governance or relayer

    def domainSeparator(self) -> _Call:  # noqa: N802 - ABI name
        if self.abi_error:
            return _Call(error=RuntimeError("domainSeparator is unavailable"))
        return _Call(
            _expected_domain_separator(
                self.config.chain_id,
                self.config.lineage_registry_address,
            )
        )

    def roots(self, _root_id: bytes) -> _Call:
        return _Call((
            Web3.to_checksum_address(self.governance),
            7,
            "0x0000000000000000000000000000000000000000",
            b"\x00" * 32,
            self.root_active,
        ))

    def budgets(self, _budget_id: bytes) -> _Call:
        return _Call((
            b"\x00" * 32,
            b"\x00" * 32,
            b"\x00" * 32,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            self.namespace_collision,
            False,
        ))


class _LineageContract:
    def __init__(self, config: ChainConfig, relayer: str, **kwargs: Any):
        self.functions = _LineageFunctions(config, relayer, **kwargs)


@dataclass
class _FakeOptions:
    chain_id: int = 11_155_111
    did_code: bytes = b"\x60\x01"
    lineage_code: bytes = b"\x60\x02"
    did_abi_error: bool = False
    lineage_abi_error: bool = False
    namespace_collision: bool = False
    root_active: bool = False
    governance: str | None = None


class _FakeEth:
    def __init__(
        self,
        config: ChainConfig,
        relayer: str,
        options: _FakeOptions,
        *,
        balances: dict[str, int] | None = None,
        latest_nonces: dict[str, int] | None = None,
        pending_nonces: dict[str, int] | None = None,
    ):
        self.config = config
        self.options = options
        self.chain_id = options.chain_id
        self.syncing = False
        self.gas_price = int(Web3.to_wei(3, "gwei"))
        self.max_priority_fee = int(Web3.to_wei(1, "gwei"))
        self._balances = {key.lower(): value for key, value in (balances or {}).items()}
        self._latest_nonces = {
            key.lower(): value for key, value in (latest_nonces or {}).items()
        }
        self._pending_nonces = {
            key.lower(): value for key, value in (pending_nonces or {}).items()
        }
        self.broadcast_attempts = 0
        self._did_contract = _DidContract(abi_error=options.did_abi_error)
        self._lineage_contract = _LineageContract(
            config,
            relayer,
            abi_error=options.lineage_abi_error,
            namespace_collision=options.namespace_collision,
            root_active=options.root_active,
            governance=options.governance,
        )

    def get_block(self, identifier: str) -> dict[str, Any]:
        if identifier != "latest":
            raise AssertionError("preflight may only inspect the latest block")
        return {
            "number": 7_654_321,
            "hash": b"\x12" * 32,
            "gasLimit": 30_000_000,
            "baseFeePerGas": int(Web3.to_wei(1, "gwei")),
        }

    def get_code(self, address: str) -> bytes:
        if address.lower() == self.config.did_registry_address.lower():
            return self.options.did_code
        if address.lower() == self.config.lineage_registry_address.lower():
            return self.options.lineage_code
        raise AssertionError(f"unexpected bytecode lookup: {address}")

    def contract(self, *, address: str, abi: Any) -> Any:
        del abi
        if address.lower() == self.config.did_registry_address.lower():
            return self._did_contract
        if address.lower() == self.config.lineage_registry_address.lower():
            return self._lineage_contract
        raise AssertionError(f"unexpected contract address: {address}")

    def get_transaction_count(self, address: str, block_identifier: str) -> int:
        normalized = address.lower()
        latest = self._latest_nonces.get(normalized, 4)
        if block_identifier == "latest":
            return latest
        if block_identifier == "pending":
            return self._pending_nonces.get(normalized, latest)
        raise AssertionError(f"unexpected nonce block identifier: {block_identifier}")

    def get_balance(self, address: str) -> int:
        return self._balances.get(address.lower(), 10**30)

    def send_raw_transaction(self, _transaction: bytes) -> bytes:
        self.broadcast_attempts += 1
        raise AssertionError("Sepolia preflight must never broadcast a transaction")

    def wait_for_transaction_receipt(self, *_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("Sepolia preflight must never wait for a receipt")


class _FakeWeb3:
    def __init__(self, eth: _FakeEth):
        self.eth = eth

    def is_connected(self) -> bool:
        return True


class SepoliaFullPreflightTests(unittest.TestCase):
    def _run(
        self,
        *,
        options: _FakeOptions | None = None,
        balances: dict[str, int] | None = None,
        latest_nonces: dict[str, int] | None = None,
        pending_nonces: dict[str, int] | None = None,
        environment: dict[str, str] | None = None,
        active_delegate_roles: set[str] | None = None,
        include_chain_key_environment: bool = True,
    ) -> tuple[dict[str, Any], _FakeWeb3, ActorKeys]:
        config = _config()
        actors = _actor_keys()
        relayer = Account.from_key(actors.chain_private_key).address
        eth = _FakeEth(
            config,
            relayer,
            options or _FakeOptions(),
            balances=balances,
            latest_nonces=latest_nonces,
            pending_nonces=pending_nonces,
        )
        web3 = _FakeWeb3(eth)
        env = (
            {"AGENTDID_EXPERIMENT_CHAIN_KEY": RELAYER_KEY}
            if include_chain_key_environment
            else {}
        )
        env.update(environment or {})
        active_roles = active_delegate_roles or set()
        identities = actors.identities(config.chain_id)

        def fake_resolver(_config: ChainConfig, did: str) -> dict[str, Any]:
            identity = next(item for item in identities.values() if item.did == did)
            document_identity = identity
            if identity.role not in active_roles:
                document_identity = ProtocolIdentity.from_keys(
                    identity.role,
                    actors.controllers[identity.role],
                    actors.controllers[identity.role],
                    config.chain_id,
                )
            return {
                "document": make_did_document(document_identity),
                "source": {"resolved_at_block": 7_654_321},
            }

        with patch(
            "_experiments.security_comparison.preflight.shutil.which",
            return_value="node",
        ):
            report = run_sepolia_full_preflight(
                config,
                run_id=RUN_ID,
                plan=build_full_plan(RUN_ID),
                child_timeout_seconds=900,
                web3_factory=lambda supplied: web3,
                actor_keys_loader=lambda backend: actors,
                did_resolver=fake_resolver,
                environment=env,
            )
        return report, web3, actors

    def test_success_reports_complete_fixed_matrix_budget_without_sending(self) -> None:
        report, web3, _actors = self._run()

        self.assertTrue(report["passed"])
        self.assertEqual("SEPOLIA_FULL_PREFLIGHT_OK", report["code"])
        self.assertEqual(63, report["planned"])
        self.assertEqual(0, report["started"])
        self.assertFalse(report["fallback"])
        budget = report["gas_budget"]
        self.assertEqual(FULL_LINEAGE_TRANSACTION_COUNT, budget["lineage_transactions"])
        self.assertEqual(FULL_ANCHOR_TRANSACTION_COUNT, budget["anchor_transactions"])
        self.assertEqual(4, budget["did_setup_transactions_max"])
        self.assertEqual(FULL_REMOTE_TRANSACTION_UPPER_BOUND, budget["transaction_upper_bound"])
        self.assertEqual(FULL_REMOTE_TRANSACTION_UPPER_BOUND, budget["protocol_transaction_upper_bound"])
        self.assertEqual(15, report["namespace"]["root_budget_ids_checked"])
        self.assertEqual(0, web3.eth.broadcast_attempts)

    def test_merged_key_config_can_supply_the_transaction_key(self) -> None:
        report, web3, _actors = self._run(
            include_chain_key_environment=False,
        )

        self.assertTrue(report["passed"])
        self.assertEqual("merged-key-config", report["actors"]["transaction_key_source"])
        self.assertEqual(0, web3.eth.broadcast_attempts)

    def test_lineage_registry_without_code_is_rejected(self) -> None:
        report, web3, _actors = self._run(
            options=_FakeOptions(lineage_code=b""),
        )

        self.assertFalse(report["passed"])
        self.assertEqual("LINEAGE_REGISTRY_NO_CODE", report["code"])
        self.assertEqual(0, web3.eth.broadcast_attempts)

    def test_did_registry_abi_mismatch_is_rejected(self) -> None:
        report, web3, _actors = self._run(
            options=_FakeOptions(did_abi_error=True),
        )

        self.assertFalse(report["passed"])
        self.assertEqual("DID_REGISTRY_ABI_MISMATCH", report["code"])
        self.assertEqual(0, web3.eth.broadcast_attempts)

    def test_lineage_registry_abi_mismatch_is_rejected(self) -> None:
        report, web3, _actors = self._run(
            options=_FakeOptions(lineage_abi_error=True),
        )

        self.assertFalse(report["passed"])
        self.assertEqual("LINEAGE_REGISTRY_ABI_MISMATCH", report["code"])
        self.assertEqual(0, web3.eth.broadcast_attempts)

    def test_wrong_remote_chain_is_rejected(self) -> None:
        report, web3, _actors = self._run(
            options=_FakeOptions(chain_id=31_337),
        )

        self.assertFalse(report["passed"])
        self.assertEqual("SEPOLIA_CHAIN_ID_MISMATCH", report["code"])
        self.assertEqual(0, web3.eth.broadcast_attempts)

    def test_relayer_pending_nonce_is_rejected(self) -> None:
        relayer = Account.from_key(RELAYER_KEY).address
        report, web3, _actors = self._run(
            latest_nonces={relayer: 8},
            pending_nonces={relayer: 9},
        )

        self.assertFalse(report["passed"])
        self.assertEqual("SEPOLIA_RELAYER_PENDING_NONCE", report["code"])
        self.assertEqual(0, web3.eth.broadcast_attempts)

    def test_relayer_balance_insufficient_is_rejected(self) -> None:
        relayer = Account.from_key(RELAYER_KEY).address
        report, web3, _actors = self._run(balances={relayer: 0})

        self.assertFalse(report["passed"])
        self.assertEqual("SEPOLIA_RELAYER_BALANCE_INSUFFICIENT", report["code"])
        self.assertGreater(report["gas_budget"]["failed_payer"]["shortfall_wei"], 0)
        self.assertEqual(0, web3.eth.broadcast_attempts)

    def test_controller_balance_insufficient_is_rejected(self) -> None:
        controller = Account.from_key(CONTROLLER_KEYS["holder"]).address
        report, web3, _actors = self._run(balances={controller: 0})

        self.assertFalse(report["passed"])
        self.assertEqual("SEPOLIA_ACTOR_BALANCE_INSUFFICIENT", report["code"])
        failed = report["gas_budget"]["failed_payer"]
        self.assertEqual(controller.lower(), failed["address"].lower())
        self.assertIn("holder-did-controller", failed["roles"])
        self.assertEqual(0, web3.eth.broadcast_attempts)

    def test_active_did_delegates_do_not_require_controller_balance(self) -> None:
        controller = Account.from_key(CONTROLLER_KEYS["holder"]).address
        report, web3, _actors = self._run(
            balances={controller: 0},
            active_delegate_roles={"holder"},
        )

        self.assertTrue(report["passed"])
        self.assertEqual(3, report["did_setup_plan"]["transaction_count"])
        self.assertNotIn("holder", report["did_setup_plan"]["roles_requiring_setup"])
        self.assertEqual(0, web3.eth.broadcast_attempts)

    def test_existing_run_namespace_collision_is_rejected(self) -> None:
        report, web3, _actors = self._run(
            options=_FakeOptions(namespace_collision=True),
        )

        self.assertFalse(report["passed"])
        self.assertEqual("SEPOLIA_RUN_NAMESPACE_ALREADY_USED", report["code"])
        self.assertEqual(0, web3.eth.broadcast_attempts)

    def test_active_root_governance_mismatch_is_rejected(self) -> None:
        foreign_governance = Account.from_key(_key("b")).address
        report, web3, _actors = self._run(
            options=_FakeOptions(
                root_active=True,
                governance=foreign_governance,
            ),
        )

        self.assertFalse(report["passed"])
        self.assertEqual("SEPOLIA_RELAYER_GOVERNANCE_MISMATCH", report["code"])
        self.assertEqual(0, web3.eth.broadcast_attempts)

    def test_cost_cap_below_upper_bound_is_rejected(self) -> None:
        report, web3, _actors = self._run(
            environment={"AGENTDID_FULL_MAX_COST_ETH": "0.000000000000000001"},
        )

        self.assertFalse(report["passed"])
        self.assertEqual("SEPOLIA_GAS_COST_CAP_EXCEEDED", report["code"])
        self.assertGreater(report["gas_budget"]["required_wei"], 1)
        self.assertEqual(1, report["gas_budget"]["max_cost_wei"])
        self.assertEqual(0, web3.eth.broadcast_attempts)

    def test_report_never_contains_rpc_token_or_private_keys(self) -> None:
        report, web3, actors = self._run()
        serialized = json.dumps(report, sort_keys=True)

        self.assertTrue(report["passed"])
        self.assertNotIn(RPC_TOKEN, serialized)
        self.assertNotIn(RPC_URL, serialized)
        private_keys = {
            RELAYER_KEY,
            actors.chain_private_key,
            *actors.controllers.values(),
            *actors.operations.values(),
        }
        for private_key in private_keys:
            with self.subTest(private_key_suffix=private_key[-6:]):
                self.assertNotIn(private_key, serialized)
                self.assertNotIn(private_key.removeprefix("0x"), serialized)
        self.assertEqual(0, web3.eth.broadcast_attempts)


if __name__ == "__main__":
    unittest.main()
