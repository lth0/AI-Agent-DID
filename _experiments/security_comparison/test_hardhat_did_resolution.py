from __future__ import annotations

import unittest
from pathlib import Path

from _experiments.security_comparison.chain import (
    HardhatNode,
    configure_did_registry,
    deploy_local_contracts,
    load_actor_keys,
    local_config,
    resolve_and_verify_dids,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class HardhatDidResolutionTests(unittest.TestCase):
    node: HardhatNode

    @classmethod
    def setUpClass(cls) -> None:
        cls.node = HardhatNode(
            PROJECT_ROOT / ".codex" / "test_hardhat_did_resolution"
        )
        cls.node.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.node.stop()

    def test_registered_delegates_resolve_from_the_hardhat_registry(self) -> None:
        config = local_config(deploy_local_contracts())
        actor_keys = load_actor_keys("hardhat")
        identities = actor_keys.identities(config.chain_id)

        setup = configure_did_registry(config, identities, actor_keys)
        resolved = resolve_and_verify_dids(config, identities)

        self.assertEqual(len(identities), len(resolved["documents"]))
        self.assertTrue(
            all(
                item["transaction"] is None
                or item["transaction"]["status"] == 1
                for item in setup["transactions"]
            )
        )
        for role, identity in identities.items():
            with self.subTest(role=role):
                entry = resolved["resolutions"][role]
                self.assertEqual(identity.did, entry["document"]["id"])
                self.assertIn(
                    identity.operation_address.lower(),
                    entry["authentication_addresses"],
                )
                self.assertIn(
                    identity.controller_address.lower(),
                    entry["assertion_addresses"],
                )


if __name__ == "__main__":
    unittest.main()
