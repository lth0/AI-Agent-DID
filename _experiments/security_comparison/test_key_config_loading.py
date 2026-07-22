from __future__ import annotations

import unittest
from unittest.mock import patch

from infrastructure import load_config


class KeyConfigLoadingTests(unittest.TestCase):
    def test_local_key_json_overrides_issuer_and_preserves_agent_roles(self) -> None:
        role_config = {
            "api_url": "https://role-rpc.invalid",
            "accounts": {
                "issuer": {"private_key": "role-issuer"},
                "agent_a_admin": {"private_key": "agent-admin"},
                "agent_a_op": {"private_key": "agent-op"},
            },
        }
        local_config = {
            "api_url": "https://local-rpc.invalid",
            "accounts": {
                "issuer": {"private_key": "local-issuer"},
                "master": {"private_key": "local-master"},
            },
        }

        def fake_read(path: str) -> dict:
            return (
                local_config
                if load_config.os.path.basename(path) == "key.json"
                else role_config
            )

        with patch.object(load_config.os.path, "exists", return_value=True), patch.object(
            load_config,
            "_read_json_config",
            side_effect=fake_read,
        ), patch.dict(load_config.os.environ, {}, clear=True):
            merged = load_config.load_key_config()

        self.assertEqual("https://local-rpc.invalid", merged["api_url"])
        self.assertEqual("local-issuer", merged["accounts"]["issuer"]["private_key"])
        self.assertIn("agent_a_admin", merged["accounts"])
        self.assertIn("agent_a_op", merged["accounts"])


if __name__ == "__main__":
    unittest.main()
