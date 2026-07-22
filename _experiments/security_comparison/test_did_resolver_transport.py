from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from _experiments.security_comparison.chain import (
    ChainConfig,
    DEFAULT_SEPOLIA_DID_REGISTRY,
    DEFAULT_SEPOLIA_LINEAGE_REGISTRY,
    resolve_did_document,
)


class DidResolverTransportTests(unittest.TestCase):
    def test_rpc_token_is_passed_by_environment_and_redacted_from_errors(self) -> None:
        secret = "resolver-token-must-not-appear-in-argv"
        rpc_url = f"https://rpc.example/v2/{secret}?apiKey={secret}"
        config = ChainConfig(
            backend="sepolia",
            rpc_url=rpc_url,
            chain_id=11155111,
            did_registry_address=DEFAULT_SEPOLIA_DID_REGISTRY,
            lineage_registry_address=DEFAULT_SEPOLIA_LINEAGE_REGISTRY,
        )
        did = "did:ethr:sepolia:0x0000000000000000000000000000000000000001"
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr=f"provider rejected {rpc_url}",
        )

        with patch(
            "_experiments.security_comparison.chain.shutil.which",
            return_value="node",
        ), patch(
            "_experiments.security_comparison.chain.subprocess.run",
            return_value=completed,
        ) as run_process:
            with self.assertRaises(RuntimeError) as raised:
                resolve_did_document(config, did)

        command = run_process.call_args.args[0]
        environment = run_process.call_args.kwargs["env"]
        self.assertNotIn(rpc_url, command)
        self.assertFalse(any(secret in str(item) for item in command))
        self.assertEqual(rpc_url, environment["AGENTDID_RESOLVER_RPC_URL"])
        self.assertNotIn(secret, str(raised.exception))


if __name__ == "__main__":
    unittest.main()
