from __future__ import annotations

import unittest

from _experiments.security_comparison.cli_common import (
    redact_rpc_text,
    validate_run_id,
)


class CliCommonTests(unittest.TestCase):
    def test_run_id_is_one_portable_path_component(self) -> None:
        for value in ("full-abc123", "single.H00_01", "A1"):
            with self.subTest(value=value):
                self.assertEqual(value, validate_run_id(value))

        for value in ("", ".", "..", "../outside", r"..\outside", "/tmp/x", r"C:\x", "NUL"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_run_id(value)

    def test_rpc_url_and_tokens_are_removed_from_diagnostics(self) -> None:
        rpc_url = "https://rpc.example/v3/SECRET_PROJECT_TOKEN?key=SECRET_QUERY_TOKEN"
        diagnostic = f"request to {rpc_url} failed; token SECRET_PROJECT_TOKEN"

        redacted = redact_rpc_text(diagnostic, rpc_url)

        self.assertNotIn(rpc_url, redacted)
        self.assertNotIn("SECRET_PROJECT_TOKEN", redacted)
        self.assertNotIn("SECRET_QUERY_TOKEN", redacted)
        self.assertIn("<redacted-rpc>", redacted)


if __name__ == "__main__":
    unittest.main()
