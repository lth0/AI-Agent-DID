"""Shared validation and redaction helpers for comparison CLIs."""

from __future__ import annotations

import argparse
import re
from urllib.parse import parse_qsl, urlsplit


RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


def validate_run_id(value: str) -> str:
    """Require a portable, single path component for every run identifier."""

    if not isinstance(value, str) or not RUN_ID_PATTERN.fullmatch(value):
        raise ValueError(
            "run-id must be 1-128 characters, start with an ASCII letter or digit, "
            "and contain only letters, digits, '.', '_' or '-'"
        )
    if value.endswith("."):
        raise ValueError("run-id cannot end with a dot")
    if value.split(".", 1)[0].upper() in WINDOWS_RESERVED_NAMES:
        raise ValueError("run-id uses a reserved Windows path name")
    return value


def run_id_argument(value: str) -> str:
    try:
        return validate_run_id(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def redact_rpc_text(value: str | bytes | None, rpc_url: str) -> str:
    """Remove an RPC URL and token-like URL components from diagnostic text."""

    if value is None:
        return ""
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
    if not rpc_url:
        return text
    text = text.replace(rpc_url, "<redacted-rpc>")
    try:
        parsed = urlsplit(rpc_url)
    except ValueError:
        return text

    secrets = [parsed.username, parsed.password]
    secrets.extend(part for part in parsed.path.split("/") if len(part) >= 8)
    secrets.extend(
        item
        for pair in parse_qsl(parsed.query, keep_blank_values=True)
        for item in pair
        if len(item) >= 8
    )
    for secret in secrets:
        if secret:
            text = text.replace(secret, "<redacted-rpc-token>")
    return text
