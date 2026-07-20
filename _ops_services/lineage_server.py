from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from flask import Flask, jsonify, request

from infrastructure.lineage.models import EpochKeyCertificate
from infrastructure.lineage.runtime import (
    DEFAULT_CONFIG,
    DEFAULT_STATE,
    LineageRuntimeConfig,
    load_parent_authority_material,
    load_public_state,
    permission_from_state,
)
from infrastructure.lineage.service import (
    LineageAuditRecorder,
    LineageAuthority,
    LineageGateway,
    ParentAuthority,
    default_tool_router,
)
from infrastructure.lineage.verifier import LineageVerifier


def create_app(
    *,
    authority: LineageAuthority | None,
    gateway: LineageGateway | None,
    registry: Any,
    root_did: str,
    governance_private_key: str | None = None,
    enabled: bool | None = None,
    control_token: str | None = None,
) -> Flask:
    app = Flask(__name__)
    active = (
        os.getenv("AGENTLINEAGE_ENABLED", "false").lower() == "true"
        if enabled is None else enabled
    )
    expected_token = control_token if control_token is not None else os.getenv(
        "AGENTLINEAGE_CONTROL_TOKEN", ""
    )

    def require_enabled():
        if not active:
            return jsonify({"error": "AgentLineage protocol is disabled"}), 503
        return None

    def require_control():
        unavailable = require_enabled()
        if unavailable:
            return unavailable
        if not expected_token or request.headers.get("X-AgentLineage-Control-Token") != expected_token:
            return jsonify({"error": "invalid control token"}), 403
        return None

    @app.get("/health")
    def health():
        return jsonify({"status": "ready" if active else "disabled", "root_did": root_did})

    @app.post("/v1/lineage/challenge")
    def challenge():
        unavailable = require_enabled()
        if unavailable:
            return unavailable
        if authority is None:
            return jsonify({"error": "spawn authority is not configured"}), 503
        return jsonify(authority.issue_challenge())

    @app.post("/v1/lineage/spawn")
    def spawn():
        denied = require_control()
        if denied:
            return denied
        if authority is None:
            return jsonify({"error": "spawn authority is not configured"}), 503
        try:
            return jsonify(authority.spawn(request.get_json(force=True)))
        except Exception as exc:
            return jsonify({"error": "spawn request rejected", "code": type(exc).__name__}), 400

    @app.post("/v1/lineage/invoke")
    def invoke():
        unavailable = require_enabled()
        if unavailable:
            return unavailable
        if gateway is None:
            return jsonify({"error": "lineage gateway is not configured"}), 503
        try:
            result = gateway.invoke(request.get_json(force=True))
            status = 200 if result["decision"]["accepted"] else 403
            return jsonify(result), status
        except Exception as exc:
            return jsonify({"error": "invalid lineage invocation", "code": type(exc).__name__}), 400

    @app.post("/v1/lineage/revoke")
    def revoke():
        denied = require_control()
        if denied:
            return denied
        if not governance_private_key:
            return jsonify({"error": "governance key is not configured"}), 503
        payload = request.get_json(force=True)
        try:
            result = registry.revoke(
                root_did, payload["kind"], str(payload["subject"]), governance_private_key
            )
            return jsonify(result)
        except Exception as exc:
            return jsonify({"error": "revocation rejected", "code": type(exc).__name__}), 400

    @app.get("/v1/lineage/status/<identifier>")
    def status(identifier: str):
        unavailable = require_enabled()
        if unavailable:
            return unavailable
        try:
            return jsonify(registry.get_status(identifier))
        except Exception as exc:
            return jsonify({"error": "status not found", "code": type(exc).__name__}), 404

    return app


def build_app_from_config(
    config_path: str = str(DEFAULT_CONFIG),
    state_path: str = str(DEFAULT_STATE),
) -> Flask:
    config = LineageRuntimeConfig.load(config_path)
    if not config.enabled:
        return create_app(
            authority=None,
            gateway=None,
            registry=None,
            root_did="",
            enabled=False,
        )

    state = load_public_state(state_path)
    if int(state["chain_id"]) != config.chain_id:
        raise ValueError("public state chain ID does not match lineage config")
    if state["registry_address"].lower() != config.registry_address.lower():
        raise ValueError("public state registry does not match lineage config")

    registry = config.registry()
    epoch = EpochKeyCertificate.from_dict(state["epoch_certificate"])
    parent_did, delegation_private_key, parent_credential = load_parent_authority_material(
        state, epoch
    )
    audit = LineageAuditRecorder(
        os.getenv(
            "AGENTLINEAGE_AUDIT_FILE",
            os.path.join(".codex", "lineage", "audit", "security.jsonl"),
        )
    )
    authority = LineageAuthority(
        ParentAuthority(
            root_did=epoch.root_did,
            parent_did=parent_did,
            epoch=epoch,
            delegation_private_key=delegation_private_key,
            permission=permission_from_state(state),
            parent_budget_id=state["parent_budget_id"],
            parent_credential=parent_credential,
        ),
        registry,
        chain_id=config.chain_id,
        verifying_contract=config.registry_address,
        audit=audit,
    )
    verifier = LineageVerifier(
        chain_id=config.chain_id,
        verifying_contract=config.registry_address,
        state_provider=registry,
        max_request_age_seconds=int(config.raw.get("max_request_age_seconds", 120)),
        max_state_block_lag=int(config.raw.get("max_state_block_lag", 2)),
    )
    gateway = LineageGateway(
        verifier,
        registry,
        default_tool_router(),
        audience=config.raw["gateway_audience"],
        audit=audit,
    )
    governance_key = os.getenv("AGENTLINEAGE_ROOT_IDENTITY_KEY") or None
    return create_app(
        authority=authority,
        gateway=gateway,
        registry=registry,
        root_did=epoch.root_did,
        governance_private_key=governance_key,
        enabled=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the AgentLineage policy enforcement gateway")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--state", default=str(DEFAULT_STATE))
    parser.add_argument("--host", default=os.getenv("AGENTLINEAGE_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("AGENTLINEAGE_PORT", "8100")))
    args = parser.parse_args()
    app = build_app_from_config(args.config, args.state)
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
