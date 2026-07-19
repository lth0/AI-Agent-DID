"""Opt-in adversarial behaviours for controlled AgentDID experiments.

No attack is enabled unless AGENTDID_ATTACK_MODE is explicitly set.  These
profiles must only be used with test DIDs and local/Sepolia infrastructure.
"""

from __future__ import annotations

import copy
import dataclasses
import os
from typing import Any

from infrastructure.security import canonical_json


SUPPORTED_ATTACK_MODES = {
    "none",
    "impersonation",
    "vp_replay",
    "vc_replay_duplicate",
    "false_capability",
    "holder_vc_tamper",
    "false_state",
    "signed_false_state",
}


@dataclasses.dataclass(frozen=True)
class AttackProfile:
    mode: str = "none"
    experiment_id: str = ""
    impersonated_did: str = ""

    @classmethod
    def from_environment(cls) -> "AttackProfile":
        mode = os.getenv("AGENTDID_ATTACK_MODE", "none").strip().lower()
        if mode not in SUPPORTED_ATTACK_MODES:
            raise ValueError(
                f"Unsupported AGENTDID_ATTACK_MODE={mode!r}; "
                f"choose from {sorted(SUPPORTED_ATTACK_MODES)}"
            )
        return cls(
            mode=mode,
            experiment_id=os.getenv("AGENTDID_EXPERIMENT_ID", ""),
            impersonated_did=os.getenv("AGENTDID_IMPERSONATED_DID", ""),
        )


class AttackInjector:
    def __init__(self, profile: AttackProfile):
        self.profile = profile
        self._captured_vp: dict[str, Any] | None = None
        self._captured_context_hash: str | None = None

    @property
    def enabled(self) -> bool:
        return self.profile.mode != "none"

    def _signed_vp(self, wallet: Any, nonce: str, holder_did: str, vcs: list[dict]) -> dict:
        body = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": vcs,
            "holder": holder_did,
        }
        vp = copy.deepcopy(body)
        vp["proof"] = {
            "type": "EcdsaSecp256k1RecoverySignature2020",
            "verificationMethod": f"{holder_did}#delegate",
            "proofPurpose": "authentication",
            "challenge": nonce,
            "jws": wallet.sign_message(canonical_json(body)),
        }
        return vp

    def create_vp(self, wallet: Any, nonce: str) -> tuple[dict, str]:
        mode = self.profile.mode
        if mode == "vp_replay" and self._captured_vp is not None:
            return copy.deepcopy(self._captured_vp), "replayed_previous_vp"

        holder_did = wallet.did
        vcs = copy.deepcopy(wallet.my_vcs)

        if mode == "impersonation":
            if not self.profile.impersonated_did:
                raise ValueError("AGENTDID_IMPERSONATED_DID is required for impersonation")
            holder_did = self.profile.impersonated_did
        elif mode == "vc_replay_duplicate" and vcs:
            vcs.append(copy.deepcopy(vcs[0]))
        elif mode in {"false_capability", "holder_vc_tamper"}:
            for vc in vcs:
                if "AgentCapabilityCredential" in vc.get("type", []):
                    evaluation = vc.setdefault("credentialSubject", {}).setdefault("evaluation", {})
                    evaluation["ratingValue"] = "1.000"
                    evaluation["attackMutation"] = "unsigned-capability-inflation"
                    break

        vp = self._signed_vp(wallet, nonce, holder_did, vcs)
        if mode == "vp_replay" and self._captured_vp is None:
            self._captured_vp = copy.deepcopy(vp)
            return vp, "captured_vp_for_replay"
        return vp, mode

    def semantic_state(
        self,
        actual_artifact_digest: str,
        certified_artifact_digest: str,
        actual_ready: bool,
        state_version: int,
    ) -> tuple[dict[str, Any], str]:
        """Return the state that the Holder reports to a semantic verifier.

        ``signed_false_state`` is deliberately different from ``false_state``:
        the latter replays a context hash for the legacy experiment, while the
        former creates a fresh, fully signed statement whose semantic content is
        false.  The returned state never contains an attack marker; that marker
        belongs only in the research audit trail.
        """

        if self.profile.mode == "signed_false_state":
            return {
                "artifactDigest": certified_artifact_digest,
                "ready": True,
                "stateVersion": state_version,
            }, "reported_certified_artifact_while_running_faulty_artifact"

        return {
            "artifactDigest": actual_artifact_digest,
            "ready": bool(actual_ready),
            "stateVersion": state_version,
        }, "honest_state"

    def context_hash(self, real_hash: str) -> tuple[str, str]:
        if self.profile.mode != "false_state":
            return real_hash, "none"
        if self._captured_context_hash is None:
            self._captured_context_hash = real_hash
            return real_hash, "captured_initial_state"
        return self._captured_context_hash, "reported_stale_state"
