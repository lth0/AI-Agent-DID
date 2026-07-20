"""In-memory unit tests for the shared AgentDID DID/VC/VP protocol.

The tests deliberately avoid registries, RPC endpoints, contracts, and files.
Each negative test starts from a valid presentation and changes one security
property so that the rejecting protocol layer remains unambiguous.
"""

from __future__ import annotations

import copy
import datetime as dt
import unittest

from eth_account import Account

from infrastructure.agentdid_protocol import (
    DidVcVpVerifier,
    ProtocolIdentity,
    create_presentation,
    issue_credential,
    issue_status_list,
    make_did_document,
    parse_utc,
    relationship_method_ids,
    sign_json,
    utc_iso,
    verify_document_proof,
    verify_relationship_signature,
)
from infrastructure.security import ReplayGuard


CHAIN_ID = 31_337
STATUS_LIST_ID = "urn:uuid:agentdid-protocol-test-status-list"
STATUS_INDEX = 37


def _identity(role: str) -> ProtocolIdentity:
    """Create independent controller and operation keys for one test DID."""

    controller = Account.create()
    operation = Account.create()
    return ProtocolIdentity.from_keys(
        role,
        controller.key.hex(),
        operation.key.hex(),
        CHAIN_ID,
    )


class AgentDidProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.issuer = _identity("issuer")
        self.holder = _identity("holder")
        self.other_holder = _identity("other-holder")

        self.documents = {
            identity.did: make_did_document(identity)
            for identity in (self.issuer, self.holder, self.other_holder)
        }
        self.status_list = issue_status_list(
            self.issuer,
            list_id=STATUS_LIST_ID,
        )
        self.credential = issue_credential(
            self.issuer,
            self.holder.did,
            credential_type="AgentIdentityCredential",
            claims={"agentType": "test-agent", "profile": "protocol-v2"},
            status_list_id=STATUS_LIST_ID,
            status_index=STATUS_INDEX,
            credential_id="urn:uuid:agentdid-protocol-test-credential",
        )
        self.challenge = "challenge-agentdid-protocol-test"
        self.audience = "did:example:protocol-verifier"
        self.presentation = create_presentation(
            [self.credential],
            self.holder,
            challenge=self.challenge,
            audience=self.audience,
        )

    def verifier(
        self,
        *,
        trusted_issuers: list[str] | None = None,
        status_lists: dict[str, dict] | None = None,
        documents: dict[str, dict] | None = None,
        replay_guard: ReplayGuard | None = None,
    ) -> DidVcVpVerifier:
        return DidVcVpVerifier(
            self.documents if documents is None else documents,
            trusted_issuers=(
                [self.issuer.did]
                if trusted_issuers is None
                else trusted_issuers
            ),
            status_lists=(
                {STATUS_LIST_ID: self.status_list}
                if status_lists is None
                else status_lists
            ),
            replay_guard=replay_guard,
            max_age_seconds=120,
        )

    def verify(
        self,
        presentation: dict,
        *,
        verifier: DidVcVpVerifier | None = None,
        expected_holder: str | None = None,
        expected_challenge: str | None = None,
        expected_audience: str | None = None,
        now: dt.datetime | None = None,
    ):
        protocol_verifier = verifier or self.verifier()
        return protocol_verifier.verify(
            presentation,
            expected_holder=expected_holder or self.holder.did,
            expected_challenge=expected_challenge or self.challenge,
            expected_audience=expected_audience or self.audience,
            now=now,
        )

    def test_valid_did_vc_vp_is_accepted(self) -> None:
        decision = self.verify(self.presentation)

        self.assertTrue(decision.accepted)
        self.assertEqual("PROTOCOL_ACCEPTED", decision.code)

    def test_did_document_separates_authentication_and_assertion_method(self) -> None:
        document = self.documents[self.holder.did]
        authentication_id = f"{self.holder.did}#delegate"
        assertion_id = f"{self.holder.did}#controller"

        self.assertEqual(
            {authentication_id},
            relationship_method_ids(document, "authentication"),
        )
        self.assertEqual(
            {assertion_id},
            relationship_method_ids(document, "assertionMethod"),
        )

        body = {"purpose": "relationship-separation"}
        authentication_signature = sign_json(
            body,
            self.holder.operation_private_key,
        )
        assertion_signature = sign_json(
            body,
            self.holder.controller_private_key,
        )

        self.assertTrue(
            verify_relationship_signature(
                document,
                "authentication",
                body,
                authentication_signature,
            )
        )
        self.assertFalse(
            verify_relationship_signature(
                document,
                "assertionMethod",
                body,
                authentication_signature,
            )
        )
        self.assertTrue(
            verify_relationship_signature(
                document,
                "assertionMethod",
                body,
                assertion_signature,
            )
        )
        self.assertFalse(
            verify_relationship_signature(
                document,
                "authentication",
                body,
                assertion_signature,
            )
        )

    def test_vc_proof_requires_issuer_assertion_method(self) -> None:
        credential_body = copy.deepcopy(self.credential)
        proof = credential_body.pop("proof")

        self.assertTrue(
            verify_document_proof(
                self.documents[self.issuer.did],
                "assertionMethod",
                credential_body,
                proof,
            )
        )
        self.assertFalse(
            verify_document_proof(
                self.documents[self.issuer.did],
                "authentication",
                credential_body,
                proof,
            )
        )

    def test_vc_signed_by_operation_key_is_not_an_assertion(self) -> None:
        forged_credential = copy.deepcopy(self.credential)
        credential_body = copy.deepcopy(forged_credential)
        original_proof = credential_body.pop("proof")
        proof_options = {
            key: value for key, value in original_proof.items() if key != "jws"
        }
        proof_options["verificationMethod"] = f"{self.issuer.did}#delegate"
        forged_credential["proof"] = {
            **proof_options,
            "jws": sign_json(
                {"document": credential_body, "proofOptions": proof_options},
                self.issuer.operation_private_key,
            ),
        }
        presentation = create_presentation(
            [forged_credential],
            self.holder,
            challenge=self.challenge,
            audience=self.audience,
        )

        decision = self.verify(presentation)

        self.assertFalse(decision.accepted)
        self.assertEqual("VC_SIGNATURE_INVALID", decision.code)

    def test_vp_requires_authentication_key(self) -> None:
        forged_presentation = copy.deepcopy(self.presentation)
        presentation_body = copy.deepcopy(forged_presentation)
        original_proof = presentation_body.pop("proof")
        proof_options = {
            key: value for key, value in original_proof.items() if key != "jws"
        }
        proof_options["verificationMethod"] = f"{self.holder.did}#controller"
        forged_presentation["proof"] = {
            **proof_options,
            "jws": sign_json(
                {
                    "presentation": presentation_body,
                    "proofOptions": proof_options,
                },
                self.holder.controller_private_key,
            ),
        }

        decision = self.verify(forged_presentation)

        self.assertFalse(decision.accepted)
        self.assertEqual("VP_PROOF_OPTIONS_INVALID", decision.code)

    def test_vp_challenge_audience_and_created_are_signature_bound(self) -> None:
        original_created = parse_utc(self.presentation["proof"]["created"])
        cases = (
            (
                "challenge",
                "challenge-forged-but-otherwise-expected",
                {"expected_challenge": "challenge-forged-but-otherwise-expected"},
                None,
            ),
            (
                "audience",
                "did:example:forged-but-otherwise-expected",
                {"expected_audience": "did:example:forged-but-otherwise-expected"},
                None,
            ),
            (
                "created",
                utc_iso(original_created + dt.timedelta(seconds=1)),
                {},
                original_created,
            ),
        )

        for field, forged_value, expected_overrides, verification_time in cases:
            with self.subTest(proof_option=field):
                forged_presentation = copy.deepcopy(self.presentation)
                forged_presentation["proof"][field] = forged_value

                decision = self.verify(
                    forged_presentation,
                    verifier=self.verifier(),
                    now=verification_time,
                    **expected_overrides,
                )

                self.assertFalse(decision.accepted)
                self.assertEqual("VP_SIGNATURE_INVALID", decision.code)

    def test_vp_rejects_unexpected_challenge_and_audience(self) -> None:
        cases = (
            (
                "challenge",
                {"expected_challenge": "a-different-challenge"},
                "VP_CHALLENGE_MISMATCH",
            ),
            (
                "audience",
                {"expected_audience": "did:example:different-verifier"},
                "VP_AUDIENCE_MISMATCH",
            ),
        )

        for name, expected_overrides, expected_code in cases:
            with self.subTest(proof_option=name):
                decision = self.verify(
                    self.presentation,
                    verifier=self.verifier(),
                    **expected_overrides,
                )

                self.assertFalse(decision.accepted)
                self.assertEqual(expected_code, decision.code)

    def test_untrusted_issuer_is_rejected(self) -> None:
        decision = self.verify(
            self.presentation,
            verifier=self.verifier(trusted_issuers=[]),
        )

        self.assertFalse(decision.accepted)
        self.assertEqual("VC_ISSUER_UNTRUSTED", decision.code)

    def test_credential_subject_must_equal_presentation_holder(self) -> None:
        presentation = create_presentation(
            [self.credential],
            self.other_holder,
            challenge=self.challenge,
            audience=self.audience,
        )

        decision = self.verify(
            presentation,
            expected_holder=self.other_holder.did,
        )

        self.assertFalse(decision.accepted)
        self.assertEqual("VC_SUBJECT_HOLDER_MISMATCH", decision.code)

    def test_revoked_status_list_entry_is_rejected(self) -> None:
        revoked_status_list = issue_status_list(
            self.issuer,
            list_id=STATUS_LIST_ID,
            revoked_indices=[STATUS_INDEX],
        )

        decision = self.verify(
            self.presentation,
            verifier=self.verifier(
                status_lists={STATUS_LIST_ID: revoked_status_list}
            ),
        )

        self.assertFalse(decision.accepted)
        self.assertEqual("VC_STATUS_REVOKED", decision.code)
        self.assertTrue(
            revoked_status_list["credentialSubject"]["encodedList"].startswith("u")
        )

    def test_presentation_can_only_be_consumed_once(self) -> None:
        verifier = self.verifier(replay_guard=ReplayGuard(ttl_seconds=3_600))

        first = self.verify(self.presentation, verifier=verifier)
        replay = self.verify(self.presentation, verifier=verifier)

        self.assertTrue(first.accepted)
        self.assertEqual("PROTOCOL_ACCEPTED", first.code)
        self.assertFalse(replay.accepted)
        self.assertEqual("VP_REPLAY", replay.code)

    def test_challenge_can_only_authorize_one_fresh_presentation(self) -> None:
        verifier = self.verifier(replay_guard=ReplayGuard(ttl_seconds=3_600))
        first = self.verify(self.presentation, verifier=verifier)
        another_presentation = create_presentation(
            [self.credential],
            self.holder,
            challenge=self.challenge,
            audience=self.audience,
        )

        replay = self.verify(another_presentation, verifier=verifier)

        self.assertTrue(first.accepted)
        self.assertFalse(replay.accepted)
        self.assertEqual("VP_REPLAY", replay.code)

    def test_tampered_vc_signature_is_rejected(self) -> None:
        tampered_credential = copy.deepcopy(self.credential)
        tampered_credential["proof"]["jws"] = "0x00"
        presentation = create_presentation(
            [tampered_credential],
            self.holder,
            challenge=self.challenge,
            audience=self.audience,
        )

        decision = self.verify(presentation)

        self.assertFalse(decision.accepted)
        self.assertEqual("VC_SIGNATURE_INVALID", decision.code)

    def test_tampered_vp_signature_is_rejected(self) -> None:
        tampered_presentation = copy.deepcopy(self.presentation)
        tampered_presentation["proof"]["jws"] = "0x00"

        decision = self.verify(tampered_presentation)

        self.assertFalse(decision.accepted)
        self.assertEqual("VP_SIGNATURE_INVALID", decision.code)


if __name__ == "__main__":
    unittest.main()
