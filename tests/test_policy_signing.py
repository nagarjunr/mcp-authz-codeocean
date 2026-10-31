"""Tests for policy document integrity protection (policy_engine/policy_signing.py).

The critical test here is test_tampered_policy_is_rejected -- this directly closes the
gap STRESS_TEST.md flagged: "an attacker... can edit [the policy file] to escalate
privileges directly, bypassing the entire credential/token layer." This test proves
that a modified policy file, even if it's still syntactically valid YAML that would
load fine on its own, is rejected before any of its (tampered) rules can be applied.
"""

from pathlib import Path

import pytest

from ca.ca import generate_root_ca
from policy_engine.policy_signing import (
    PolicySignatureError,
    load_and_verify_policy,
    sign_policy_file,
    signature_path_for,
    verify_policy_signature,
)

EXAMPLE_POLICY = Path(__file__).parent.parent / "examples" / "policy.example.yaml"


@pytest.fixture()
def ca():
    return generate_root_ca(site_id="test-site")


@pytest.fixture()
def signed_policy(ca, tmp_path):
    """Copies the example policy into a scratch dir and signs it there, so tests can
    freely mutate the copy without touching the real example file."""
    policy_copy = tmp_path / "policy.yaml"
    policy_copy.write_bytes(EXAMPLE_POLICY.read_bytes())
    sign_policy_file(ca, policy_copy)
    return policy_copy


class TestSigningAndVerification:
    def test_signature_file_is_created(self, signed_policy):
        sig_path = signature_path_for(signed_policy)
        assert sig_path.exists()
        assert sig_path.stat().st_size > 0

    def test_valid_signature_verifies(self, ca, signed_policy):
        verify_policy_signature(ca, signed_policy)  # must not raise

    def test_missing_signature_file_is_rejected(self, ca, tmp_path):
        unsigned = tmp_path / "unsigned.yaml"
        unsigned.write_bytes(EXAMPLE_POLICY.read_bytes())
        with pytest.raises(PolicySignatureError, match="no signature file"):
            verify_policy_signature(ca, unsigned)

    def test_tampered_policy_is_rejected(self, ca, signed_policy):
        """THE key test for this module. Simulates exactly the attack STRESS_TEST.md
        warned about: an attacker (or a misbehaving process) with filesystem write
        access modifies the policy file after it was signed -- here, granting the
        read-only predictive-maintenance-agent a DELETE capability it was never meant
        to have. Even though the resulting file is still perfectly valid YAML (it would
        load fine via policy_engine.policy.load_policy() in isolation), the signature
        check must catch the tampering and refuse to proceed."""
        original_bytes = signed_policy.read_bytes()
        tampered_bytes = original_bytes.replace(
            b'tools: ["delete_*", "claim_thing"]\n        effect: DENY',
            b'tools: ["delete_thing"]\n        effect: ALLOW  # TAMPERED: attacker-added privilege escalation',
        )
        assert tampered_bytes != original_bytes, "test setup error: replacement did not match anything"

        signed_policy.write_bytes(tampered_bytes)

        with pytest.raises(PolicySignatureError, match="failed signature verification"):
            verify_policy_signature(ca, signed_policy)

    def test_signature_from_different_ca_is_rejected(self, signed_policy):
        """A policy signed by one CA must not verify against a different CA's public
        key -- otherwise an attacker could generate their own CA, sign their own
        malicious policy with it, and present it alongside a stolen/copied signature
        file structure. This mirrors test_cert_from_a_different_root_is_rejected in
        test_ca.py."""
        attacker_ca = generate_root_ca(site_id="attacker-controlled")
        with pytest.raises(PolicySignatureError, match="failed signature verification"):
            verify_policy_signature(attacker_ca, signed_policy)

    def test_corrupted_signature_bytes_is_rejected(self, ca, signed_policy):
        sig_path = signature_path_for(signed_policy)
        sig_path.write_bytes(b"\x00" * 64)  # correct length for an Ed25519 sig, wrong content
        with pytest.raises(PolicySignatureError, match="failed signature verification"):
            verify_policy_signature(ca, signed_policy)


class TestLoadAndVerifyPolicy:
    def test_full_flow_loads_a_valid_signed_policy(self, ca, signed_policy):
        policy = load_and_verify_policy(ca, signed_policy)
        assert "predictive-maintenance-agent" in policy.roles

    def test_full_flow_rejects_a_tampered_policy_before_parsing_rules(self, ca, signed_policy):
        """End-to-end version of test_tampered_policy_is_rejected, going through the
        actual entry point (load_and_verify_policy) that server startup code will call
        -- confirms the ordering guarantee (signature check strictly before semantic
        load) holds through the convenience wrapper, not just the lower-level function."""
        original_bytes = signed_policy.read_bytes()
        tampered_bytes = original_bytes.replace(b"DENY", b"ALLOW")
        signed_policy.write_bytes(tampered_bytes)

        with pytest.raises(PolicySignatureError):
            load_and_verify_policy(ca, signed_policy)
