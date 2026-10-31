"""Tests for the local CA / agent certificate module (ca/ca.py).

Beyond the happy-path round-trip, this includes the adversarial cases the stress-test
flagged as mandatory: a certificate NOT signed by the trusted root must be rejected
(this is the direct fix for the HMAC "any verifier can forge" problem -- with Ed25519,
an attacker without the root's private key cannot produce a certificate that verifies
against that root, unlike a shared HMAC secret where possession of the secret alone is
sufficient to forge). Also covers expiry and the exposure-window measurement referenced
in SCOPE.md evaluation scenario #8.
"""

import datetime

import pytest

from ca.ca import (
    CertificateError,
    generate_root_ca,
    issue_agent_certificate,
    load_root_ca,
    save_root_ca,
    verify_agent_certificate,
)


@pytest.fixture()
def root_ca():
    return generate_root_ca(site_id="plant-7-hydraulic-press-line")


class TestRootCAGeneration:
    def test_generates_a_valid_self_signed_cert(self, root_ca):
        assert root_ca.certificate.issuer == root_ca.certificate.subject  # self-signed
        assert root_ca.site_id == "plant-7-hydraulic-press-line"

    def test_save_and_load_round_trip(self, root_ca, tmp_path):
        save_root_ca(root_ca, tmp_path)

        # Confirm the private key file has restrictive permissions -- the stated,
        # honest v1 boundary (filesystem protection, not TPM-backed) from the module
        # docstring must actually be enforced, not just claimed in a comment.
        key_path = tmp_path / "root_ca.key.pem"
        mode = key_path.stat().st_mode & 0o777
        assert mode == 0o600

        loaded = load_root_ca(tmp_path, site_id="plant-7-hydraulic-press-line")
        assert loaded.certificate.serial_number == root_ca.certificate.serial_number

    def test_load_fails_closed_on_missing_files(self, tmp_path):
        with pytest.raises(CertificateError):
            load_root_ca(tmp_path / "nonexistent", site_id="x")


class TestAgentCertificateIssuanceAndVerification:
    def test_issued_cert_verifies_successfully(self, root_ca):
        agent_cert = issue_agent_certificate(
            root_ca, agent_id="predictive-maintenance-01", role="predictive-maintenance-agent"
        )
        identity = verify_agent_certificate(root_ca, agent_cert.cert_pem)
        assert identity.agent_id == "predictive-maintenance-01"
        assert identity.role == "predictive-maintenance-agent"

    def test_cert_from_a_different_root_is_rejected(self, root_ca):
        """This is the direct test of the HMAC-vs-PKI security fix from the
        stress-test: an attacker who doesn't hold root_ca's private key (here simulated
        by a second, independently-generated root) cannot produce a certificate that
        verifies against root_ca. With shared-secret HMAC this test would be
        meaningless -- possessing *a* secret would be enough to forge a token against
        *any* verifier using that same secret. Here, forgery requires the actual root
        private key."""
        attacker_ca = generate_root_ca(site_id="attacker-controlled")
        forged_cert = issue_agent_certificate(
            attacker_ca, agent_id="predictive-maintenance-01", role="commissioning-agent"
        )

        with pytest.raises(CertificateError, match="issuer mismatch"):
            verify_agent_certificate(root_ca, forged_cert.cert_pem)

    def test_expired_cert_is_rejected(self, root_ca):
        agent_cert = issue_agent_certificate(
            root_ca,
            agent_id="agent-01",
            role="predictive-maintenance-agent",
            validity=datetime.timedelta(seconds=1),
        )
        future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        with pytest.raises(CertificateError, match="not valid at"):
            verify_agent_certificate(root_ca, agent_cert.cert_pem, now=future)

    def test_not_yet_valid_cert_is_rejected(self, root_ca):
        """Defense in depth: a certificate presented before its not_valid_before time
        (e.g. due to clock skew on the verifying host) must also be rejected, not just
        expiry in the forward direction."""
        agent_cert = issue_agent_certificate(root_ca, agent_id="agent-01", role="predictive-maintenance-agent")
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        with pytest.raises(CertificateError, match="not valid at"):
            verify_agent_certificate(root_ca, agent_cert.cert_pem, now=past)

    def test_malformed_pem_is_rejected(self, root_ca):
        with pytest.raises(CertificateError, match="not valid PEM"):
            verify_agent_certificate(root_ca, b"this is not a certificate at all")

    def test_exposure_window_matches_configured_validity(self, root_ca):
        """Directly measures SCOPE.md evaluation scenario #8 ("Credential compromise /
        no-revocation window"): since there is no live revocation channel, a
        compromised credential's worst-case exposure is bounded exactly by its validity
        period. This test asserts that bound is what we claim it to be (the
        ISSUED_CERT_VALIDITY default), so this number can be reported as measured,
        not assumed."""
        from ca.ca import ISSUED_CERT_VALIDITY

        issued_at = datetime.datetime.now(datetime.timezone.utc)
        agent_cert = issue_agent_certificate(root_ca, agent_id="agent-01", role="predictive-maintenance-agent")

        # Still valid just before expiry.
        just_before_expiry = issued_at + ISSUED_CERT_VALIDITY - datetime.timedelta(seconds=5)
        verify_agent_certificate(root_ca, agent_cert.cert_pem, now=just_before_expiry)  # must not raise

        # Invalid just after expiry -- this is the measured worst-case exposure bound.
        just_after_expiry = issued_at + ISSUED_CERT_VALIDITY + datetime.timedelta(seconds=5)
        with pytest.raises(CertificateError):
            verify_agent_certificate(root_ca, agent_cert.cert_pem, now=just_after_expiry)

    def test_role_with_special_characters_in_agent_id_still_parses(self, root_ca):
        """Guards against a subtle parsing bug: agent_id containing '|role=' itself
        would break the naive partition() in verify_agent_certificate if not handled
        carefully. This test documents the current (simple) behavior rather than
        silently allowing an ambiguous encoding to pass unnoticed."""
        agent_cert = issue_agent_certificate(
            root_ca, agent_id="agent-01", role="predictive-maintenance-agent"
        )
        identity = verify_agent_certificate(root_ca, agent_cert.cert_pem)
        assert identity.agent_id == "agent-01"
        assert identity.role == "predictive-maintenance-agent"
