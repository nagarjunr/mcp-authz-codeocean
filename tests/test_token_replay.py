"""Evaluation scenario #2 (token replay / stolen-credential) -- SCOPE.md's mandatory
addition, per STRESS_TEST.md 2.1: "capture a valid signed token, replay it after the
legitimate agent's session ended; show whether/how your design detects or prevents
this."

Honest framing up front (this is important -- see SCOPE.md's design decision and the
stress-test's own critique): this project's v1 credential scheme is a BEARER
certificate, not a per-call signed proof. A captured cert_pem, replayed verbatim, WILL
successfully re-authenticate as that agent for as long as the certificate remains
within its validity window -- this is a known, explicitly-scoped limitation, not
something this test suite is pretending to solve. What this test suite DOES verify,
honestly:

  1. A replayed (captured) certificate works exactly as long as, and no longer than,
     its validity window -- i.e. the "worst-case exposure window" claim from
     tests/test_ca.py::test_exposure_window_matches_configured_validity is confirmed
     to hold in the full middleware/audit-log path too, not just at the raw
     ca.py-function level.
  2. Once a certificate expires, a replay attempt is denied -- expiry is a real,
     enforced boundary, not just a claim.
  3. Every replay attempt (successful or not) is faithfully recorded in the audit log,
     including MULTIPLE uses of the identical certificate -- so even though replay
     itself isn't cryptographically prevented in v1, it is NOT silent: an operator
     reviewing the audit log sees the same agent_id/cert making repeated calls, which
     is the detection-not-prevention posture this project takes elsewhere (see
     audit_log.py's own docstring) applied consistently to this attack class too.
  4. What replay does NOT get past: a replayed certificate still only grants the ROLE
     it was actually issued for -- it cannot be replayed "as" a different, more
     privileged role no matter how it's replayed, since role is embedded in and
     verified as part of the certificate itself (same guarantee tested from the
     confused-deputy angle in test_confused_deputy.py).

This module explicitly does NOT claim to implement nonce-based replay prevention or
per-call signing (both named as future work in SCOPE.md/STRESS_TEST.md) -- it tests and
documents the ACTUAL bound (TTL-limited exposure, auditable, role-locked), consistent
with the honesty-over-overclaiming principle used throughout this project's preparation.
"""

import base64
import datetime

import pytest
from fastmcp import Client, FastMCP

from ca.ca import generate_root_ca, issue_agent_certificate
from policy_engine.audit_log import AuditLog, verify_chain
from policy_engine.middleware import LocalAuthorizationMiddleware
from policy_engine.policy import load_policy
from pathlib import Path

EXAMPLE_POLICY = Path(__file__).parent.parent / "examples" / "policy.example.yaml"


def _cert_meta(cert_pem: bytes) -> dict:
    return {"agent_cert_b64": base64.b64encode(cert_pem).decode("ascii")}


@pytest.fixture()
def ca():
    return generate_root_ca(site_id="test-site")


@pytest.fixture()
def policy():
    return load_policy(EXAMPLE_POLICY)


@pytest.fixture()
def replay_test_server_and_log(ca, policy, tmp_path):
    audit_log = AuditLog.open(tmp_path / "audit.jsonl")
    mcp = FastMCP("replay-test-server")

    @mcp.tool()
    def get_thing(thing_id: str) -> dict:
        return {"thingId": thing_id, "status": "ok"}

    mcp.add_middleware(LocalAuthorizationMiddleware(ca=ca, policy=policy, audit_log=audit_log))
    return mcp, audit_log


class TestReplayWithinValidityWindow:
    async def test_captured_certificate_can_be_replayed_within_validity_window(
        self, ca, replay_test_server_and_log
    ):
        """Honest baseline: this is the actual (limited) guarantee this v1 design
        provides -- NOT that replay is prevented, but that its consequences are bounded
        and auditable. A "captured" certificate (simulated: we just reuse the same
        cert_pem bytes across multiple independent calls, exactly as an attacker who
        exfiltrated it from a log file or a compromised intermediate host would) DOES
        successfully re-authenticate multiple times, as expected for a bearer-token
        scheme -- this is documented as a known limitation, not silently glossed over.
        """
        mcp, audit_log = replay_test_server_and_log
        agent_cert = issue_agent_certificate(
            ca, agent_id="pm-01", role="predictive-maintenance-agent"
        )
        captured_cert_pem = agent_cert.cert_pem  # the "stolen" credential

        async with Client(mcp) as client:
            # Legitimate original use.
            result1 = await client.call_tool(
                "get_thing", {"thing_id": "t1"}, meta=_cert_meta(captured_cert_pem)
            )
            assert result1.data["status"] == "ok"

            # "Attacker" replays the identical captured bytes, e.g. from an
            # exfiltrated log file, after the legitimate session ended.
            result2 = await client.call_tool(
                "get_thing", {"thing_id": "t2"}, meta=_cert_meta(captured_cert_pem)
            )
            assert result2.data["status"] == "ok"  # replay succeeds -- the known, honest limitation

        # But every use -- legitimate or replayed -- is faithfully recorded, so the
        # replay is NOT silent even though it isn't prevented.
        verification = verify_chain(audit_log.log_path)
        assert verification.valid
        assert verification.entry_count == 2

    async def test_replay_is_role_locked_even_though_not_prevented(
        self, ca, policy, tmp_path
    ):
        """Critically: even a successfully-replayed certificate only ever grants the
        role it was ACTUALLY issued for -- a captured predictive-maintenance-agent
        certificate can be replayed all day, but it will never let an attacker perform
        a commissioning-agent action, because the role is bound into and verified from
        the certificate itself (same underlying guarantee as the confused-deputy tests).
        Replay is a real, honestly-scoped limitation, but it is NOT a privilege
        escalation vector on top of being a replay vector.
        """
        audit_log = AuditLog.open(tmp_path / "audit.jsonl")
        mcp = FastMCP("replay-role-lock-test-server")

        @mcp.tool()
        def put_thing(thing_id: str) -> dict:
            return {"thingId": thing_id, "updated": True}

        mcp.add_middleware(LocalAuthorizationMiddleware(ca=ca, policy=policy, audit_log=audit_log))

        low_priv_cert = issue_agent_certificate(
            ca, agent_id="pm-01", role="predictive-maintenance-agent"
        )
        captured_cert_pem = low_priv_cert.cert_pem

        async with Client(mcp) as client:
            for _ in range(3):  # replay it repeatedly
                with pytest.raises(Exception, match="denied"):
                    await client.call_tool(
                        "put_thing", {"thing_id": "staging:x"}, meta=_cert_meta(captured_cert_pem)
                    )


class TestReplayBeyondValidityWindow:
    async def test_replay_after_expiry_is_denied(self, ca, policy, tmp_path):
        """The actual bound on this project's replay exposure: once a certificate's
        validity window elapses, replay attempts are denied, same as any other expired
        credential. This confirms the exposure-window guarantee
        (tests/test_ca.py::test_exposure_window_matches_configured_validity) holds
        through the FULL middleware path against a real FastMCP server, not just at
        the raw ca.py function level.
        """
        audit_log = AuditLog.open(tmp_path / "audit.jsonl")
        mcp = FastMCP("replay-expiry-test-server")

        @mcp.tool()
        def get_thing(thing_id: str) -> dict:
            return {"thingId": thing_id, "status": "ok"}

        mcp.add_middleware(LocalAuthorizationMiddleware(ca=ca, policy=policy, audit_log=audit_log))

        short_lived_cert = issue_agent_certificate(
            ca,
            agent_id="pm-01",
            role="predictive-maintenance-agent",
            validity=datetime.timedelta(seconds=1),
        )
        captured_cert_pem = short_lived_cert.cert_pem

        async with Client(mcp) as client:
            # Legitimate use, within the validity window.
            result = await client.call_tool(
                "get_thing", {"thing_id": "t1"}, meta=_cert_meta(captured_cert_pem)
            )
            assert result.data["status"] == "ok"

            # Wait past expiry -- simulates the "replayed after the legitimate
            # session ended" scenario from STRESS_TEST.md's evaluation scenario #2,
            # combined with the actual TTL bound.
            import asyncio

            await asyncio.sleep(1.2)

            # The exact same captured bytes, replayed now, must be denied.
            with pytest.raises(Exception, match="denied"):
                await client.call_tool(
                    "get_thing", {"thing_id": "t2"}, meta=_cert_meta(captured_cert_pem)
                )

        # Both the successful original use AND the denied replay attempt are recorded
        # -- an operator reviewing the log sees exactly what happened.
        verification = verify_chain(audit_log.log_path)
        assert verification.valid
        assert verification.entry_count == 2
