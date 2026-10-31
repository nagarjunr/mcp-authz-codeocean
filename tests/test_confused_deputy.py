"""Evaluation scenario #1 (confused-deputy / privilege-relay) -- SCOPE.md and
STRESS_TEST.md 2.3 both call this out as mandatory: "the single most-cited MCP-specific
attack pattern in 2026 literature."

The classic confused-deputy pattern in MCP: a low-privilege caller (Agent A) gets its
request executed with a higher-privilege caller's (Agent B's) authority, typically
because the server trusts SESSION-level identity/role rather than re-verifying
per-call. This module proves LocalAuthorizationMiddleware closes this specific pattern
by construction -- every tool call re-verifies the caller's certificate and re-derives
their role fresh from that certificate, with no session-level identity caching
anywhere in the authorization path (see policy_engine/middleware.py's
_verify_caller_identity, called on every on_call_tool invocation, not just once at
session start).

Three angles tested:
  1. Two agents (different roles) sharing the SAME underlying Client/session must each
     get their own certificate's role applied per call -- no bleed-through from
     whichever agent called most recently.
  2. A caller cannot smuggle a role/privilege claim through TOOL ARGUMENTS (as opposed
     to the verified certificate) -- role is derived exclusively from the certificate,
     so any attempt to pass e.g. {"role": "commissioning-agent"} as a tool argument has
     no effect on the authorization decision.
  3. A caller cannot "relay" a higher-privilege agent's identity by simply omitting
     their own certificate and hoping the middleware falls back to some ambient/cached
     identity -- confirmed via test_middleware.py's existing
     test_missing_certificate_is_denied, cross-referenced here for completeness.
"""

import base64

import pytest
from fastmcp import Client, FastMCP

from ca.ca import generate_root_ca, issue_agent_certificate
from policy_engine.audit_log import AuditLog
from policy_engine.middleware import LocalAuthorizationMiddleware
from policy_engine.policy import load_policy
from pathlib import Path

EXAMPLE_POLICY = Path(__file__).parent.parent / "examples" / "policy.example.yaml"


def _cert_meta(cert_pem: bytes, **extra) -> dict:
    meta = {"agent_cert_b64": base64.b64encode(cert_pem).decode("ascii")}
    meta.update(extra)
    return meta


@pytest.fixture()
def ca():
    return generate_root_ca(site_id="test-site")


@pytest.fixture()
def policy():
    return load_policy(EXAMPLE_POLICY)


@pytest.fixture()
def audit_log(tmp_path):
    return AuditLog.open(tmp_path / "audit.jsonl")


@pytest.fixture()
def confused_deputy_server(ca, policy, audit_log):
    """A minimal server exposing one read tool and one write tool, enough to
    distinguish the two roles' privileges cleanly."""
    mcp = FastMCP("confused-deputy-test-server")

    @mcp.tool()
    def get_thing(thing_id: str) -> dict:
        return {"thingId": thing_id, "status": "ok"}

    @mcp.tool()
    def put_thing(thing_id: str) -> dict:
        return {"thingId": thing_id, "updated": True}

    mcp.add_middleware(LocalAuthorizationMiddleware(ca=ca, policy=policy, audit_log=audit_log))
    return mcp


class TestPerCallIdentityBinding:
    """Angle 1: two agents sharing one Client/session, interleaved calls."""

    async def test_low_privilege_agent_cannot_borrow_high_privilege_agents_authority(
        self, ca, confused_deputy_server
    ):
        """Agent A (predictive-maintenance, read-only) and Agent B (commissioning,
        scoped-write) share the SAME FastMCP Client session. Confirm that A's calls are
        always evaluated under A's own role -- never accidentally elevated to B's role
        just because B made a call moments earlier on the same connection.
        """
        low_priv_cert = issue_agent_certificate(
            ca, agent_id="agent-a-low-priv", role="predictive-maintenance-agent"
        )
        high_priv_cert = issue_agent_certificate(
            ca, agent_id="agent-b-high-priv", role="commissioning-agent"
        )

        async with Client(confused_deputy_server) as client:
            # High-privilege agent calls first, establishing SOME activity on this session.
            result = await client.call_tool(
                "put_thing",
                {"thing_id": "staging:press-01"},
                meta=_cert_meta(high_priv_cert.cert_pem),
            )
            assert result.data["updated"] is True

            # Low-privilege agent then calls on the SAME client/session -- must still
            # be denied on the write tool, not silently inherit agent B's just-used
            # write privilege.
            with pytest.raises(Exception, match="denied"):
                await client.call_tool(
                    "put_thing",
                    {"thing_id": "staging:press-02"},
                    meta=_cert_meta(low_priv_cert.cert_pem),
                )

            # And agent A's own read privilege still works correctly afterward --
            # confirming denial isn't a session-wide side effect either.
            result = await client.call_tool(
                "get_thing", {"thing_id": "staging:press-02"}, meta=_cert_meta(low_priv_cert.cert_pem)
            )
            assert result.data["status"] == "ok"

    async def test_rapidly_alternating_agents_never_cross_contaminate(
        self, ca, confused_deputy_server
    ):
        """Stress the per-call re-verification more: alternate between two agents many
        times on one session, confirming each call is independently and correctly
        authorized every time -- no caching of "the last verified role" anywhere in the
        middleware's request path.
        """
        low_priv_cert = issue_agent_certificate(
            ca, agent_id="agent-a", role="predictive-maintenance-agent"
        )
        high_priv_cert = issue_agent_certificate(ca, agent_id="agent-b", role="commissioning-agent")

        async with Client(confused_deputy_server) as client:
            for i in range(5):
                # High-privilege write must succeed every time.
                result = await client.call_tool(
                    "put_thing",
                    {"thing_id": f"staging:press-{i}"},
                    meta=_cert_meta(high_priv_cert.cert_pem),
                )
                assert result.data["updated"] is True

                # Low-privilege write must be denied every time -- never "leaks
                # through" due to the immediately-preceding high-privilege success.
                with pytest.raises(Exception, match="denied"):
                    await client.call_tool(
                        "put_thing",
                        {"thing_id": f"staging:press-{i}-attempt-by-low-priv"},
                        meta=_cert_meta(low_priv_cert.cert_pem),
                    )


class TestRoleCannotBeSmuggledViaArguments:
    """Angle 2: role must come exclusively from the verified certificate, never from
    anything the caller can set directly via tool arguments or other request metadata
    fields."""

    async def test_role_argument_in_tool_call_is_ignored(self, ca, confused_deputy_server):
        """A low-privilege agent attempts to pass a 'role' field directly as a tool
        argument, hoping some naive implementation might read authorization role from
        request data rather than the verified certificate. Confirms this has zero
        effect -- the call is still evaluated (and denied) under the certificate's
        actual bound role.
        """
        low_priv_cert = issue_agent_certificate(
            ca, agent_id="agent-a", role="predictive-maintenance-agent"
        )

        with pytest.raises(Exception, match="denied"):
            async with Client(confused_deputy_server) as client:
                await client.call_tool(
                    "put_thing",
                    # Smuggled/spoofed role claim as a tool argument -- must be inert.
                    {"thing_id": "staging:press-01", "role": "commissioning-agent"},
                    meta=_cert_meta(low_priv_cert.cert_pem),
                )

    async def test_role_claim_in_request_meta_is_ignored(self, ca, confused_deputy_server):
        """Same idea, but attempting to smuggle a role claim via an EXTRA metadata
        field alongside the real certificate (rather than a tool argument). The
        middleware only ever reads 'agent_cert_b64' and 'confirm_authorization' from
        request meta (see policy_engine/middleware.py's _read_meta_field usage) --
        any other field, including one literally named 'role', must have zero
        influence on the authorization decision.
        """
        low_priv_cert = issue_agent_certificate(
            ca, agent_id="agent-a", role="predictive-maintenance-agent"
        )

        with pytest.raises(Exception, match="denied"):
            async with Client(confused_deputy_server) as client:
                await client.call_tool(
                    "put_thing",
                    {"thing_id": "staging:press-01"},
                    meta=_cert_meta(low_priv_cert.cert_pem, role="commissioning-agent"),
                )


class TestNoIdentityFallback:
    """Angle 3: cross-referenced with test_middleware.py's existing
    test_missing_certificate_is_denied -- a caller cannot "relay" through by simply
    omitting their own identity and hoping for an ambient/default/cached fallback."""

    async def test_omitting_certificate_after_a_previous_valid_call_is_still_denied(
        self, ca, confused_deputy_server
    ):
        """Even immediately after a legitimate, successfully-authorized call on the
        same session, a SUBSEQUENT call with NO certificate at all must still be denied
        -- there is no session-level 'last known good identity' fallback anywhere in
        the middleware.
        """
        high_priv_cert = issue_agent_certificate(ca, agent_id="agent-b", role="commissioning-agent")

        async with Client(confused_deputy_server) as client:
            result = await client.call_tool(
                "put_thing", {"thing_id": "staging:press-01"}, meta=_cert_meta(high_priv_cert.cert_pem)
            )
            assert result.data["updated"] is True

            with pytest.raises(Exception, match="denied"):
                await client.call_tool("put_thing", {"thing_id": "staging:press-02"})  # no meta at all
