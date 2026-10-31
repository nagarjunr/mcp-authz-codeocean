"""Integration tests for the FastMCP enforcement middleware (policy_engine/middleware.py).

These build a real, minimal FastMCP server with the middleware attached and drive it
through a real FastMCP Client (in-memory transport -- no network, no subprocess), so
these tests exercise the actual FastMCP request/response pipeline, not a hand-rolled
simulation of it. This is what makes the coverage assertion, the on_call_tool
interception, and the fail-closed exception handling genuinely verified rather than
merely plausible.
"""

import base64

import pytest
from fastmcp import Client, FastMCP

from ca.ca import generate_root_ca, issue_agent_certificate
from policy_engine.audit_log import AuditLog, verify_chain
from policy_engine.middleware import LocalAuthorizationMiddleware, ToolCoverageRegistry
from policy_engine.policy import load_policy
from pathlib import Path

EXAMPLE_POLICY = Path(__file__).parent.parent / "examples" / "policy.example.yaml"


def _cert_meta(cert_pem: bytes, *, confirm: bool = False) -> dict:
    meta = {"agent_cert_b64": base64.b64encode(cert_pem).decode("ascii")}
    if confirm:
        meta["confirm_authorization"] = True
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
def test_server(ca, policy, audit_log):
    """A minimal FastMCP server with a handful of tools mirroring the eclipse-ditto
    server's shape closely enough to exercise the policy rules meaningfully (read
    tools, a scoped-create tool, a delete tool, a time-windowed tool), with the
    authorization middleware attached.
    """
    mcp = FastMCP("test-server")

    @mcp.tool()
    def get_thing(thing_id: str) -> dict:
        return {"thingId": thing_id, "status": "ok"}

    @mcp.tool()
    def get_things() -> dict:
        return {"items": []}

    @mcp.tool()
    def list_things() -> dict:
        return {"items": []}

    @mcp.tool()
    def count_things() -> int:
        return 0

    @mcp.tool()
    def get_thing_attributes(thing_id: str) -> dict:
        return {}

    @mcp.tool()
    def get_thing_features(thing_id: str) -> dict:
        return {}

    @mcp.tool()
    def get_feature(thing_id: str, feature_id: str) -> dict:
        return {}

    @mcp.tool()
    def get_feature_properties(thing_id: str, feature_id: str) -> dict:
        return {}

    @mcp.tool()
    def whoami() -> dict:
        return {"identity": "test"}

    @mcp.tool()
    def get_messages() -> dict:
        return {"messages": []}

    @mcp.tool()
    def list_subscriptions() -> dict:
        return {"subscriptions": []}

    @mcp.tool()
    def get_connection_status() -> dict:
        return {"status": "connected"}

    @mcp.tool()
    def put_thing(thing_id: str) -> dict:
        return {"thingId": thing_id, "updated": True}

    @mcp.tool()
    def delete_thing(thing_id: str, confirm: bool = False) -> dict:
        return {"thingId": thing_id, "deleted": True}

    @mcp.tool()
    def update_thing_shadow(thing_id: str) -> dict:
        return {"thingId": thing_id, "shadow_updated": True}

    @mcp.tool()
    def send_message(thing_id: str) -> dict:
        return {"thingId": thing_id, "sent": True}

    mcp.add_middleware(LocalAuthorizationMiddleware(ca=ca, policy=policy, audit_log=audit_log))
    return mcp


class TestToolCoverageAssertion:
    """Directly implements STRESS_TEST.md 2.3's '100% tool-surface coverage' requirement."""

    def test_coverage_passes_when_every_tool_is_covered(self):
        registry = ToolCoverageRegistry(
            expected_tool_names={"get_thing", "delete_thing", "create_thing"}
        )
        registry.assert_full_coverage({"get_thing", "delete_thing", "create_thing"})  # no raise

    def test_coverage_fails_when_a_tool_is_unmapped(self):
        registry = ToolCoverageRegistry(expected_tool_names={"get_thing"})
        with pytest.raises(RuntimeError, match="Tool coverage assertion failed"):
            registry.assert_full_coverage({"get_thing", "some_new_unmapped_tool"})


class TestEndToEndAuthorization:
    async def test_read_only_agent_can_call_get_thing(self, ca, test_server):
        agent_cert = issue_agent_certificate(ca, agent_id="pm-01", role="predictive-maintenance-agent")

        async with Client(test_server) as client:
            result = await client.call_tool(
                "get_thing", {"thing_id": "press-07"}, meta=_cert_meta(agent_cert.cert_pem)
            )
        assert result.data == {"thingId": "press-07", "status": "ok"}

    async def test_read_only_agent_denied_on_delete(self, ca, test_server):
        agent_cert = issue_agent_certificate(ca, agent_id="pm-01", role="predictive-maintenance-agent")

        async with Client(test_server) as client:
            with pytest.raises(Exception, match="denied"):
                await client.call_tool(
                    "delete_thing", {"thing_id": "press-07"}, meta=_cert_meta(agent_cert.cert_pem)
                )

    async def test_commissioning_agent_can_create_in_scope(self, ca, test_server):
        agent_cert = issue_agent_certificate(ca, agent_id="comm-01", role="commissioning-agent")

        async with Client(test_server) as client:
            result = await client.call_tool(
                "put_thing", {"thing_id": "staging:press-07"}, meta=_cert_meta(agent_cert.cert_pem)
            )
        assert result.data["updated"] is True

    async def test_commissioning_agent_denied_out_of_scope(self, ca, test_server):
        agent_cert = issue_agent_certificate(ca, agent_id="comm-01", role="commissioning-agent")

        async with Client(test_server) as client:
            with pytest.raises(Exception, match="denied"):
                await client.call_tool(
                    "put_thing",
                    {"thing_id": "production:press-07"},
                    meta=_cert_meta(agent_cert.cert_pem),
                )

    async def test_missing_certificate_is_denied(self, test_server):
        """No agent_cert_b64 at all in the request metadata -- identity cannot be
        established, so the call must be denied, not treated as some default role."""
        async with Client(test_server) as client:
            with pytest.raises(Exception, match="denied"):
                await client.call_tool("get_thing", {"thing_id": "press-07"})

    async def test_expired_certificate_is_denied(self, ca, test_server):
        import datetime

        from ca.ca import issue_agent_certificate as _issue

        agent_cert = _issue(
            ca,
            agent_id="pm-01",
            role="predictive-maintenance-agent",
            validity=datetime.timedelta(seconds=1),
        )
        # Certificate is valid for 1 second from issuance -- wait past that so it's
        # genuinely expired by wall-clock time when the middleware verifies it (the
        # middleware always verifies against "now", so we can't simulate a future
        # `now` the way test_ca.py's unit tests do; a real sleep is the honest way to
        # exercise this at the integration level).
        import asyncio

        await asyncio.sleep(1.2)

        async with Client(test_server) as client:
            with pytest.raises(Exception, match="denied"):
                await client.call_tool(
                    "get_thing", {"thing_id": "press-07"}, meta=_cert_meta(agent_cert.cert_pem)
                )

    async def test_forged_certificate_from_different_ca_is_denied(self, test_server):
        """The end-to-end version of test_cert_from_a_different_root_is_rejected --
        confirms the middleware, not just the underlying ca.py function in isolation,
        actually rejects a certificate that wasn't issued by the server's trusted root."""
        attacker_ca = generate_root_ca(site_id="attacker")
        forged_cert = issue_agent_certificate(attacker_ca, agent_id="pm-01", role="commissioning-agent")

        async with Client(test_server) as client:
            with pytest.raises(Exception, match="denied"):
                await client.call_tool(
                    "get_thing", {"thing_id": "press-07"}, meta=_cert_meta(forged_cert.cert_pem)
                )

    async def test_all_decisions_are_written_to_the_audit_log(self, ca, test_server, audit_log):
        agent_cert = issue_agent_certificate(ca, agent_id="pm-01", role="predictive-maintenance-agent")

        async with Client(test_server) as client:
            await client.call_tool(
                "get_thing", {"thing_id": "press-07"}, meta=_cert_meta(agent_cert.cert_pem)
            )
            with pytest.raises(Exception):
                await client.call_tool(
                    "delete_thing", {"thing_id": "press-07"}, meta=_cert_meta(agent_cert.cert_pem)
                )

        entries = audit_log.log_path.read_text().splitlines()
        assert len(entries) == 2  # one ALLOW, one DENY -- both recorded

        result = verify_chain(audit_log.log_path)
        assert result.valid
        assert result.entry_count == 2

    async def test_fail_closed_on_policy_engine_exception(self, ca, policy, tmp_path):
        """Directly implements STRESS_TEST.md's 'Fail-open vs fail-closed under
        middleware exception' requirement and SCOPE.md evaluation scenario #7. We
        simulate an internal policy-engine failure by pointing the middleware at an
        audit log path that cannot be written to (a directory, not a file), which
        forces AuditLog.append() to raise -- and confirm the tool call is still denied,
        not silently allowed through because logging failed.
        """
        unwritable_log = tmp_path / "not_a_file_but_a_dir"
        unwritable_log.mkdir()  # writing to a directory path will raise OSError

        broken_audit_log = AuditLog(log_path=unwritable_log)

        mcp = FastMCP("broken-test-server")

        @mcp.tool()
        def get_thing(thing_id: str) -> dict:
            return {"thingId": thing_id, "status": "ok"}

        mcp.add_middleware(
            LocalAuthorizationMiddleware(ca=ca, policy=policy, audit_log=broken_audit_log)
        )

        agent_cert = issue_agent_certificate(ca, agent_id="pm-01", role="predictive-maintenance-agent")

        async with Client(mcp) as client:
            with pytest.raises(Exception, match="denied"):
                await client.call_tool(
                    "get_thing", {"thing_id": "press-07"}, meta=_cert_meta(agent_cert.cert_pem)
                )

    async def test_confirm_required_tool_denied_without_confirm_flag(self, ca, test_server):
        agent_cert = issue_agent_certificate(ca, agent_id="er-01", role="emergency-response-agent")

        async with Client(test_server) as client:
            with pytest.raises(Exception):
                await client.call_tool(
                    "update_thing_shadow",
                    {"thing_id": "press-07"},
                    meta=_cert_meta(agent_cert.cert_pem, confirm=False),
                )
