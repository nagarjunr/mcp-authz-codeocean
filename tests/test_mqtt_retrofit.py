"""Integration tests for the mqtt retrofit (retrofit/mqtt_retrofit.py).

Like test_ditto_retrofit.py, these require a REAL running MQTT broker (Eclipse
Mosquitto) since the vendored mqtt server connects to MQTT_HOST at import time (see
mqtt_vendor/mqttmcpserver.py's module-level `client = _build_client()` call) --
importing the module without a reachable broker raises at import time, before any
skip marker could apply. Skipped automatically unless MQTT_HOST is set.

Run for real via:

    docker run -d --name test-mosquitto -p 1883:1883 eclipse-mosquitto:2 \\
        mosquitto -c /mosquitto-no-auth.conf
    MQTT_HOST=localhost MQTT_PORT=1883 .venv/bin/python -m pytest tests/test_mqtt_retrofit.py -v
"""

import os

import pytest

_MQTT_HOST = os.environ.get("MQTT_HOST")

pytestmark = pytest.mark.skipif(
    not _MQTT_HOST,
    reason=(
        "Requires a real running MQTT broker (Eclipse Mosquitto). Set MQTT_HOST (and "
        "optionally MQTT_PORT) to run this suite -- see module docstring for the "
        "docker command, or run on Jetson/other Docker-capable hardware."
    ),
)

if not _MQTT_HOST:
    # Same reasoning as test_ditto_retrofit.py's placeholder-env-var guard: the vendored
    # mqttmcpserver module reads MQTT_HOST directly from os.environ at import time (no
    # default), so importing retrofit.mqtt_retrofit would raise KeyError during test
    # collection itself if we didn't set a placeholder here. No test in this file
    # actually runs against this placeholder -- they're all skipped when MQTT_HOST
    # wasn't genuinely provided.
    os.environ["MQTT_HOST"] = "placeholder-unused.invalid"

import base64  # noqa: E402
import uuid  # noqa: E402

from fastmcp import Client  # noqa: E402

from ca.ca import generate_root_ca, issue_agent_certificate  # noqa: E402
from policy_engine.audit_log import AuditLog, verify_chain  # noqa: E402
from policy_engine.policy import load_policy  # noqa: E402
from pathlib import Path  # noqa: E402

EXAMPLE_POLICY = Path(__file__).parent.parent / "examples" / "policy.example.yaml"


def _cert_meta(cert_pem: bytes) -> dict:
    return {"agent_cert_b64": base64.b64encode(cert_pem).decode("ascii")}


@pytest.fixture()
def ca():
    return generate_root_ca(site_id="jetson-test-site")


@pytest.fixture()
def policy():
    return load_policy(EXAMPLE_POLICY)


@pytest.fixture()
def audit_log(tmp_path):
    return AuditLog.open(tmp_path / "mqtt_retrofit_audit.jsonl")


@pytest.fixture()
def authorized_mqtt_server(ca, policy, audit_log):
    # Local import (not at module top level) so this fixture's own import of
    # retrofit.mqtt_retrofit -- which connects to the real broker at import time via
    # the vendored server's module-level client -- only happens for tests that are
    # NOT skipped, i.e. only when a real MQTT_HOST was genuinely provided.
    from retrofit.mqtt_retrofit import build_authorized_mqtt_server

    return build_authorized_mqtt_server(ca=ca, policy=policy, audit_log=audit_log)


class TestRetrofitAgainstRealMqtt:
    async def test_policy_covers_every_real_mqtt_tool(self, authorized_mqtt_server, policy):
        from retrofit.mqtt_retrofit import assert_policy_covers_every_mqtt_tool

        await assert_policy_covers_every_mqtt_tool(authorized_mqtt_server, policy)

    async def test_predictive_maintenance_agent_can_check_connection_status(
        self, ca, authorized_mqtt_server
    ):
        agent_cert = issue_agent_certificate(
            ca, agent_id="pm-jetson-01", role="predictive-maintenance-agent"
        )

        async with Client(authorized_mqtt_server) as client:
            result = await client.call_tool(
                "get_connection_status", {}, meta=_cert_meta(agent_cert.cert_pem)
            )
        assert result.data["connected"] is True  # genuinely connected to the real broker

    async def test_predictive_maintenance_agent_denied_on_publish(
        self, ca, authorized_mqtt_server
    ):
        """Read-only role must not be able to publish -- confirms the DENY rule added
        for publish_message during this retrofit's policy-coverage pass actually holds,
        BEFORE any real MQTT PUBLISH packet is sent to the broker."""
        agent_cert = issue_agent_certificate(
            ca, agent_id="pm-jetson-01", role="predictive-maintenance-agent"
        )

        async with Client(authorized_mqtt_server) as client:
            with pytest.raises(Exception, match="denied"):
                await client.call_tool(
                    "publish_message",
                    {"topic": "test/retrofit", "payload": "should not be sent"},
                    meta=_cert_meta(agent_cert.cert_pem),
                )

    async def test_emergency_response_agent_can_publish_with_confirm(
        self, ca, policy, tmp_path
    ):
        """End-to-end: emergency-response-agent publishes a REAL message to the live
        broker (genuine MQTT PUBLISH + ack round-trip), gated by CONFIRM_REQUIRED since
        publish_message matches a require_confirm=true rule for this role.

        The policy's time_window condition (06:00-22:00 UTC) is real-wall-clock
        dependent, and this test suite may run at any hour -- rather than making this
        test flaky depending on when it's run (it already failed once this way during
        Jetson testing at 21:22 CDT / ~02:22 UTC, outside the window), we widen this
        specific test's own policy copy to drop the time_window condition entirely, so
        it deterministically exercises the CONFIRM_REQUIRED gating logic, independent
        of wall-clock time. The time-window mechanism's correctness is already covered
        independently and deterministically by tests/test_policy.py's
        TestTimeWindowCondition suite (which mocks the clock directly), so this
        integration test's job is to prove the end-to-end real-broker publish path, not
        to re-prove time-window logic.
        """
        import copy

        from policy_engine.audit_log import AuditLog
        from retrofit.mqtt_retrofit import build_authorized_mqtt_server

        widened_policy = copy.deepcopy(policy)
        for rule in widened_policy.roles["emergency-response-agent"].rules:
            if "publish_message" in rule.tools and "time_window" in rule.conditions:
                rule.conditions = {
                    k: v for k, v in rule.conditions.items() if k != "time_window"
                }

        audit_log = AuditLog.open(tmp_path / "widened_audit.jsonl")
        server = build_authorized_mqtt_server(ca=ca, policy=widened_policy, audit_log=audit_log)

        agent_cert = issue_agent_certificate(ca, agent_id="er-jetson-01", role="emergency-response-agent")
        topic = f"test/retrofit/{uuid.uuid4().hex[:8]}"

        async with Client(server) as client:
            # Without confirmation: must be denied (CONFIRM_REQUIRED, not auto-allowed).
            with pytest.raises(Exception):
                await client.call_tool(
                    "publish_message",
                    {"topic": topic, "payload": "test-payload"},
                    meta=_cert_meta(agent_cert.cert_pem),
                )

            # With confirmation: the real publish goes through.
            result = await client.call_tool(
                "publish_message",
                {"topic": topic, "payload": "test-payload", "qos": 1},
                meta={**_cert_meta(agent_cert.cert_pem), "confirm_authorization": True},
            )
        assert result.data["topic"] == topic
        assert result.data["acknowledged"] is True  # real broker ack, qos=1

    async def test_commissioning_agent_denied_on_all_mqtt_tools(self, ca, authorized_mqtt_server):
        """The commissioning-agent role is scoped to Ditto provisioning only -- it
        should have no access to MQTT messaging tools at all, per the explicit DENY
        block added for this role during the mqtt retrofit's coverage pass."""
        agent_cert = issue_agent_certificate(ca, agent_id="comm-jetson-01", role="commissioning-agent")

        async with Client(authorized_mqtt_server) as client:
            with pytest.raises(Exception, match="denied"):
                await client.call_tool(
                    "get_connection_status", {}, meta=_cert_meta(agent_cert.cert_pem)
                )

    async def test_audit_log_reflects_real_mqtt_interactions(self, ca, authorized_mqtt_server, audit_log):
        agent_cert = issue_agent_certificate(
            ca, agent_id="pm-jetson-01", role="predictive-maintenance-agent"
        )

        async with Client(authorized_mqtt_server) as client:
            await client.call_tool(
                "get_connection_status", {}, meta=_cert_meta(agent_cert.cert_pem)
            )
            with pytest.raises(Exception):
                await client.call_tool(
                    "publish_message",
                    {"topic": "test/retrofit", "payload": "x"},
                    meta=_cert_meta(agent_cert.cert_pem),
                )

        result = verify_chain(audit_log.log_path)
        assert result.valid
        assert result.entry_count == 2
