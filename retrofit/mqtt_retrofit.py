"""
mqtt_retrofit.py -- attaching LocalAuthorizationMiddleware to the real mqtt MCP
server, with ZERO modifications to the server's own source code.

Second retrofit target per SCOPE.md (after eclipse-ditto): mqtt was chosen alongside
Ditto specifically because it's self-hostable/disconnected-consistent (a local Mosquitto
broker, unlike aws-iot-core/azure-iot-hub which are cloud-only) and because it's the
most widely-recognized IoT protocol in the suite, per the earlier venue/protocol
discussion recorded in this project's session history.

Same pattern as retrofit/ditto_retrofit.py: the vendored server (retrofit/mqtt_vendor/
mqttmcpserver.py) is a byte-for-byte copy of the real server from the
iot-mcp-servers suite, and this module attaches middleware externally via the public
mcp.add_middleware() API -- no changes to the vendored file itself.
"""

from __future__ import annotations

import fnmatch

from fastmcp import FastMCP

from ca.ca import RootCA
from policy_engine.audit_log import AuditLog
from policy_engine.middleware import LocalAuthorizationMiddleware
from policy_engine.policy import Policy

# Importing this module registers all of mqtt's 7 tools onto its own module-level `mcp`
# object -- same side-effect-on-import pattern as any normal FastMCP server script.
from retrofit.mqtt_vendor import mqttmcpserver as mqtt_server


def _all_policy_tool_patterns(policy: Policy) -> set[str]:
    patterns: set[str] = set()
    for role_policy in policy.roles.values():
        for rule in role_policy.rules:
            patterns.update(rule.tools)
    return patterns


async def assert_policy_covers_every_mqtt_tool(mcp: FastMCP, policy: Policy) -> None:
    """Same completeness check as ditto_retrofit's version, applied to the real mqtt
    server's tool surface (7 tools: get_connection_status, publish_message,
    start_subscription, get_messages, stop_subscription, list_subscriptions,
    discover_topics). See STRESS_TEST.md 2.3.
    """
    tools = await mcp.list_tools()
    actual_tool_names = {tool.name for tool in tools}

    covered_patterns = _all_policy_tool_patterns(policy)

    uncovered = {
        tool_name
        for tool_name in actual_tool_names
        if not any(fnmatch.fnmatchcase(tool_name, pattern) for pattern in covered_patterns)
    }

    if uncovered:
        raise RuntimeError(
            "Policy coverage check failed for the mqtt retrofit: the following real "
            f"server tools match no policy rule pattern in any role: {sorted(uncovered)}. "
            "These tools would silently fall through to default_effect=DENY for every "
            "role -- add an explicit rule (even a DENY one) for these tools before "
            "deploying this policy."
        )


def build_authorized_mqtt_server(*, ca: RootCA, policy: Policy, audit_log: AuditLog) -> FastMCP:
    """Return the real mqtt FastMCP server object with LocalAuthorizationMiddleware
    attached. Same singleton-safe replace-not-stack behavior as
    ditto_retrofit.build_authorized_ditto_server() -- see that function's docstring for
    the full explanation of the bug this guards against (found via real-hardware
    testing on the Jetson): repeatedly calling this in the same process (e.g. once per
    test) must REPLACE the previously-attached middleware, not stack a new one on top
    of the module-level singleton `mqtt_server.mcp` object.
    """
    existing = getattr(mqtt_server.mcp, "_mcp_local_authz_middleware", None)
    if existing is not None:
        middleware_list = getattr(mqtt_server.mcp, "middleware", None)
        if middleware_list is not None and existing in middleware_list:
            middleware_list.remove(existing)

    new_middleware = LocalAuthorizationMiddleware(ca=ca, policy=policy, audit_log=audit_log)
    mqtt_server.mcp.add_middleware(new_middleware)
    mqtt_server.mcp._mcp_local_authz_middleware = new_middleware  # type: ignore[attr-defined]

    return mqtt_server.mcp
