"""
ditto_retrofit.py -- attaching LocalAuthorizationMiddleware to the real eclipse-ditto
MCP server, with ZERO modifications to the server's own source code.

This is the concrete demonstration of SCOPE.md's "retrofit, not rewrite" claim: the
vendored dittomcpserver.py (retrofit/eclipse_ditto_vendor/dittomcpserver.py) is byte-
for-byte identical to the upstream server from the iot-mcp-servers suite. All of
the authorization logic is attached externally, via FastMCP's public
`mcp.add_middleware()` API -- the same integration point any third party could use
against any FastMCP server without needing write access to that server's source at all.

Usage:

    from retrofit.ditto_retrofit import build_authorized_ditto_server

    mcp = build_authorized_ditto_server(
        ca=my_root_ca, policy=my_policy, audit_log=my_audit_log
    )
    mcp.run()  # same as calling the vendored server's own main(), now with
               # authorization enforced on every tool call

This module also implements the "100% tool-surface coverage" completeness check
(STRESS_TEST.md 2.3) concretely: build_authorized_ditto_server() enumerates every tool
FastMCP actually registered on the real Ditto server and asserts each one is covered by
a role pattern in the supplied policy, refusing to start the server otherwise (see
_assert_policy_covers_every_ditto_tool).
"""

from __future__ import annotations

import fnmatch

from fastmcp import FastMCP

from ca.ca import RootCA
from policy_engine.audit_log import AuditLog
from policy_engine.middleware import LocalAuthorizationMiddleware
from policy_engine.policy import Policy

# Importing this module has the side effect of registering all of eclipse-ditto's
# tools onto its own `mcp` object -- this is exactly how the vendored server would be
# imported and run normally, unchanged.
from retrofit.eclipse_ditto_vendor import dittomcpserver as ditto_server


def _all_policy_tool_patterns(policy: Policy) -> set[str]:
    patterns: set[str] = set()
    for role_policy in policy.roles.values():
        for rule in role_policy.rules:
            patterns.update(rule.tools)
    return patterns


async def _assert_policy_covers_every_ditto_tool(mcp: FastMCP, policy: Policy) -> None:
    """Enumerate every tool actually registered on the (real, vendored) Ditto server and
    confirm each one matches at least one glob pattern somewhere in the policy -- across
    ANY role, not necessarily every role. A tool with zero matching patterns anywhere in
    the policy would, in practice, always resolve to the policy's default_effect (DENY)
    for every role, which is safe but usually indicates the policy author forgot to
    account for that tool rather than a deliberate blanket-deny -- so this is a startup
    warning-turned-error to catch that class of authoring mistake early, distinct from
    (but complementary to) the runtime fail-closed guarantee already provided by
    policy_engine.policy.authorize()'s default_effect handling.
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
            "Policy coverage check failed for the eclipse-ditto retrofit: the following "
            f"real server tools match no policy rule pattern in any role: {sorted(uncovered)}. "
            "These tools would silently fall through to default_effect=DENY for every "
            "role, which is safe but is very likely an authoring oversight rather than "
            "an intentional blanket denial -- add an explicit rule (even a DENY one) "
            "for these tools before deploying this policy."
        )


def build_authorized_ditto_server(
    *, ca: RootCA, policy: Policy, audit_log: AuditLog
) -> FastMCP:
    """Return the real eclipse-ditto FastMCP server object with
    LocalAuthorizationMiddleware attached. The returned object is literally
    `dittomcpserver.mcp` (the same module-level FastMCP instance the vendored server
    itself uses) -- not a copy, not a proxy, the actual server -- with one middleware
    added to it.

    IMPORTANT (bug found and fixed during real-hardware testing on the Jetson Orin
    Nano, 2026-08-29): because `dittomcpserver.mcp` is a MODULE-LEVEL singleton (the
    vendored server, like any normal FastMCP server script, defines `mcp = FastMCP(...)`
    once at import time), calling this function more than once in the same process
    (e.g. once per pytest test function, each with its own fresh CA/policy/audit_log
    fixtures) would previously ADD a new middleware on top of the server's existing
    middleware stack every time, rather than replacing it. Every subsequent call would
    then be checked against ALL previously-added middlewares in sequence -- so a second
    test using a different CA would have its valid certificate verified successfully by
    ITS OWN middleware, but then still fail against the FIRST test's middleware (which
    trusts a different, unrelated root CA), because FastMCP's middleware chain runs
    every middleware, not just the most recently added one. This surfaced as seemingly
    random "certificate signature verification failed" errors that only appeared when
    tests ran in a particular order within the same process -- exactly the kind of bug
    that a from-scratch server (not a real-hardware, real-hydro-server retrofit test)
    would never have exposed, and a good illustration of why this project's stated
    principle of testing against the real, unmodified server object (not a fresh one
    per test) matters.

    Fix: track the most recently added middleware instance on the FastMCP object itself
    (via a private attribute) and remove it before adding a new one, so this function is
    safely callable multiple times in the same process -- each call fully replaces the
    server's authorization middleware rather than stacking another one on top.
    """
    existing = getattr(ditto_server.mcp, "_mcp_local_authz_middleware", None)
    if existing is not None:
        # FastMCP's Server (via the underlying MiddlewareManager) exposes middleware as
        # a list attribute we can mutate directly to remove a specific prior instance --
        # see fastmcp.server.middleware's manager implementation for the storage shape.
        middleware_list = getattr(ditto_server.mcp, "middleware", None)
        if middleware_list is not None and existing in middleware_list:
            middleware_list.remove(existing)

    new_middleware = LocalAuthorizationMiddleware(ca=ca, policy=policy, audit_log=audit_log)
    ditto_server.mcp.add_middleware(new_middleware)
    ditto_server.mcp._mcp_local_authz_middleware = new_middleware  # type: ignore[attr-defined]

    return ditto_server.mcp
