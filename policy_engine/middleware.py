"""
middleware.py -- the FastMCP enforcement point.

Wraps every `tools/call` request: verifies the calling agent's certificate, looks up
their role and evaluates the requested tool + arguments against the loaded policy, then
either lets the call proceed, blocks it, or (for CONFIRM_REQUIRED) requires the caller to
have set an explicit confirmation flag in the request metadata. Every decision -- ALLOW,
DENY, or CONFIRM_REQUIRED -- is appended to the audit log before the middleware returns
or raises.

Design notes on how identity is carried (a deliberate, stated PoC scope boundary):
this middleware expects the calling agent's certificate (PEM bytes, base64-encoded) to
be present in the MCP request's `_meta` dict under the key `agent_cert_b64`. This is a
pragmatic choice for demonstrating the enforcement mechanism without needing to modify
FastMCP's underlying transport/session layer to carry a custom auth header end-to-end --
a production deployment might instead bind identity at the transport layer (e.g. mTLS
client certificates on the underlying stdio/HTTP connection) rather than per-request
metadata. This distinction should be stated explicitly in the project's implementation
section, not left implicit.

Fail-closed behavior (per SCOPE.md and STRESS_TEST.md, tested exhaustively in
tests/test_middleware.py):
  - Missing or malformed agent_cert_b64 -> DENY (cannot establish identity).
  - Certificate verification failure (expired, wrong issuer, bad signature) -> DENY.
  - Any exception raised by the policy engine itself (malformed policy, internal bug)
    -> DENY. This is implemented as a broad `except Exception` specifically because the
    fail-closed guarantee must hold even for bugs in this code, not just expected error
    paths -- see test_middleware.py::test_fail_closed_on_policy_engine_exception.
  - An unmapped/unwrapped tool (one this middleware's tool-coverage assertion didn't
    account for) -> DENY, never silently passed through. See the coverage-check
    machinery below.
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

import mcp.types as mt
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.tools.base import ToolResult

from ca.ca import CertificateError, RootCA, VerifiedIdentity, verify_agent_certificate
from policy_engine.audit_log import AuditLog
from policy_engine.policy import Decision, Policy, authorize

logger = logging.getLogger(__name__)


class AuthorizationDeniedError(ToolError):
    """Raised (as a ToolError, so FastMCP reports it back to the calling client as a
    normal tool-call failure rather than an uncaught server exception) when a tool call
    is denied by policy. Kept as a distinct subclass so tests and callers can
    distinguish "denied by policy" from other tool errors if useful."""


class ConfirmationRequiredError(ToolError):
    """Raised when a tool call matches a rule with require_confirm=true, and the caller
    did not supply a confirmation flag in the request metadata. This mirrors the
    existing iot-mcp-servers convention (confirm=True as a tool argument) but at the
    policy-enforcement layer rather than hard-coded per-tool -- see SCOPE.md's framing of
    this as generalizing what's currently hard-coded per-tool into a declarative policy."""


@dataclass
class ToolCoverageRegistry:
    """Tracks which tool names this middleware instance has been told about via
    register_expected_tools(), so that assert_full_coverage() can verify every tool the
    underlying MCP server actually exposes is accounted for. This directly implements
    the '100% tool-surface coverage' requirement from STRESS_TEST.md 2.3: 'every
    registered tool is enumerated and asserted-wrapped at startup, and unwrapped tools
    fail closed.'"""

    expected_tool_names: set[str]

    def assert_full_coverage(self, actual_tool_names: set[str]) -> None:
        """Call this once at server startup, after all @mcp.tool()-decorated functions
        have been registered, passing the live set of tool names FastMCP knows about
        (e.g. via `await mcp.get_tools()` -- see tests/test_middleware.py for the
        pattern). Raises RuntimeError if any tool exists on the server that this
        middleware's policy vocabulary doesn't know about -- this is a startup-time
        fail-loud check (better to crash at boot than silently let an unmapped tool
        bypass authorization at runtime).
        """
        unmapped = actual_tool_names - self.expected_tool_names
        if unmapped:
            raise RuntimeError(
                "Tool coverage assertion failed: the following tools are registered on "
                f"the MCP server but are not covered by any policy rule pattern: "
                f"{sorted(unmapped)}. Every tool must be reachable by at least one "
                "role's rule (even if only via an explicit DENY-all pattern) so that "
                "authorization coverage is provably complete, not assumed."
            )


class LocalAuthorizationMiddleware(Middleware):
    """The FastMCP middleware implementing this project's core enforcement point.

    Usage (see eclipse-ditto server retrofit for a concrete example):

        ca = load_root_ca(ca_dir, site_id=...)
        policy = load_and_verify_policy(ca, policy_path)
        audit_log = AuditLog.open(audit_log_path)
        mcp.add_middleware(LocalAuthorizationMiddleware(ca=ca, policy=policy, audit_log=audit_log))
    """

    def __init__(self, *, ca: RootCA, policy: Policy, audit_log: AuditLog) -> None:
        self._ca = ca
        self._policy = policy
        self._audit_log = audit_log

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: Callable[[MiddlewareContext[mt.CallToolRequestParams]], Awaitable[ToolResult]],
    ) -> ToolResult:
        tool_name = context.message.name
        arguments = context.message.arguments or {}

        # Fail-closed wrapper: ANY exception below (a bug in our own code included)
        # must resolve to DENY, never to "call_next() gets invoked anyway." This is
        # deliberately a broad except -- see module docstring and
        # STRESS_TEST.md 2.3 "Fail-open vs fail-closed under middleware exception."
        try:
            try:
                identity = self._verify_caller_identity(context)
            except CertificateError as e:
                # Identity verification failed (missing/expired/forged/malformed
                # certificate) -- this must still be audited, not silently dropped.
                # Found via real replay-scenario testing (SCOPE.md evaluation #2):
                # an expired/forged-cert attempt previously produced ZERO audit log
                # entries at all, because the original code path only logged AFTER
                # authorize() ran, which requires an already-verified identity. An
                # operator reviewing the log would have no record that someone
                # attempted a call with a bad credential -- a real visibility gap,
                # not just a theoretical one. Logged here with agent_id/role set to
                # "unverified" (never trust unverified certificate content for the
                # audit record itself) and the policy's own hash for correlation.
                self._audit_log.append(
                    agent_id="unverified",
                    role="unverified",
                    tool=tool_name,
                    decision=Decision.DENY.value,
                    matched_rule_index=None,
                    reason=f"identity verification failed: {e}",
                    policy_hash=self._policy.policy_hash,
                    arguments_summary=self._summarize_arguments(arguments),
                )
                raise

            requires_confirm_flag = self._extract_confirm_flag(context)

            result = authorize(
                self._policy,
                role=identity.role,
                tool=tool_name,
                arguments=arguments,
                clock_is_trusted=True,  # see module TODO / SCOPE.md future-work note:
                # a production deployment should source this from an actual local
                # clock-trust signal (e.g. "has this host successfully synced via NTP
                # recently, or does it have a battery-backed RTC known to be sane") --
                # hardcoded True here since simulating clock distrust is exercised
                # directly at the policy_engine.policy.authorize() layer's own tests,
                # not re-derived from real hardware state in this PoC.
            )

            self._audit_log.append(
                agent_id=identity.agent_id,
                role=identity.role,
                tool=tool_name,
                decision=result.decision.value,
                matched_rule_index=result.matched_rule_index,
                reason=result.reason,
                policy_hash=result.policy_hash,
                arguments_summary=self._summarize_arguments(arguments),
            )

            if result.decision == Decision.DENY:
                raise AuthorizationDeniedError(
                    f"Tool '{tool_name}' denied for role '{identity.role}': {result.reason}"
                )
            if result.decision == Decision.CONFIRM_REQUIRED and not requires_confirm_flag:
                raise ConfirmationRequiredError(
                    f"Tool '{tool_name}' requires explicit confirmation for role "
                    f"'{identity.role}' (matched rule: {result.reason}). Retry with "
                    "confirm_authorization=true in the request metadata."
                )

        except (AuthorizationDeniedError, ConfirmationRequiredError):
            raise  # these are the expected, already-audited denial paths -- re-raise as-is
        except Exception as e:
            # Anything else (audit log append failed, an unexpected bug in authorize()
            # itself) -- log it, and fail closed by denying the call rather than
            # letting it fall through to call_next(). Note: CertificateError from
            # identity verification is already audited and re-raised above, so it
            # reaches this generic handler too (to still produce the fail-closed
            # AuthorizationDeniedError the caller sees) but without double-logging.
            logger.error("Authorization middleware failed closed for tool %r: %s", tool_name, e)
            raise AuthorizationDeniedError(
                f"Tool '{tool_name}' denied: authorization could not be evaluated "
                f"({type(e).__name__}) -- failing closed."
            ) from e

        return await call_next(context)

    def _verify_caller_identity(
        self, context: MiddlewareContext[mt.CallToolRequestParams]
    ) -> VerifiedIdentity:
        cert_b64 = self._read_meta_field(context, "agent_cert_b64")

        if not cert_b64 or not isinstance(cert_b64, str):
            raise CertificateError(
                "no agent_cert_b64 present in request metadata -- cannot establish caller identity"
            )

        try:
            cert_pem = base64.b64decode(cert_b64, validate=True)
        except Exception as e:
            raise CertificateError(f"agent_cert_b64 is not valid base64: {e}") from e

        return verify_agent_certificate(self._ca, cert_pem)

    def _extract_confirm_flag(self, context: MiddlewareContext[mt.CallToolRequestParams]) -> bool:
        return bool(self._read_meta_field(context, "confirm_authorization"))

    @staticmethod
    def _read_meta_field(context: MiddlewareContext[mt.CallToolRequestParams], field_name: str) -> Any:
        """Read a caller-supplied field out of the MCP request's `_meta` object.

        This is NOT `context.message.meta` (which is only populated when the message
        itself carries top-level `_meta` -- in practice this was observed to be None
        for tool calls). The client-supplied `meta={...}` dict passed to
        `Client.call_tool(..., meta=...)` actually arrives on the SERVER side as
        `context.fastmcp_context.request_context.meta`, a pydantic `RequestParams.Meta`
        model with the caller's custom keys as extra attributes (verified directly
        against a live FastMCP request/response round-trip -- see the debugging session
        referenced in this project's build notes). We read it defensively via
        getattr()/model_dump() so a missing fastmcp_context or a meta object without
        the field we want both resolve to None rather than raising an AttributeError
        that would otherwise escape this fail-closed code path uncaught.
        """
        fastmcp_context = context.fastmcp_context
        if fastmcp_context is None:
            return None

        request_context = getattr(fastmcp_context, "request_context", None)
        if request_context is None:
            return None

        meta = getattr(request_context, "meta", None)
        if meta is None:
            return None

        # `meta` is a pydantic model (mcp.types.RequestParams.Meta) with the caller's
        # custom fields as extra/dynamic attributes, not a plain dict -- getattr works
        # for this because pydantic models with extra="allow"-style fields expose them
        # as real attributes.
        return getattr(meta, field_name, None)

    @staticmethod
    def _summarize_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
        """Redact/limit what gets written into the audit log's arguments_summary field.
        Current policy: pass through only string/int/float/bool scalar values, and only
        the first 200 chars of any string -- avoids accidentally logging large payloads
        or embedded secrets wholesale. See SCOPE.md for the broader point that
        arguments_summary is caller-controlled precisely to keep this concern local to
        the middleware, not baked into the audit log module itself.
        """
        summary: dict[str, Any] = {}
        for key, value in arguments.items():
            if isinstance(value, str):
                summary[key] = value[:200]
            elif isinstance(value, (int, float, bool)) or value is None:
                summary[key] = value
            else:
                summary[key] = f"<{type(value).__name__}>"
        return summary
