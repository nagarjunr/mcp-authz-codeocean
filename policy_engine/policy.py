"""
policy.py -- the local, control-plane-optional MCP authorization policy engine.

This module implements the core decision function described in SCOPE.md: given a
caller's verified role, the tool they're trying to invoke, and the arguments they're
passing, decide ALLOW / DENY / CONFIRM_REQUIRED. It has zero network dependency --
everything it needs (the policy document, the verifying keys) is loaded from local
disk at startup.

Design invariants (see STRESS_TEST.md and SCOPE.md for the reasoning):
  - Fail-closed by default: any error (malformed policy, verification failure, clock
    distrust, unexpected exception) resolves to DENY, never ALLOW.
  - Policy document integrity is verified at load time via a detached signature file
    (see verify_policy_signature) -- a tampered policy is rejected outright at startup,
    and its hash is still recorded so a *successful* load's provenance is auditable too.
  - No implicit fallback conditions: every condition type the engine understands is
    listed in SUPPORTED_CONDITION_TYPES; an unrecognized condition key in a policy rule
    is a hard load-time error, not a silently-ignored no-op (silently ignoring an
    unrecognized condition could accidentally grant broader access than the policy author
    intended).
"""

from __future__ import annotations

import fnmatch
import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

SUPPORTED_CONDITION_TYPES = {"arg_prefix", "time_window"}


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    CONFIRM_REQUIRED = "CONFIRM_REQUIRED"


class PolicyLoadError(Exception):
    """Raised when a policy document fails to load or verify. Callers MUST treat this
    as fail-closed: do not fall back to an unauthenticated/default-allow state."""


@dataclass
class AuthorizationResult:
    decision: Decision
    role: str
    tool: str
    reason: str
    matched_rule_index: int | None = None
    policy_hash: str = ""


@dataclass
class Rule:
    tools: list[str]
    effect: Decision
    conditions: dict[str, Any] = field(default_factory=dict)
    require_confirm: bool = False
    reason: str = ""

    def matches_tool(self, tool_name: str) -> bool:
        return any(fnmatch.fnmatchcase(tool_name, pattern) for pattern in self.tools)


@dataclass
class RolePolicy:
    description: str
    rules: list[Rule]


@dataclass
class Policy:
    schema_version: int
    metadata: dict[str, Any]
    roles: dict[str, RolePolicy]
    default_effect: Decision
    policy_hash: str  # SHA-256 of the raw file bytes, computed at load time


def _compute_hash(raw_bytes: bytes) -> str:
    return hashlib.sha256(raw_bytes).hexdigest()


def load_policy(policy_path: str | Path) -> Policy:
    """Load and validate a policy YAML file. Raises PolicyLoadError on any problem --
    callers must treat that as fail-closed (deny everything) rather than proceeding
    with a partially-loaded or default policy.

    NOTE: this function does NOT verify the detached signature -- that is a separate
    step (verify_policy_signature) so that hash computation and signature verification
    are independently testable (see tests/test_policy_tamper.py).
    """
    path = Path(policy_path)
    try:
        raw_bytes = path.read_bytes()
    except OSError as e:
        raise PolicyLoadError(f"cannot read policy file {path}: {e}") from e

    policy_hash = _compute_hash(raw_bytes)

    try:
        doc = yaml.safe_load(raw_bytes)
    except yaml.YAMLError as e:
        raise PolicyLoadError(f"policy file {path} is not valid YAML: {e}") from e

    if not isinstance(doc, dict):
        raise PolicyLoadError(f"policy file {path} did not parse to a mapping")

    schema_version = doc.get("schema_version")
    if schema_version != 1:
        raise PolicyLoadError(
            f"unsupported schema_version {schema_version!r} (this engine supports version 1 only)"
        )

    default_effect_raw = doc.get("default_effect")
    if default_effect_raw != "DENY":
        # This is deliberately a hard failure, not a warning: a policy author (or an
        # attacker who tampered with the file) setting default_effect to ALLOW would
        # silently defeat every fail-closed guarantee this engine is supposed to provide.
        raise PolicyLoadError(
            "policy document's default_effect must be 'DENY' -- refusing to load a "
            f"policy with default_effect={default_effect_raw!r}"
        )

    roles_raw = doc.get("roles")
    if not isinstance(roles_raw, dict) or not roles_raw:
        raise PolicyLoadError("policy document must define at least one role under 'roles'")

    roles: dict[str, RolePolicy] = {}
    for role_name, role_doc in roles_raw.items():
        if not isinstance(role_doc, dict):
            raise PolicyLoadError(f"role {role_name!r} must be a mapping")

        rules_raw = role_doc.get("rules")
        if not isinstance(rules_raw, list) or not rules_raw:
            raise PolicyLoadError(f"role {role_name!r} must define at least one rule")

        rules: list[Rule] = []
        for i, rule_doc in enumerate(rules_raw):
            rules.append(_parse_rule(role_name, i, rule_doc))

        roles[role_name] = RolePolicy(
            description=role_doc.get("description", ""),
            rules=rules,
        )

    return Policy(
        schema_version=schema_version,
        metadata=doc.get("metadata", {}),
        roles=roles,
        default_effect=Decision.DENY,
        policy_hash=policy_hash,
    )


def _parse_rule(role_name: str, index: int, rule_doc: Any) -> Rule:
    if not isinstance(rule_doc, dict):
        raise PolicyLoadError(f"role {role_name!r} rule #{index} must be a mapping")

    tools = rule_doc.get("tools")
    if not isinstance(tools, list) or not tools or not all(isinstance(t, str) for t in tools):
        raise PolicyLoadError(
            f"role {role_name!r} rule #{index} must have a non-empty 'tools' list of strings"
        )

    effect_raw = rule_doc.get("effect")
    try:
        effect = Decision(effect_raw)
    except ValueError:
        raise PolicyLoadError(
            f"role {role_name!r} rule #{index} has invalid effect {effect_raw!r} "
            f"(must be one of {[d.value for d in Decision]})"
        ) from None

    conditions = rule_doc.get("conditions", {}) or {}
    if not isinstance(conditions, dict):
        raise PolicyLoadError(f"role {role_name!r} rule #{index}: 'conditions' must be a mapping")

    unsupported = set(conditions.keys()) - SUPPORTED_CONDITION_TYPES
    if unsupported:
        # Hard failure by design -- see module docstring. An unrecognized condition key
        # must not be silently ignored, since that could grant broader access than
        # intended by whoever authored the policy.
        raise PolicyLoadError(
            f"role {role_name!r} rule #{index} uses unsupported condition type(s) "
            f"{sorted(unsupported)}; supported types are {sorted(SUPPORTED_CONDITION_TYPES)}"
        )

    return Rule(
        tools=tools,
        effect=effect,
        conditions=conditions,
        require_confirm=bool(rule_doc.get("require_confirm", False)),
        reason=rule_doc.get("reason", ""),
    )


def _check_arg_prefix_condition(condition: dict[str, str], arguments: dict[str, Any]) -> bool:
    for arg_name, required_prefix in condition.items():
        value = arguments.get(arg_name)
        if not isinstance(value, str) or not value.startswith(required_prefix):
            return False
    return True


def _check_time_window_condition(
    condition: dict[str, str], *, clock_is_trusted: bool, now: datetime | None = None
) -> bool:
    # Fail closed if the caller can't vouch for clock trust (e.g. no NTP reachable and
    # RTC known to have reset) -- see STRESS_TEST.md item 8 ("Degraded-clock / no-NTP
    # scenario"). A time-windowed rule that can't verify the time is being asked to make
    # a decision it has no basis for, so it must deny rather than guess.
    if not clock_is_trusted:
        return False

    now = now or datetime.now(timezone.utc)
    start = datetime.strptime(condition["start"], "%H:%M:%S").time()
    end = datetime.strptime(condition["end"], "%H:%M:%S").time()
    current_time = now.time()

    if start <= end:
        return start <= current_time <= end
    # window wraps midnight, e.g. 22:00 -> 06:00
    return current_time >= start or current_time <= end


def _rule_conditions_satisfied(
    rule: Rule, arguments: dict[str, Any], *, clock_is_trusted: bool
) -> bool:
    for condition_type, condition_value in rule.conditions.items():
        if condition_type == "arg_prefix":
            if not _check_arg_prefix_condition(condition_value, arguments):
                return False
        elif condition_type == "time_window":
            if not _check_time_window_condition(condition_value, clock_is_trusted=clock_is_trusted):
                return False
        else:
            # Unreachable in practice -- _parse_rule already rejects unknown condition
            # types at load time -- but kept as an explicit fail-closed guard rather than
            # an assumption, in case this function is ever called with a Rule built by
            # some other path than load_policy().
            return False
    return True


def authorize(
    policy: Policy,
    *,
    role: str,
    tool: str,
    arguments: dict[str, Any] | None = None,
    clock_is_trusted: bool = True,
) -> AuthorizationResult:
    """The core decision function. Never raises for a normal "no matching rule" case --
    that resolves to DENY via policy.default_effect. Only raises if called with a
    structurally invalid Policy object (which load_policy() should have already
    prevented) or a role/tool of the wrong type -- callers should still wrap this in a
    try/except that treats ANY exception as DENY (see the FastMCP middleware in
    policy_engine/middleware.py), since defense-in-depth against an engine bug is exactly
    the fail-closed guarantee this whole project is about.
    """
    arguments = arguments or {}

    role_policy = policy.roles.get(role)
    if role_policy is None:
        return AuthorizationResult(
            decision=Decision.DENY,
            role=role,
            tool=tool,
            reason=f"role {role!r} is not defined in this policy",
            policy_hash=policy.policy_hash,
        )

    for i, rule in enumerate(role_policy.rules):
        if not rule.matches_tool(tool):
            continue
        if not _rule_conditions_satisfied(rule, arguments, clock_is_trusted=clock_is_trusted):
            continue

        decision = rule.effect
        if decision == Decision.ALLOW and rule.require_confirm:
            decision = Decision.CONFIRM_REQUIRED

        return AuthorizationResult(
            decision=decision,
            role=role,
            tool=tool,
            reason=rule.reason or f"matched rule #{i} for role {role!r}",
            matched_rule_index=i,
            policy_hash=policy.policy_hash,
        )

    # No rule matched -- default_effect is always DENY (enforced at load time).
    return AuthorizationResult(
        decision=policy.default_effect,
        role=role,
        tool=tool,
        reason="no matching rule; default_effect applies",
        policy_hash=policy.policy_hash,
    )
