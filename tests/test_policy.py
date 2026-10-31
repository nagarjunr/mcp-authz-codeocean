"""Tests for the core policy decision engine (policy_engine/policy.py).

These cover the load-time validation (fail-closed on malformed policy), the three
condition types, and the default-deny behavior -- the foundational correctness
properties everything else in this project's evaluation builds on.
"""

from pathlib import Path

import pytest

from policy_engine.policy import (
    Decision,
    PolicyLoadError,
    authorize,
    load_policy,
)

EXAMPLE_POLICY = Path(__file__).parent.parent / "examples" / "policy.example.yaml"


@pytest.fixture()
def policy():
    return load_policy(EXAMPLE_POLICY)


class TestPolicyLoading:
    def test_loads_valid_policy(self, policy):
        assert policy.schema_version == 1
        assert "predictive-maintenance-agent" in policy.roles
        assert "commissioning-agent" in policy.roles
        assert "emergency-response-agent" in policy.roles
        assert policy.default_effect == Decision.DENY

    def test_policy_hash_is_computed(self, policy):
        assert len(policy.policy_hash) == 64  # sha256 hex digest length
        # Hash must be deterministic for the same file content.
        policy2 = load_policy(EXAMPLE_POLICY)
        assert policy.policy_hash == policy2.policy_hash

    def test_rejects_missing_file(self):
        with pytest.raises(PolicyLoadError):
            load_policy("/nonexistent/path/policy.yaml")

    def test_rejects_invalid_yaml(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("schema_version: 1\nroles: [this is not: valid: yaml: at: all")
        with pytest.raises(PolicyLoadError):
            load_policy(bad)

    def test_rejects_wrong_schema_version(self, tmp_path):
        p = tmp_path / "p.yaml"
        p.write_text("schema_version: 2\ndefault_effect: DENY\nroles:\n  a:\n    rules: []\n")
        with pytest.raises(PolicyLoadError, match="schema_version"):
            load_policy(p)

    def test_rejects_default_effect_allow(self, tmp_path):
        """This is the single most important negative test in this suite: a policy
        document that tries to set default_effect to ALLOW must be rejected outright at
        load time, since that would silently defeat the fail-closed guarantee the whole
        design is built on."""
        p = tmp_path / "p.yaml"
        p.write_text(
            "schema_version: 1\n"
            "default_effect: ALLOW\n"
            "roles:\n"
            "  a:\n"
            "    rules:\n"
            "      - tools: ['*']\n"
            "        effect: ALLOW\n"
        )
        with pytest.raises(PolicyLoadError, match="default_effect"):
            load_policy(p)

    def test_rejects_empty_roles(self, tmp_path):
        p = tmp_path / "p.yaml"
        p.write_text("schema_version: 1\ndefault_effect: DENY\nroles: {}\n")
        with pytest.raises(PolicyLoadError, match="roles"):
            load_policy(p)

    def test_rejects_unsupported_condition_type(self, tmp_path):
        """Per module docstring: an unrecognized condition key must be a hard load-time
        error, not silently ignored (silent ignoring could grant broader access than
        intended)."""
        p = tmp_path / "p.yaml"
        p.write_text(
            "schema_version: 1\n"
            "default_effect: DENY\n"
            "roles:\n"
            "  a:\n"
            "    rules:\n"
            "      - tools: ['get_thing']\n"
            "        effect: ALLOW\n"
            "        conditions:\n"
            "          not_a_real_condition_type: {foo: bar}\n"
        )
        with pytest.raises(PolicyLoadError, match="unsupported condition"):
            load_policy(p)


class TestAuthorizeReadOnlyRole:
    def test_read_only_agent_can_read(self, policy):
        result = authorize(policy, role="predictive-maintenance-agent", tool="get_thing")
        assert result.decision == Decision.ALLOW

    def test_read_only_agent_cannot_delete(self, policy):
        result = authorize(policy, role="predictive-maintenance-agent", tool="delete_thing")
        assert result.decision == Decision.DENY

    def test_read_only_agent_cannot_write(self, policy):
        result = authorize(
            policy, role="predictive-maintenance-agent", tool="update_thing_shadow"
        )
        assert result.decision == Decision.DENY

    def test_unknown_tool_defaults_to_deny(self, policy):
        """No rule mentions this tool at all -- must fall through to default_effect,
        not silently ALLOW."""
        result = authorize(
            policy, role="predictive-maintenance-agent", tool="some_tool_not_in_policy"
        )
        assert result.decision == Decision.DENY
        assert "default_effect" in result.reason


class TestAuthorizeScopedWriteRole:
    def test_commissioning_agent_can_create_in_scope(self, policy):
        result = authorize(
            policy,
            role="commissioning-agent",
            tool="put_thing",
            arguments={"thing_id": "staging:press-07"},
        )
        assert result.decision == Decision.ALLOW

    def test_commissioning_agent_cannot_create_out_of_scope(self, policy):
        """This is the arg_prefix scoping condition -- a commissioning agent may only
        create things whose ID starts with the 'staging:' namespace (Ditto thing IDs
        are namespaced as 'namespace:name'). This directly tests the
        device-ID/namespace scoping design described in SCOPE.md."""
        result = authorize(
            policy,
            role="commissioning-agent",
            tool="put_thing",
            arguments={"thing_id": "production:press-07"},
        )
        assert result.decision == Decision.DENY

    def test_commissioning_agent_cannot_delete(self, policy):
        result = authorize(
            policy,
            role="commissioning-agent",
            tool="delete_thing",
            arguments={"thing_id": "staging:press-07"},
        )
        assert result.decision == Decision.DENY


class TestUnknownRole:
    def test_unknown_role_is_denied(self, policy):
        """A role not present in the policy at all must be denied, not treated as
        having some implicit default permission set."""
        result = authorize(policy, role="totally-made-up-role", tool="get_thing")
        assert result.decision == Decision.DENY
        assert "not defined" in result.reason


class TestTimeWindowCondition:
    def test_emergency_agent_denied_when_clock_untrusted(self, policy):
        """Per STRESS_TEST.md item 8 (degraded-clock scenario): if the caller can't
        vouch for clock trust, a time-windowed rule must deny rather than guess --
        this is tested directly here, independent of what the wall-clock time actually
        is when the test runs."""
        result = authorize(
            policy,
            role="emergency-response-agent",
            tool="update_thing_shadow",
            arguments={},
            clock_is_trusted=False,
        )
        assert result.decision == Decision.DENY

    def test_emergency_agent_requires_confirm_when_allowed(self, policy, monkeypatch):
        """When the time window matches and clock is trusted, the rule's
        require_confirm=true should produce CONFIRM_REQUIRED, not a bare ALLOW."""
        import datetime as dt

        from policy_engine import policy as policy_module

        fixed_noon = dt.datetime(2026, 8, 29, 12, 0, 0, tzinfo=dt.timezone.utc)

        original = policy_module._check_time_window_condition

        def patched(condition, *, clock_is_trusted, now=None):
            return original(condition, clock_is_trusted=clock_is_trusted, now=fixed_noon)

        monkeypatch.setattr(policy_module, "_check_time_window_condition", patched)

        result = authorize(
            policy,
            role="emergency-response-agent",
            tool="update_thing_shadow",
            arguments={},
            clock_is_trusted=True,
        )
        assert result.decision == Decision.CONFIRM_REQUIRED

    def test_emergency_agent_denied_outside_window(self, policy, monkeypatch):
        import datetime as dt

        from policy_engine import policy as policy_module

        fixed_3am = dt.datetime(2026, 8, 29, 3, 0, 0, tzinfo=dt.timezone.utc)

        original = policy_module._check_time_window_condition

        def patched(condition, *, clock_is_trusted, now=None):
            return original(condition, clock_is_trusted=clock_is_trusted, now=fixed_3am)

        monkeypatch.setattr(policy_module, "_check_time_window_condition", patched)

        result = authorize(
            policy,
            role="emergency-response-agent",
            tool="update_thing_shadow",
            arguments={},
            clock_is_trusted=True,
        )
        assert result.decision == Decision.DENY
