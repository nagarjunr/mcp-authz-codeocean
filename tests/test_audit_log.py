"""Tests for the hash-chained audit log (policy_engine/audit_log.py).

test_tampering_is_detected and test_reordering_is_detected directly implement SCOPE.md
evaluation scenario #4 ("Audit-log tamper detection ... verify the audit log detects a
deliberately corrupted/reordered entry").
"""

import json

import pytest

from policy_engine.audit_log import (
    GENESIS_HASH,
    AuditLog,
    AuditLogError,
    verify_chain,
)


@pytest.fixture()
def log_path(tmp_path):
    return tmp_path / "audit.jsonl"


class TestAppendAndVerify:
    def test_empty_log_verifies_as_valid(self, log_path):
        result = verify_chain(log_path)
        assert result.valid
        assert result.entry_count == 0
        assert result.final_hash == GENESIS_HASH

    def test_single_entry_chains_from_genesis(self, log_path):
        log = AuditLog.open(log_path)
        entry = log.append(
            agent_id="agent-01",
            role="predictive-maintenance-agent",
            tool="get_thing",
            decision="ALLOW",
            matched_rule_index=0,
            reason="matched rule #0",
            policy_hash="deadbeef" * 8,
        )
        assert entry.previous_hash == GENESIS_HASH
        assert entry.sequence == 0

        result = verify_chain(log_path)
        assert result.valid
        assert result.entry_count == 1
        assert result.final_hash == entry.entry_hash

    def test_multiple_entries_form_a_valid_chain(self, log_path):
        log = AuditLog.open(log_path)
        e0 = log.append(
            agent_id="a", role="r", tool="t1", decision="ALLOW",
            matched_rule_index=0, reason="x", policy_hash="h",
        )
        e1 = log.append(
            agent_id="a", role="r", tool="t2", decision="DENY",
            matched_rule_index=None, reason="default deny", policy_hash="h",
        )
        assert e1.previous_hash == e0.entry_hash
        assert e1.sequence == 1

        result = verify_chain(log_path)
        assert result.valid
        assert result.entry_count == 2

    def test_reopening_an_existing_log_continues_the_chain(self, log_path):
        log1 = AuditLog.open(log_path)
        e0 = log1.append(
            agent_id="a", role="r", tool="t1", decision="ALLOW",
            matched_rule_index=0, reason="x", policy_hash="h",
        )

        # Simulate a process restart: open a fresh AuditLog instance against the same file.
        log2 = AuditLog.open(log_path)
        e1 = log2.append(
            agent_id="a", role="r", tool="t2", decision="ALLOW",
            matched_rule_index=0, reason="x", policy_hash="h",
        )

        assert e1.sequence == 1  # continued from log1's state, not restarted at 0
        assert e1.previous_hash == e0.entry_hash

        result = verify_chain(log_path)
        assert result.valid
        assert result.entry_count == 2


class TestTamperDetection:
    """Directly implements SCOPE.md evaluation scenario #4."""

    def test_tampering_is_detected(self, log_path):
        """Modify a field in a previously-written entry (e.g. change a DENY to ALLOW,
        simulating an attacker trying to retroactively cover up a rejected privilege
        escalation attempt) and confirm verify_chain() catches it."""
        log = AuditLog.open(log_path)
        log.append(
            agent_id="a", role="r", tool="t1", decision="DENY",
            matched_rule_index=None, reason="denied", policy_hash="h",
        )
        log.append(
            agent_id="a", role="r", tool="t2", decision="ALLOW",
            matched_rule_index=0, reason="x", policy_hash="h",
        )

        lines = log_path.read_text().splitlines()
        first_entry = json.loads(lines[0])
        first_entry["decision"] = "ALLOW"  # tamper: attacker rewrites history
        lines[0] = json.dumps(first_entry, sort_keys=True)
        log_path.write_text("\n".join(lines) + "\n")

        result = verify_chain(log_path)
        assert not result.valid
        assert result.failure_sequence == 0
        assert "modified" in result.failure_reason

    def test_reordering_is_detected(self, log_path):
        """Swap the order of two entries -- even though both entries' own content is
        individually unmodified, the chain linkage (previous_hash) no longer matches,
        which verify_chain() must catch."""
        log = AuditLog.open(log_path)
        log.append(
            agent_id="a", role="r", tool="t1", decision="ALLOW",
            matched_rule_index=0, reason="first", policy_hash="h",
        )
        log.append(
            agent_id="a", role="r", tool="t2", decision="ALLOW",
            matched_rule_index=0, reason="second", policy_hash="h",
        )

        lines = log_path.read_text().splitlines()
        lines[0], lines[1] = lines[1], lines[0]  # swap order
        log_path.write_text("\n".join(lines) + "\n")

        result = verify_chain(log_path)
        assert not result.valid
        assert "chain link broken" in result.failure_reason

    def test_deletion_of_an_entry_is_detected(self, log_path):
        """Remove a middle entry entirely -- the surrounding entries' hash linkage must
        no longer connect, revealing the gap."""
        log = AuditLog.open(log_path)
        log.append(
            agent_id="a", role="r", tool="t1", decision="ALLOW",
            matched_rule_index=0, reason="first", policy_hash="h",
        )
        log.append(
            agent_id="a", role="r", tool="t2", decision="DENY",
            matched_rule_index=None, reason="second - the one we'll delete", policy_hash="h",
        )
        log.append(
            agent_id="a", role="r", tool="t3", decision="ALLOW",
            matched_rule_index=0, reason="third", policy_hash="h",
        )

        lines = log_path.read_text().splitlines()
        del lines[1]  # remove the middle entry
        log_path.write_text("\n".join(lines) + "\n")

        result = verify_chain(log_path)
        assert not result.valid
        assert "chain link broken" in result.failure_reason

    def test_opening_a_tampered_log_refuses_new_appends(self, log_path):
        """AuditLog.open() must itself refuse to open (and thus refuse to append to) a
        log whose existing chain is already broken -- appending on top of a known-bad
        chain would be meaningless and could mask the earlier tampering."""
        log = AuditLog.open(log_path)
        log.append(
            agent_id="a", role="r", tool="t1", decision="ALLOW",
            matched_rule_index=0, reason="x", policy_hash="h",
        )

        entry = json.loads(log_path.read_text().splitlines()[0])
        entry["decision"] = "DENY"
        log_path.write_text(json.dumps(entry, sort_keys=True) + "\n")

        with pytest.raises(AuditLogError, match="chain is invalid"):
            AuditLog.open(log_path)

    def test_corrupted_json_line_is_detected(self, log_path):
        log_path.write_text('{"not": "a valid entry", missing closing brace\n')
        result = verify_chain(log_path)
        assert not result.valid
        assert "not valid JSON" in result.failure_reason
