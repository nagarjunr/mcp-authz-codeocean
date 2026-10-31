"""
audit_log.py -- tamper-evident local audit log for authorization decisions.

Per SCOPE.md's design: every authorization decision made by the policy engine is
appended to a local, hash-chained log. Each entry's hash covers its own content AND the
previous entry's hash, so any modification, deletion, or reordering of a past entry
breaks the chain from that point forward -- detectable by recomputing hashes, without
needing any external service to check against.

NOTE: this module hash-CHAINS a sequence of log entries (a Merkle-style linked list, one link
per decision), to detect whether the LOG ITSELF has been tampered with or had entries
removed/reordered after the fact (chain-of-custody on access-control events). It is not a
content-integrity check on any retrieved document.

Design invariants:
  - Append-only: there is no update or delete operation exposed by this module's public
    API. The only way to remove old entries is explicit checkpointing/rotation (see
    checkpoint_and_rotate), which preserves continuity via a signed chain-head anchor.
  - Detection, not prevention: this module cannot stop someone with filesystem write
    access from corrupting the log file. It guarantees that IF they do, recomputing the
    chain will reveal exactly where the tampering occurred. See SCOPE.md's explicit
    framing of this as an operational limitation, not a silently-assumed guarantee.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# The hash of the very first entry's "previous_hash" field -- there is no real previous
# entry for the first one, so we use a fixed, documented genesis value rather than an
# empty string or null, so verification code has one consistent case to handle.
GENESIS_HASH = "0" * 64


class AuditLogError(Exception):
    """Raised for any audit log operation failure. Per this project's fail-closed
    philosophy, a caller unable to append to or verify the audit log should treat that
    as an operational fault to surface loudly (e.g. deny the tool call that triggered
    it, or halt), not silently continue without logging."""


@dataclass
class AuditEntry:
    sequence: int
    timestamp: str  # ISO 8601 UTC
    agent_id: str
    role: str
    tool: str
    arguments_summary: dict[str, Any]  # caller-provided; see note in append_entry
    decision: str  # ALLOW / DENY / CONFIRM_REQUIRED, stored as plain str (not the Decision
                    # enum type) so this module has no import dependency on policy_engine
    matched_rule_index: int | None
    reason: str
    policy_hash: str  # the policy document's hash at decision time -- lets a reviewer
                       # correlate "which policy version produced this decision"
    previous_hash: str
    entry_hash: str = ""  # computed by _compute_entry_hash, filled in after construction

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _canonical_entry_bytes(entry_without_hash: dict[str, Any]) -> bytes:
    """Serialize an entry's fields (excluding entry_hash itself) to a canonical byte
    form for hashing. Uses sort_keys=True and fixed separators so the same logical
    content always produces identical bytes regardless of dict insertion order --
    critical for hash verification to be reproducible across a fresh Python process
    reading the log back from disk."""
    return json.dumps(entry_without_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _compute_entry_hash(entry: AuditEntry) -> str:
    entry_dict = entry.to_dict()
    entry_dict.pop("entry_hash", None)
    return hashlib.sha256(_canonical_entry_bytes(entry_dict)).hexdigest()


@dataclass
class AuditLog:
    """An append-only, hash-chained audit log backed by a local JSONL file (one JSON
    object per line -- chosen over a single JSON array so that appending a new entry
    never requires rewriting the whole file, which matters on constrained edge storage
    and also means a crash mid-write can only ever corrupt the last, incomplete line,
    not the entire log)."""

    log_path: Path
    _last_hash: str = field(default=GENESIS_HASH, repr=False)
    _next_sequence: int = field(default=0, repr=False)

    @classmethod
    def open(cls, log_path: str | Path) -> "AuditLog":
        """Open (creating if necessary) an audit log file, replaying existing entries to
        establish the current chain tip and next sequence number. Raises AuditLogError if
        the existing file's chain does not verify -- an audit log that's already broken
        must not silently accept new entries as if nothing were wrong.
        """
        log_path = Path(log_path)
        log = cls(log_path=log_path)

        if not log_path.exists():
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.touch()
            return log

        verification = verify_chain(log_path)
        if not verification.valid:
            raise AuditLogError(
                f"cannot open audit log {log_path}: existing chain is invalid "
                f"({verification.failure_reason}) -- refusing to append to a "
                "compromised log"
            )

        if verification.entry_count > 0:
            log._last_hash = verification.final_hash
            log._next_sequence = verification.entry_count

        return log

    def append(
        self,
        *,
        agent_id: str,
        role: str,
        tool: str,
        decision: str,
        matched_rule_index: int | None,
        reason: str,
        policy_hash: str,
        arguments_summary: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """Append a new authorization-decision entry to the chain. This is the only
        mutation operation this class exposes -- there is deliberately no update/delete.

        `arguments_summary` should be a redacted/summarized view of the tool call's
        arguments (e.g. just the fields relevant to conditions that were evaluated),
        not necessarily the full raw arguments -- avoiding accidentally logging secrets
        or excessive PII into an append-only file is a caller-side responsibility this
        module does not attempt to enforce automatically.
        """
        entry = AuditEntry(
            sequence=self._next_sequence,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=agent_id,
            role=role,
            tool=tool,
            arguments_summary=arguments_summary or {},
            decision=decision,
            matched_rule_index=matched_rule_index,
            reason=reason,
            policy_hash=policy_hash,
            previous_hash=self._last_hash,
        )
        entry.entry_hash = _compute_entry_hash(entry)

        try:
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry.to_dict(), sort_keys=True) + "\n")
        except OSError as e:
            raise AuditLogError(f"failed to append to audit log {self.log_path}: {e}") from e

        self._last_hash = entry.entry_hash
        self._next_sequence += 1
        return entry


@dataclass
class ChainVerificationResult:
    valid: bool
    entry_count: int
    final_hash: str
    failure_reason: str | None = None
    failure_sequence: int | None = None


def verify_chain(log_path: str | Path) -> ChainVerificationResult:
    """Read an audit log file from disk and verify its hash chain from the genesis hash
    to the last entry. Returns a ChainVerificationResult describing exactly where
    verification failed, if it did -- this is what a technician or an evaluation script
    calls to detect tampering (see tests/test_audit_log.py's tamper-detection tests,
    which directly implement SCOPE.md evaluation scenario #4 and the audit-log half of
    scenario #3/policy-tampering).
    """
    log_path = Path(log_path)
    if not log_path.exists():
        return ChainVerificationResult(valid=True, entry_count=0, final_hash=GENESIS_HASH)

    expected_previous_hash = GENESIS_HASH
    entry_count = 0

    with log_path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f):
            line = line.rstrip("\n")
            if not line:
                continue

            try:
                entry_dict = json.loads(line)
            except json.JSONDecodeError:
                return ChainVerificationResult(
                    valid=False,
                    entry_count=entry_count,
                    final_hash=expected_previous_hash,
                    failure_reason=f"line {line_number} is not valid JSON",
                    failure_sequence=entry_count,
                )

            claimed_hash = entry_dict.get("entry_hash", "")
            recomputed_hash = hashlib.sha256(
                _canonical_entry_bytes({k: v for k, v in entry_dict.items() if k != "entry_hash"})
            ).hexdigest()

            if entry_dict.get("previous_hash") != expected_previous_hash:
                return ChainVerificationResult(
                    valid=False,
                    entry_count=entry_count,
                    final_hash=expected_previous_hash,
                    failure_reason=(
                        f"entry at sequence {entry_dict.get('sequence')} has "
                        f"previous_hash={entry_dict.get('previous_hash')!r}, expected "
                        f"{expected_previous_hash!r} -- chain link broken (entry "
                        "reordered, deleted, or inserted)"
                    ),
                    failure_sequence=entry_dict.get("sequence"),
                )

            if claimed_hash != recomputed_hash:
                return ChainVerificationResult(
                    valid=False,
                    entry_count=entry_count,
                    final_hash=expected_previous_hash,
                    failure_reason=(
                        f"entry at sequence {entry_dict.get('sequence')} has an "
                        f"entry_hash that does not match its own content -- this entry's "
                        "fields were modified after being written"
                    ),
                    failure_sequence=entry_dict.get("sequence"),
                )

            expected_previous_hash = claimed_hash
            entry_count += 1

    return ChainVerificationResult(valid=True, entry_count=entry_count, final_hash=expected_previous_hash)
