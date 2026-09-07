"""Tests for the M0 hash-chained audit ledger."""

from __future__ import annotations

import json

import pytest

from agentserver.ledger.chain import GENESIS_HASH, Ledger, LedgerCorruption
from agentserver.ledger.events import TERMINAL_DECISIONS, Decision, EventType


def _seed(path, n=5):
    ledger = Ledger(path)
    for i in range(n):
        ledger.append(EventType.AUTHORIZATION, {"i": i, "decision": Decision.APPROVED})
    return ledger


def test_empty_ledger_starts_at_genesis(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    assert len(ledger) == 0
    assert ledger.head == GENESIS_HASH
    assert ledger.verify() == 0


def test_append_returns_entry_and_links_to_previous(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    first = ledger.append(EventType.GENESIS, {"note": "start"})
    second = ledger.append(EventType.TOKEN_ISSUED, {"sub": "abc"})
    assert first["seq"] == 0 and second["seq"] == 1
    assert first["prev"] == GENESIS_HASH
    assert second["prev"] == first["hash"]
    assert ledger.head == second["hash"]
    assert len(ledger) == 2


def test_written_file_is_owner_only(tmp_path):
    path = tmp_path / "l.jsonl"
    Ledger(path).append(EventType.GENESIS)
    assert path.stat().st_mode & 0o777 == 0o600


def test_round_trips_through_disk_and_verifies(tmp_path):
    path = tmp_path / "l.jsonl"
    _seed(path, 5)
    reopened = Ledger(path)
    assert len(reopened) == 5
    assert reopened.verify() == 5
    assert [e["data"]["i"] for e in reopened.read()] == [0, 1, 2, 3, 4]


def test_reopening_resumes_sequence_and_head(tmp_path):
    path = tmp_path / "l.jsonl"
    original = _seed(path, 3)
    reopened = Ledger(path)
    assert reopened.head == original.head
    entry = reopened.append(EventType.LIFECYCLE, {"state": "killed"})
    assert entry["seq"] == 3
    assert entry["prev"] == original.head
    assert reopened.verify() == 4


def test_altering_an_entry_is_detected_at_that_sequence(tmp_path):
    path = tmp_path / "l.jsonl"
    _seed(path, 5)
    lines = path.read_text().splitlines()
    entry = json.loads(lines[2])
    entry["data"]["decision"] = Decision.DENIED.value  # rewrite history
    lines[2] = json.dumps(entry, ensure_ascii=False, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")

    with pytest.raises(LedgerCorruption) as exc:
        Ledger(path).verify()
    assert exc.value.seq == 2


def test_deleting_an_interior_entry_is_detected(tmp_path):
    path = tmp_path / "l.jsonl"
    _seed(path, 5)
    lines = path.read_text().splitlines()
    del lines[2]
    path.write_text("\n".join(lines) + "\n")

    with pytest.raises(LedgerCorruption) as exc:
        Ledger(path).verify()
    assert exc.value.seq == 3  # the entry that should have been seq 2


def test_reordering_entries_is_detected(tmp_path):
    path = tmp_path / "l.jsonl"
    _seed(path, 5)
    lines = path.read_text().splitlines()
    lines[1], lines[3] = lines[3], lines[1]
    path.write_text("\n".join(lines) + "\n")

    with pytest.raises(LedgerCorruption):
        Ledger(path).verify()


def test_a_live_ledger_notices_its_tail_being_cut(tmp_path):
    path = tmp_path / "l.jsonl"
    ledger = _seed(path, 5)
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:-2]) + "\n")

    with pytest.raises(LedgerCorruption, match="head hash"):
        ledger.verify()  # this object remembers the head it wrote


def test_tail_truncation_is_NOT_detectable_after_a_restart(tmp_path):
    """A documented limit, asserted so it cannot regress silently.

    A truncated chain is internally consistent, and a fresh process has no
    anchor to compare against. Detecting this needs a signed checkpoint or the
    head published outside the file — neither is in v0.
    """
    path = tmp_path / "l.jsonl"
    _seed(path, 5)
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:-2]) + "\n")

    reopened = Ledger(path)
    assert reopened.verify() == 3  # verifies happily; two denials could vanish


def test_decisions_are_recorded_whatever_they_were(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    for decision in Decision:
        ledger.append(EventType.AUTHORIZATION, {"decision": decision})
    recorded = [e["data"]["decision"] for e in ledger.read()]
    assert recorded == ["approved", "escalated", "denied"]
    activated = [d for d in recorded if d in TERMINAL_DECISIONS]
    assert len(activated) == 2, "BAR counts escalations and denials, not approvals"


def test_event_and_decision_values_are_plain_strings(tmp_path):
    """They land in JSON, so they must serialise without special handling."""
    ledger = Ledger(tmp_path / "l.jsonl")
    ledger.append(EventType.SPAWN_REFUSED, {"decision": Decision.DENIED})
    raw = json.loads(path_text := (tmp_path / "l.jsonl").read_text().strip())
    assert raw["type"] == "spawn_refused"
    assert raw["data"]["decision"] == "denied"
    assert path_text.count("\n") == 0
