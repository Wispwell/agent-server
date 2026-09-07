"""Tests for the counterfactual probe."""

from __future__ import annotations

from agentserver.containment.admission import Outcome
from evals.counterfactual import probe

from .helpers import NOW, denial_count, request


def test_the_probe_shows_denial_is_still_reachable(env):
    report = probe(env["engine"], request(env), now=NOW)
    assert report.baseline.outcome is Outcome.APPROVED
    assert report.can_deny, "no mutation produced DENIED — enforcement would be vacuous"
    assert report.bar > 0


def test_every_default_mutation_activates_the_boundary(env):
    report = probe(env["engine"], request(env), now=NOW)
    for result in report.applicable:
        assert result.activated, f"{result.name} did not activate: {result.outcome}"
    assert report.bar == 1.0


def test_probing_writes_nothing(env):
    """A probe that moved the counters would trip the cooldown it measures."""
    store, ledger = env["store"], env["ledger"]
    before = (
        len(ledger),
        store.one("SELECT COUNT(*) AS n FROM pattern_events", ())["n"],
        store.one("SELECT COUNT(*) AS n FROM escalations", ())["n"],
        denial_count(env)["denial_count"],
    )
    for _ in range(3):
        probe(env["engine"], request(env), now=NOW)
    after = (
        len(ledger),
        store.one("SELECT COUNT(*) AS n FROM pattern_events", ())["n"],
        store.one("SELECT COUNT(*) AS n FROM escalations", ())["n"],
        denial_count(env)["denial_count"],
    )
    assert before == after
    assert denial_count(env)["cooldown_until"] is None


def test_the_summary_names_the_failure_mode_when_nothing_denies(env):
    report = probe(env["engine"], request(env), now=NOW, mutations={})
    assert report.bar == 0.0
    assert "enforcement is vacuous" in report.summary()


def test_the_summary_is_readable(env):
    text = probe(env["engine"], request(env), now=NOW).summary()
    assert "counterfactual BAR" in text
    assert "unbound_tool" in text and "path_traversal" in text
