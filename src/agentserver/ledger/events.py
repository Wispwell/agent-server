"""Ledger event types. M0.

Every decision is recorded — APPROVED, ESCALATED and DENIED alike, not only
successes. A ledger that records what was allowed tells you nothing about
whether the boundary works; recording refusals is what makes the Boundary
Activation Rate computable, and BAR is what distinguishes a containment layer
that is working from one that is dormant.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = ["TERMINAL_DECISIONS", "Decision", "EventType"]


class EventType(StrEnum):
    GENESIS = "genesis"

    # control plane — the supervisor
    GOVERNOR_OUTPUT = "governor_output"
    SCHEMA_REJECTED = "schema_rejected"
    SPAWN_ADMITTED = "spawn_admitted"
    SPAWN_REFUSED = "spawn_refused"
    BUDGET_EXHAUSTED = "budget_exhausted"
    LIFECYCLE = "lifecycle"

    # data plane — the admission engine
    AUTHORIZATION = "authorization"
    COOLDOWN_STARTED = "cooldown_started"
    ESCALATION_RAISED = "escalation_raised"
    ESCALATION_RESOLVED = "escalation_resolved"

    # tokens
    TOKEN_ISSUED = "token_issued"
    TOKEN_REVOKED = "token_revoked"
    EXECUTION_TOKEN_ISSUED = "execution_token_issued"
    EXECUTION_TOKEN_CONSUMED = "execution_token_consumed"

    # evaluation
    COUNTERFACTUAL_PROBE = "counterfactual_probe"


class Decision(StrEnum):
    APPROVED = "approved"
    ESCALATED = "escalated"
    DENIED = "denied"


#: Decisions that count as the boundary having activated (see E4 / BAR).
TERMINAL_DECISIONS = frozenset({Decision.ESCALATED, Decision.DENIED})
