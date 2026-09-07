"""Per-agent risk state and PatternKey scoping. M1.

    PatternKey(a, c, r) = SHA-256(agent_id || capability || resource)

Anomaly counters are keyed by *context*, not by agent. Keying by agent alone
lets eleven harmless reads poison the score on an unrelated write — a real
vulnerability in ACP-RISK-2.0, fixed in 3.0, and cheap to build correctly from
the start.

Risk state is separate from lifecycle state (see supervisor/lifecycle.py).

    { denial_count, pattern_count[PatternKey], cooldown_until, last_decision }

TODO(M1): counters, windows, cooldown arithmetic
"""
