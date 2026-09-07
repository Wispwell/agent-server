"""Human escalation queue. M1.

The governor cannot resolve its own escalations. If ESCALATE routed back to the
planner, escalation would be decorative — an untrusted component auditing
itself. Escalations go to a human. In v0 that is a CLI prompt.

TODO(M1): enqueue, await_decision, CLI presenter
"""
