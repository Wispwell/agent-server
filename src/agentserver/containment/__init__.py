"""Containment server — the data plane. Milestone M1. Trusted.

Answers one question per tool call: may this action execute right now?
Distinct from the supervisor's control-plane question (may this goal become a
subagent with these capabilities?). Different state, different failure modes,
deliberately not merged — conflating them destroys the ability to explain a
denial. Both fail closed.
"""
