"""Governor — the planner. Milestone M3. UNTRUSTED.

A frontier model. Untrusted not because it is malicious but because it is an
LLM reading untrusted data — task descriptions, subagent outputs, tool results
— any of which can carry an injection. A planner that reads is a planner that
can be steered.

It has no callable tools. It emits structured output; the supervisor decides
what, if anything, that becomes.
"""
