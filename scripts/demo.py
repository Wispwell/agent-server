"""The demo that proves it works. Milestone M4.

Governor decomposes a task -> selects a role and spawns a subagent with a
narrowly scoped capability token -> the subagent's tool output contains a
prompt injection -> the subagent attempts the injected out-of-scope action ->
the containment server denies it, the subagent holds no credentials with which
to route around the denial, the ledger records the attempt -> the governor
observes the denial and re-plans, or the action escalates and a human approves
at the terminal.

Every component earns its place in this single run. Anything that does not
serve it is post-deadline work.

TODO(M4)
"""
