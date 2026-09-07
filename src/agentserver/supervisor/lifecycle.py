"""Subagent lifecycle state machine. M2.

    spawned -> bound -> running -> { completed | killed | faulted }

`bound` is where the capability token is issued. Capabilities cannot be
attached to an already-running agent: no runtime privilege mutation.

Distinct from risk state (containment/state.py).

TODO(M2): transitions, legality checks
"""
