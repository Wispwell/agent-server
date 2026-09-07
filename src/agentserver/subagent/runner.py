"""Subagent process runner. M2.

v0 ships PROCESS isolation, not containers: subprocess with a scrubbed
environment, no credentials in reachable state, gateway as the only configured
route to tools.

This is the weakest link and the docs say so. It is honest containment against
an injected model that follows its instructions, and inadequate against one
that deliberately probes for escape. Container isolation under OrbStack is the
first post-deadline milestone.

TODO(M2): spawn with scrubbed env, keypair generation, teardown, kill
"""
