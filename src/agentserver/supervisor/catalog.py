"""Role catalog. M2.

A fixed set of subagent roles, each with a capability set frozen at config
time. The governor SELECTS a role and supplies parameters; it can never DEFINE
a capability set. This is the largest single reduction in attack surface — it
collapses the governor's output space from "arbitrary capability request" to a
small enum.

Open question: granularity. Too coarse and the ceiling means little; too fine
and the governor cannot plan. Start with three roles and let friction teach it.

TODO(M2): load config/roles.yaml, validate, resolve role -> capability set
"""
