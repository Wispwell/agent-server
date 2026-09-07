"""agent-server — a contained multi-agent system.

Trust model (see docs/design.md):
    TRUSTED    containment, supervisor, ledger, the human at the escalation queue
    UNTRUSTED  governor, subagents — anything containing a language model

The claim is bounded authority, not trust: the governor's effects on the world
are confined to what the supervisor's rules admit, regardless of what the model
decides to want.
"""

__version__ = "0.0.0"
