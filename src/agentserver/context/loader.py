"""Prompt and skill loading. M3. Trusted.

Loads the operator-authored material that becomes layers 1-3 of a context
window: system instructions, rulesets, and skill definitions.

**Everything here is trusted input and must be loaded from somewhere the agent
side cannot write.** A skill file is, in effect, part of an agent's system
prompt. If a subagent could write into the skill directory — or if skills were
read from the workspace an agent operates on — it would be authoring its own
instructions, and every containment property downstream would be reasoning
about a prompt the agent chose. The load path is configuration, never a
resource any capability grants access to.

Rulesets are where operator-configured auto-approval presets will live. Those
carry a specific hazard recorded in the design doc: approve enough
automatically and the containment boundary stops activating, so preset
approvals are counted separately from ordinary ones and reported apart in the
Boundary Activation Rate.

TODO(M3): load system instructions, rulesets, skills; validate; refuse paths
          reachable by any role's capability set
"""
