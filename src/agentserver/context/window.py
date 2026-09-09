"""Layered context window. M3.

    1. System instructions      ┐
    2. Rulesets                 │  operator-authored — TRUSTED
    3. Skills and available tools ┘
    ─────────────────────────────────────────────────────────────
    4. Sliding window           ┐  history, memory, retrieval, tool
    5. Query                    ┘  results — TAINTED

**The line between layer 3 and layer 4 is the trust boundary**, and that is the
point of the layering. Everything above it is authored by the operator and
loaded from a location the agent side cannot write. Everything below it is
attacker-influenceable: a file's contents, a tool result, another agent's
output, the task text itself.

The rule this structure exists to enforce:

    Layers 1-3 are never constructed from layer 4-5 content.

Enforcing it at assembly means it holds for the governor and for every subagent
without either having to remember. The alternative — each caller carefully not
interpolating untrusted text into its own instructions — is the failure mode
that indirect prompt injection exploits, and it fails silently.

Two further properties, both from the design doc:

  * **Assembled fresh, never accumulated.** The window is a function of current
    state rather than an appended transcript, so there is no growing history
    and no truncation decision to get wrong. Anything that must persist across
    turns is carried explicitly, not by being left in the buffer.
  * **Every tainted layer is length-capped and delimited.** Reducing the
    channel, not eliminating it: a filename is still attacker-chosen text. This
    degrades usefulness rather than safety, because an agent's authority never
    depends on what it believes.

TODO(M3): Layer, Window, assemble(), per-layer budgets, rendering
"""
