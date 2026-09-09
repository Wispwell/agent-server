"""The governor. M3. UNTRUSTED — despite living here.

Assembly, not a subsystem. The governor is a context window (`context/`) plus a
model client (`providers/`) plus the output contract (`contract.py`), wired
together. It owns no mechanism of its own, which is why it is a single module
rather than a package: everything it needs already exists for subagents too.

**It sits in `supervisor/` but is not trusted.** The rest of this package is
the deterministic control plane; this file is the one part of it driven by a
language model, and it is untrusted for the ordinary reason — it reads task
text, subagent results and tool outcomes, any of which can carry an injection.
Package membership is not a trust domain. Nothing here may be relied on by the
code around it.

What that means concretely:

  * **No callable tools.** The governor does not act; it emits a structured
    turn and the supervisor decides what that becomes.
  * **Everything it emits is hostile input**, validated by `contract.py`
    before any part of it is honoured — unknown keys reject the whole turn,
    and a stale observation version rejects the batch.
  * **Everything it receives is injected by the supervisor**, scoped to the
    governor's own ceiling. It never fetches, and never sees the ledger, the
    bindings, or another agent's escalations.

The claim this file is here to keep true is bounded authority: whatever the
model decides to want, its effects are confined to what the supervisor's rules
admit.

TODO(M3): assemble the window from an observation, call the provider, return
          the raw turn for contract validation, count consecutive rejections
"""
