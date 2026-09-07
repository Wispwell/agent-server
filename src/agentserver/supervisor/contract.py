"""Governor output contract. M2.

Everything the governor emits is HOSTILE INPUT. Schema-validate, reject on any
deviation, log the rejection. Never string-match model output to decide
anything.

    {
      "reasoning": "<free text, logged, never parsed>",
      "actions": [
        {"op": "spawn", "role": "<enum>", "params": {...}, "budget": {...}},
        {"op": "kill",  "agent_id": "<known id>"},
        {"op": "wait"},
        {"op": "conclude", "summary": "<free text>"}
      ]
    }

Also normalises the return channel: subagent results become a fixed schema
(state, exit reason, denied-action count, bounded output), never raw stdout.
Raw output would let a subagent inject the planner, and let two subagents pass
messages through the governor and coordinate.

TODO(M2): schema, validate(), normalise_status()
"""
