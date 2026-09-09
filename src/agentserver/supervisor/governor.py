"""The governor. M3. UNTRUSTED — despite living here.

Assembly, not a subsystem. A context window plus a model client plus the output
contract, wired together. It owns no mechanism of its own, which is why it is
one module and not a package.

**It sits in `supervisor/` but is not trusted.** The rest of this package is
the deterministic control plane; this is the one part driven by a language
model, and it is untrusted for the ordinary reason — it reads task text,
subagent results and tool outcomes, any of which can carry an injection.
Package membership is not a trust domain.

  * **No callable tools.** It emits a structured turn; the supervisor decides
    what that becomes.
  * **Everything it emits is hostile input**, validated by `contract.py`.
  * **Everything it receives is injected**, scoped to its own ceiling, and
    fenced as untrusted in the window.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..context.loader import Kind, Loader, LoaderError, Prompt
from ..context.window import Layer, Window
from ..providers.openrouter import Completion, OpenRouterClient

__all__ = ["TURN_SCHEMA", "Governor"]

#: Requested of the provider when it supports structured output. This is a
#: *hint*, not the enforcement: support varies by model and by the provider
#: OpenRouter routes to, so `contract.validate` is what actually decides
#: whether a turn is honoured. Duplicating the rules here would invite them to
#: drift apart, so this stays deliberately loose and the contract stays strict.
TURN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["observed", "reasoning", "actions"],
    "properties": {
        "observed": {"type": "string"},
        "reasoning": {"type": "string"},
        "actions": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": True,
                "required": ["op"],
                "properties": {
                    "op": {"type": "string",
                           "enum": ["spawn", "kill", "wait", "conclude"]},
                    "role": {"type": "string"},
                    "task": {"type": "string"},
                    "params": {"type": "object", "additionalProperties": True},
                    "agent_id": {"type": "string"},
                    "summary": {"type": "string"},
                },
            },
        },
    },
}


class Governor:
    def __init__(
        self,
        provider: OpenRouterClient,
        loader: Loader,
        *,
        name: str = "governor",
        model: str | None = None,
    ):
        self.provider = provider
        self.loader = loader
        self.name = name
        self.model = model

    def build_window(self, observation: Mapping[str, Any]) -> Window:
        window = Window()

        for kind in (Kind.SYSTEM, Kind.RULES):
            try:
                window.instructions(self.loader.load(kind, self.name))
            except LoaderError:
                pass    # a missing ruleset is a thinner prompt, not a failure

        # Role descriptions are trusted: they come from operator-signed
        # artifacts verified against the trust anchor on load, which is the
        # same provenance a file in the prompt directory has. Wrapping them in
        # a Prompt states that provenance rather than bypassing the check.
        window.instructions(Prompt(Kind.SKILL, "roles", _render_roles(observation)))

        for label in ("environment", "roster", "outcomes", "budgets"):
            if label in observation:
                window.untrusted(Layer.SLIDING, label, observation[label])
        window.untrusted(Layer.SLIDING, "version", observation.get("version", ""))
        window.untrusted(Layer.QUERY, "task", observation.get("task", ""))
        return window

    def turn(self, observation: Mapping[str, Any]) -> tuple[dict[str, Any] | None, Completion]:
        """Ask for one turn. Returns (raw, completion); `raw` is unvalidated.

        A malformed answer returns `None` rather than raising, and is never
        repaired into shape — the text that failed to parse is the text an
        attacker influenced.
        """
        window = self.build_window(observation)
        completion = self.provider.complete(
            window.render(), schema=TURN_SCHEMA, model=self.model
        )
        return completion.parsed, completion


def _render_roles(observation: Mapping[str, Any]) -> str:
    lines = ["## Roles you may spawn", ""]
    for role in observation.get("roles") or []:
        lines.append(f"### {role['role']}")
        if role.get("description"):
            lines.append(role["description"])
        lines.append(f"- capabilities: {', '.join(role.get('capabilities', []))}")
        lines.append(f"- scope: {role.get('resource', '')}")
        params = role.get("params")
        if params:
            lines.append(f"- parameters: {', '.join(params)}")
        lines.append("")
    if len(lines) == 2:
        lines.append("(none installed — nothing can be spawned)")
    return "\n".join(lines)
