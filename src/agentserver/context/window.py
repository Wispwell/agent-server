"""Layered context window. M3.

    1. System instructions        ┐
    2. Rulesets                   │  operator-authored — TRUSTED
    3. Skills and available tools ┘
    ──────────────────────────────────────────────────────────────
    4. Sliding window             ┐  observations, history, tool results,
    5. Query                      ┘  another agent's output — TAINTED

**The line between layer 3 and layer 4 is the trust boundary**, and the point
of the layering is to make one rule enforceable in one place:

    Layers 1-3 are never constructed from layer 4-5 content.

That is enforced by type rather than by discipline. `instructions()` accepts
only a `Prompt` — the object the loader returns after reading from a directory
no agent can write — and refuses a bare string. `untrusted()` accepts strings
and refuses to write to a trusted layer. Untrusted text therefore cannot reach
the instruction layers by being passed to the wrong argument, which is the
mistake the alternative design invites.

Two further properties:

  * **Assembled fresh, never accumulated.** A window is a function of current
    state rather than an appended transcript, so there is no growing history
    and no truncation decision to get wrong. Anything that must persist is
    carried explicitly.
  * **Every untrusted block is capped and delimited.** This reduces the channel
    rather than closing it — a filename is still attacker-chosen text — and it
    degrades usefulness rather than safety, because an agent's authority never
    depends on what it believes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Self

from .loader import Prompt

__all__ = ["DEFAULT_BLOCK_CAP", "Layer", "Window", "WindowError"]

DEFAULT_BLOCK_CAP = 4000


class WindowError(Exception):
    reason = "window_error"


class Layer(IntEnum):
    SYSTEM = 1
    RULES = 2
    SKILLS = 3
    SLIDING = 4
    QUERY = 5


TRUSTED = frozenset({Layer.SYSTEM, Layer.RULES, Layer.SKILLS})


@dataclass
class _Block:
    label: str
    text: str
    truncated: bool = False


@dataclass
class Window:
    block_cap: int = DEFAULT_BLOCK_CAP
    _layers: dict[Layer, list[_Block]] = field(default_factory=dict)

    # -- trusted ----------------------------------------------------------

    def instructions(self, prompt: Prompt) -> Self:
        """Add operator-authored text to its layer.

        Takes a `Prompt`, not a string, deliberately: the type is what carries
        the provenance. There is no overload that accepts text here.
        """
        if not isinstance(prompt, Prompt):
            raise WindowError(
                f"instructions() takes a Prompt from the loader, not "
                f"{type(prompt).__name__} — trusted layers are never built from "
                f"untrusted text"
            )
        layer = {"system": Layer.SYSTEM, "rules": Layer.RULES,
                 "skills": Layer.SKILLS}[str(prompt.kind)]
        self._layers.setdefault(layer, []).append(_Block(prompt.name, prompt.text))
        return self

    # -- untrusted --------------------------------------------------------

    def untrusted(self, layer: Layer, label: str, content: Any) -> Self:
        """Add attacker-influenceable content, capped and delimited."""
        if layer in TRUSTED:
            raise WindowError(
                f"{layer.name} is a trusted layer; untrusted content cannot be "
                f"written to it"
            )
        text = content if isinstance(content, str) else _render(content)
        truncated = len(text) > self.block_cap
        self._layers.setdefault(layer, []).append(
            _Block(label, text[: self.block_cap], truncated)
        )
        return self

    # -- rendering --------------------------------------------------------

    def render(self) -> list[dict[str, str]]:
        """Messages for the provider. Trusted layers become the system message;
        untrusted blocks are fenced and labelled inside the user message."""
        trusted = "\n\n".join(
            block.text.strip()
            for layer in (Layer.SYSTEM, Layer.RULES, Layer.SKILLS)
            for block in self._layers.get(layer, [])
        )
        parts = []
        for layer in (Layer.SLIDING, Layer.QUERY):
            for block in self._layers.get(layer, []):
                suffix = " (truncated)" if block.truncated else ""
                parts.append(
                    f"<<<untrusted:{block.label}{suffix}>>>\n"
                    f"{block.text}\n"
                    f"<<<end:{block.label}>>>"
                )
        messages = []
        if trusted:
            messages.append({"role": "system", "content": trusted})
        messages.append({"role": "user", "content": "\n\n".join(parts)})
        return messages

    def truncated_blocks(self) -> list[str]:
        return [b.label for blocks in self._layers.values() for b in blocks if b.truncated]


def _render(value: Any) -> str:
    import json

    return json.dumps(value, indent=2, sort_keys=True, default=str)
