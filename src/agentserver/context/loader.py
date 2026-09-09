"""Prompt and skill loading. M3. Trusted.

Loads the operator-authored material that becomes the trusted layers of a
context window: system instructions, rulesets, and skills.

**A skill file is, in effect, part of an agent's system prompt.** So the load
path must be somewhere no agent can write. If skills were read from a workspace
an agent operates on — or if a subagent held write capability over the prompt
directory — it would be authoring its own instructions, and every containment
property downstream would be reasoning about a prompt the agent chose.

That is checked, not assumed: constructing a Loader whose root sits inside any
configured capability root raises. It is the kind of misconfiguration that
would never announce itself.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

__all__ = ["Kind", "Loader", "LoaderError", "Prompt"]


class LoaderError(Exception):
    reason = "prompt_unavailable"


class Kind(StrEnum):
    SYSTEM = "system"
    RULES = "rules"
    SKILL = "skills"


@dataclass(frozen=True)
class Prompt:
    """Operator-authored text. The type is the marker: a context window's
    trusted layers accept only these, never a bare string, so untrusted text
    cannot reach them by being passed to the wrong argument."""

    kind: Kind
    name: str
    text: str


class Loader:
    def __init__(self, root: str | os.PathLike, *, agent_roots: Iterable[Path] = ()):
        self.root = Path(root).resolve()
        for agent_root in agent_roots:
            resolved = Path(agent_root).resolve()
            if self.root == resolved or self.root.is_relative_to(resolved):
                raise LoaderError(
                    f"prompt root {self.root} is inside the agent-writable root "
                    f"{resolved}; an agent could author its own instructions"
                )

    def path_for(self, kind: Kind, name: str) -> Path:
        if "/" in name or name.startswith("."):
            raise LoaderError(f"invalid prompt name {name!r}")
        return self.root / str(kind) / f"{name}.md"

    def load(self, kind: Kind, name: str) -> Prompt:
        path = self.path_for(kind, name)
        try:
            return Prompt(kind, name, path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise LoaderError(f"cannot read {path}: {exc}") from None

    def load_all(self, kind: Kind) -> list[Prompt]:
        directory = self.root / str(kind)
        if not directory.is_dir():
            return []
        return [
            Prompt(kind, path.stem, path.read_text(encoding="utf-8"))
            for path in sorted(directory.glob("*.md"))
        ]
