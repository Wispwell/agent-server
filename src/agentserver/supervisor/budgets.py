"""Budgets. M2.

Hard caps that end a run regardless of what the model does. This is what
removes any need to reason about whether the governor *would* stop: it does not
have to, because the budget does it.

Budgets also do the work a separate action-count limit would have done —
max_concurrent already refuses a spawn that cannot run, so capping how many
actions a turn may contain would be a second mechanism enforcing the same
property.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

__all__ = ["Budget", "BudgetExceeded"]


class BudgetExceeded(Exception):
    def __init__(self, limit: str, detail: str = ""):
        super().__init__(f"{limit} exhausted{f': {detail}' if detail else ''}")
        self.limit = limit
        self.reason = "budget_exhausted"


@dataclass
class Budget:
    max_turns: int = 20
    max_spawns: int = 10
    max_concurrent: int = 3
    max_wall_clock: int = 600
    max_tool_calls_per_subagent: int = 25
    max_tool_calls_total: int = 100

    turns: int = 0
    spawns: int = 0
    tool_calls: int = 0
    started_at: int | None = None
    _per_agent: dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any] | None) -> Budget:
        raw = raw or {}
        limits = {"max_turns", "max_spawns", "max_concurrent", "max_wall_clock",
                  "max_tool_calls_per_subagent", "max_tool_calls_total"}
        return cls(**{k: int(v) for k, v in raw.items() if k in limits})

    # -- checks -----------------------------------------------------------

    def check_turn(self) -> None:
        if self.turns >= self.max_turns:
            raise BudgetExceeded("max_turns", f"{self.turns}")

    def check_wall_clock(self, now: int) -> None:
        if self.started_at is not None and now - self.started_at >= self.max_wall_clock:
            raise BudgetExceeded("max_wall_clock", f"{now - self.started_at}s")

    def check_spawn(self, live: int) -> None:
        if self.spawns >= self.max_spawns:
            raise BudgetExceeded("max_spawns", f"{self.spawns}")
        if live >= self.max_concurrent:
            raise BudgetExceeded("max_concurrent", f"{live} live")

    def check_tool_call(self, agent_id: str) -> None:
        if self.tool_calls >= self.max_tool_calls_total:
            raise BudgetExceeded("max_tool_calls_total", f"{self.tool_calls}")
        used = self._per_agent.get(agent_id, 0)
        if used >= self.max_tool_calls_per_subagent:
            raise BudgetExceeded("max_tool_calls_per_subagent", f"{used}")

    # -- consumption ------------------------------------------------------

    def spend_turn(self) -> None:
        self.turns += 1

    def spend_spawn(self) -> None:
        self.spawns += 1

    def spend_tool_call(self, agent_id: str) -> None:
        self.tool_calls += 1
        self._per_agent[agent_id] = self._per_agent.get(agent_id, 0) + 1

    def used_by(self, agent_id: str) -> int:
        return self._per_agent.get(agent_id, 0)

    def remaining(self, now: int | None = None) -> dict[str, int]:
        out = {
            "turns": self.max_turns - self.turns,
            "spawns": self.max_spawns - self.spawns,
            "tool_calls": self.max_tool_calls_total - self.tool_calls,
        }
        if self.started_at is not None and now is not None:
            out["seconds"] = max(0, self.max_wall_clock - (now - self.started_at))
        return out
