"""The supervisor loop. M2/M3. Trusted.

The supervisor owns the loop. It observes, invokes the governor, validates the
answer, dispatches what it admits, and observes again. The model is a
subroutine of a deterministic program, not a program that consults a
deterministic helper — a governor that could decline to call its own check
would have no check.

**Termination does not depend on the model choosing to stop.** `conclude` is an
action the governor emits, so a governor that never emits it must still be
stopped. The hard guards end the run regardless, which is what removes any need
to reason about whether it would.

*What v0 does not do:* subagents run to completion inside dispatch, so there is
nothing to supervise concurrently and asynchronous dispatch would buy nothing
today. The governor call is bounded by the provider timeout. `max_concurrent`
therefore never fires — `max_spawns` is the cap that bites — and `kill` has
nothing to kill. Both are implemented and both are honest no-ops until
subagents run concurrently.
"""

from __future__ import annotations

import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from ..crypto.tokens import resource_matches
from ..ledger.events import EventType
from .budgets import BudgetExceeded
from .contract import ContractError, Turn, validate

__all__ = ["ActionOutcome", "Observation", "RunResult", "Supervisor"]

_PLACEHOLDER = re.compile(r"\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


@dataclass
class Observation:
    version: str
    task: str
    roles: list[dict[str, Any]] = field(default_factory=list)
    environment: list[str] = field(default_factory=list)
    roster: list[dict[str, Any]] = field(default_factory=list)
    outcomes: list[dict[str, Any]] = field(default_factory=list)
    budgets: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version, "task": self.task, "roles": self.roles,
            "environment": self.environment, "roster": self.roster,
            "outcomes": self.outcomes, "budgets": self.budgets,
        }


@dataclass
class ActionOutcome:
    op: str
    ok: bool
    reason: str = ""
    detail: str = ""
    agent_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        out = {"op": self.op, "ok": self.ok}
        if self.reason:
            out["reason"] = self.reason
        if self.detail:
            out["detail"] = self.detail
        if self.agent_id:
            out["agent_id"] = self.agent_id
        return out


@dataclass
class RunResult:
    halted: str
    turns: int
    summary: str = ""
    rejections: int = 0
    subagents: list[dict[str, Any]] = field(default_factory=list)


class Supervisor:
    def __init__(
        self,
        *,
        engine,
        gateway,
        catalog,
        runner,
        governor,
        policy,
        budget,
        choose=None,
        max_rejections: int = 3,
        no_progress_turns: int = 3,
        environment_cap: int = 100,
        environment_depth: int = 4,
    ):
        self.engine = engine
        self.gateway = gateway
        self.catalog = catalog
        self.runner = runner
        self.governor = governor
        self.policy = policy
        self.budget = budget
        self.choose = choose
        self.max_rejections = max_rejections
        self.no_progress_turns = no_progress_turns
        self.environment_cap = environment_cap
        self.environment_depth = environment_depth
        self._version = 0
        self._results: list = []
        self._last_outcomes: list[ActionOutcome] = []

    @property
    def ledger(self):
        return self.engine.ledger

    # -- observation ------------------------------------------------------

    def observe(self, task: str, *, now: int | None = None) -> Observation:
        """Assemble what the governor is allowed to know.

        Scoped by the ceiling: the environment listing shows only resources
        inside some installed role's scope. Least privilege applies to
        information, not only to authority, and deriving both from the same
        scopes leaves one thing to get right rather than two.
        """
        self._version += 1
        roles = []
        for described in self.catalog.describe():
            role = self.catalog.get(described["role"])
            roles.append({**described, "params": sorted(_placeholders(role.spec))})
        return Observation(
            version=f"v{self._version}",
            task=task,
            roles=roles,
            environment=self._environment(),
            roster=[r.normalised() for r in self._results],
            outcomes=[o.as_dict() for o in self._last_outcomes],
            budgets=self.budget.remaining(now),
        )

    def _environment(self) -> list[str]:
        scopes = [role.resource for role in self.catalog.roles.values()]
        found: list[str] = []
        for name, root in self.policy.roots.items():
            base = root.path
            for path in sorted(_walk(base, self.environment_depth)):
                resource = f"{name}/{path}"
                if any(resource_matches(scope, resource) for scope in scopes):
                    found.append(resource)
                if len(found) >= self.environment_cap:
                    return found
        return found

    # -- the loop ---------------------------------------------------------

    def run(self, task: str, *, now: int | None = None) -> RunResult:
        started = int(time.time()) if now is None else now
        self.budget.started_at = started
        rejections = 0
        idle_turns = 0
        summary = ""

        while True:
            clock = int(time.time()) if now is None else now
            halted = self._halt_guard(clock, rejections, idle_turns)
            if halted:
                return self._finish(halted, rejections, summary)

            observation = self.observe(task, now=clock)
            raw, completion = self.governor.turn(observation.as_dict())

            turn, failure = self._parse(raw, completion, observation)
            self.budget.spend_turn()
            if turn is None:
                rejections += 1
                self.ledger.append(EventType.SCHEMA_REJECTED,
                                   {"turn": self.budget.turns, "detail": failure})
                self._last_outcomes = [ActionOutcome("(rejected)", False,
                                                     "schema_rejected", failure)]
                continue

            rejections = 0
            self.ledger.append(EventType.GOVERNOR_OUTPUT,
                               {"turn": self.budget.turns,
                                "actions": [a.op for a in turn.actions],
                                "reasoning": turn.reasoning[:400]})

            outcomes, concluded = self._dispatch(turn, clock)
            self._last_outcomes = outcomes
            idle_turns = idle_turns + 1 if all(o.op == "wait" for o in outcomes) else 0
            if concluded is not None:
                return self._finish("conclude", rejections, concluded)

    # -- pieces -----------------------------------------------------------

    def _parse(self, raw, completion, observation) -> tuple[Turn | None, str]:
        if raw is None:
            return None, completion.malformed or "no parseable answer"
        try:
            return validate(
                raw,
                version=observation.version,
                roles=list(self.catalog.roles),
                known_agents=[r.agent_id for r in self._results],
            ), ""
        except ContractError as exc:
            return None, f"{exc.reason}: {exc}"

    def _dispatch(self, turn: Turn, now: int) -> tuple[list[ActionOutcome], str | None]:
        outcomes: list[ActionOutcome] = []
        concluded: str | None = None
        for action in turn.actions:
            if action.op == "conclude":
                concluded = action.summary
                outcomes.append(ActionOutcome("conclude", True))
                continue
            if action.op == "wait":
                outcomes.append(ActionOutcome("wait", True))
                continue
            if action.op == "kill":
                outcomes.append(ActionOutcome(
                    "kill", False, "not_running",
                    "subagents run to completion in v0; there is nothing to kill",
                    action.agent_id))
                continue
            outcomes.append(self._spawn(action, now))
        return outcomes, concluded

    def _spawn(self, action, now: int) -> ActionOutcome:
        live = sum(1 for r in self._results if str(r.state) == "running")
        try:
            self.budget.check_spawn(live)
        except BudgetExceeded as exc:
            self.ledger.append(EventType.BUDGET_EXHAUSTED,
                               {"limit": exc.limit, "role": action.role}, now=now)
            return ActionOutcome("spawn", False, exc.reason, str(exc))

        role = self.catalog.get(action.role)
        self.budget.spend_spawn()
        self.ledger.append(EventType.SPAWN_ADMITTED,
                           {"role": role.name, "task": action.task[:200]}, now=now)
        result = self.runner.run(role, params=action.params, choose=self.choose, now=now)
        self._results.append(result)
        return ActionOutcome(
            "spawn", result.denied == 0, "" if result.denied == 0 else "denied_actions",
            f"{result.tool_calls} calls, {result.denied} denied", result.agent_id,
        )

    def _halt_guard(self, now: int, rejections: int, idle_turns: int) -> str | None:
        if rejections >= self.max_rejections:
            return "schema_rejections"
        if idle_turns >= self.no_progress_turns:
            return "no_progress"
        try:
            self.budget.check_turn()
            self.budget.check_wall_clock(now)
        except BudgetExceeded as exc:
            return exc.limit
        return None

    def _finish(self, halted: str, rejections: int, summary: str) -> RunResult:
        self.ledger.append(EventType.LIFECYCLE,
                           {"scope": "run", "halted": halted, "turns": self.budget.turns})
        return RunResult(
            halted=halted, turns=self.budget.turns, summary=summary,
            rejections=rejections,
            subagents=[r.normalised() for r in self._results],
        )


def _placeholders(spec: Mapping[str, Any]) -> set[str]:
    """Which ${names} a role's tree expects, so the governor knows what to supply."""
    import json

    return set(_PLACEHOLDER.findall(json.dumps(spec)))


def _walk(base, depth: int) -> list[str]:
    from pathlib import Path

    root = Path(base)
    if not root.is_dir():
        return []
    out = []
    for path in root.rglob("*"):
        if path.is_file():
            relative = path.relative_to(root)
            if len(relative.parts) <= depth:
                out.append(str(relative).replace("\\", "/"))
    return out
