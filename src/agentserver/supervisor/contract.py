"""Governor output contract. M2.

Everything the governor emits is **hostile input**. Schema-validate, reject on
any deviation, log the rejection. Never string-match model output to decide
anything.

Validation is deterministic and total:

  * An unknown key anywhere rejects the whole turn. Not "ignore unexpected
    fields" — an unexpected key means the model is doing something the design
    does not cover, and silently dropping it hides exactly that.
  * `observed` must match the current observation version or the batch is
    rejected whole. The governor plans against a snapshot and the world moves
    while it thinks; applying half a plan against a changed world is worse than
    discarding it. Ordinary optimistic concurrency control.
  * Empty `actions` means wait, not an error.
  * There is no cap on action count: max_concurrent already refuses a spawn
    that cannot run.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

__all__ = ["Action", "ContractError", "Turn", "validate"]

_TURN_KEYS = {"observed", "reasoning", "actions"}
_ACTION_KEYS = {
    "spawn": {"op", "role", "task", "params", "budget"},
    "kill": {"op", "agent_id"},
    "wait": {"op"},
    "conclude": {"op", "summary"},
}


class ContractError(Exception):
    def __init__(self, message: str, reason: str = "schema_rejected"):
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class Action:
    op: str
    role: str | None = None
    task: str = ""
    params: Mapping[str, Any] = field(default_factory=dict)
    budget: Mapping[str, Any] = field(default_factory=dict)
    agent_id: str | None = None
    summary: str = ""


@dataclass(frozen=True)
class Turn:
    observed: str
    reasoning: str
    actions: tuple[Action, ...]


def validate(
    raw: Any,
    *,
    version: str,
    roles: Sequence[str],
    known_agents: Sequence[str],
) -> Turn:
    """Parse one governor turn, or raise ContractError."""
    if not isinstance(raw, Mapping):
        raise ContractError(f"turn must be an object, got {type(raw).__name__}")

    unknown = set(raw) - _TURN_KEYS
    if unknown:
        raise ContractError(f"turn has unknown keys: {sorted(unknown)}")

    observed = raw.get("observed")
    if not isinstance(observed, str):
        raise ContractError("turn has no 'observed' version")
    if observed != version:
        raise ContractError(
            f"turn answers observation {observed!r}, current is {version!r}",
            reason="stale_observation",
        )

    reasoning = raw.get("reasoning")
    if reasoning is not None and not isinstance(reasoning, str):
        raise ContractError("'reasoning' must be text")

    actions_raw = raw.get("actions")
    if actions_raw is None:
        actions_raw = []
    if not isinstance(actions_raw, list):
        raise ContractError("'actions' must be a list")

    actions = [_action(a, roles, known_agents) for a in actions_raw]
    if not actions:
        actions = [Action(op="wait")]

    return Turn(observed=observed, reasoning=str(reasoning or ""), actions=tuple(actions))


def _action(raw: Any, roles: Sequence[str], known_agents: Sequence[str]) -> Action:
    if not isinstance(raw, Mapping):
        raise ContractError(f"action must be an object, got {type(raw).__name__}")
    op = raw.get("op")
    if op not in _ACTION_KEYS:
        raise ContractError(f"unknown op {op!r}; known: {sorted(_ACTION_KEYS)}")
    unknown = set(raw) - _ACTION_KEYS[op]
    if unknown:
        raise ContractError(f"{op} action has unknown keys: {sorted(unknown)}")

    if op == "spawn":
        role = raw.get("role")
        if role not in roles:
            raise ContractError(f"unknown role {role!r}; available: {sorted(roles)}")
        params = raw.get("params") or {}
        if not isinstance(params, Mapping):
            raise ContractError("spawn params must be an object")
        budget = raw.get("budget") or {}
        if not isinstance(budget, Mapping):
            raise ContractError("spawn budget must be an object")
        return Action(op=op, role=role, task=str(raw.get("task") or ""),
                      params=dict(params), budget=dict(budget))

    if op == "kill":
        agent_id = raw.get("agent_id")
        if agent_id not in known_agents:
            raise ContractError(f"unknown agent {agent_id!r}")
        return Action(op=op, agent_id=agent_id)

    if op == "conclude":
        return Action(op=op, summary=str(raw.get("summary") or ""))

    return Action(op="wait")
