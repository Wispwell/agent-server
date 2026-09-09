"""Subagent lifecycle. M2.

    spawned → bound → running → { completed | killed | faulted }

`bound` is where the capability token is issued. Capabilities cannot be
attached to an already-running agent: no runtime privilege mutation, enforced
by the transition table rather than by remembering not to.

Distinct from an agent's risk state — denial counts, cooldown, rate counters,
held in the `agents` table and applied by the admission engine. Conflating the
two destroys the ability to explain a denial.
Conflating the two destroys the ability to explain a denial.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = ["TERMINAL", "LifecycleError", "State", "check_transition"]


class State(StrEnum):
    SPAWNED = "spawned"
    BOUND = "bound"
    RUNNING = "running"
    COMPLETED = "completed"
    KILLED = "killed"
    FAULTED = "faulted"


TERMINAL = frozenset({State.COMPLETED, State.KILLED, State.FAULTED})

_ALLOWED: dict[State, frozenset[State]] = {
    State.SPAWNED: frozenset({State.BOUND, State.KILLED, State.FAULTED}),
    State.BOUND: frozenset({State.RUNNING, State.KILLED, State.FAULTED}),
    State.RUNNING: frozenset({State.COMPLETED, State.KILLED, State.FAULTED}),
    State.COMPLETED: frozenset(),
    State.KILLED: frozenset(),
    State.FAULTED: frozenset(),
}


class LifecycleError(Exception):
    reason = "illegal_transition"


def check_transition(current: State, target: State) -> None:
    """Raise unless the move is legal. Terminal states are terminal."""
    if target not in _ALLOWED[current]:
        raise LifecycleError(f"cannot move from {current} to {target}")
