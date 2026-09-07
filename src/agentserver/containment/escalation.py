"""Escalation handlers. M1.

The governor cannot resolve its own escalations — an untrusted component
auditing itself makes escalation decorative. Escalations go to a human, and in
v0 that is a CLI prompt.

Every handler here fails closed. An unanswered question is not an approval,
a closed stdin is not an approval, and a handler that raises is not an
approval.
"""

from __future__ import annotations

import select
import sys
from collections.abc import Mapping, Sequence
from typing import Any

__all__ = ["auto_refuse", "cli_handler", "scripted_handler"]


def auto_refuse(_escalation: Mapping[str, Any]) -> bool:
    """The default. Refuses everything, silently."""
    return False


def _render(escalation: Mapping[str, Any]) -> str:
    return (
        "\n─── escalation ────────────────────────────────────────\n"
        f"  agent      {escalation.get('agent_id')}\n"
        f"  capability {escalation.get('capability')}\n"
        f"  resource   {escalation.get('resource')}\n"
        f"  reason     {escalation.get('reason')}"
        + (f"  ({escalation['detail']})" if escalation.get("detail") else "")
        + "\n───────────────────────────────────────────────────────"
    )


def cli_handler(timeout: int = 120, stream=None):
    """Ask at the terminal, refusing if unanswered within `timeout` seconds.

    The timeout is the point. A blocking prompt with no deadline turns one
    unattended escalation into a stalled system, and "the operator stepped
    away" must resolve to refusal rather than to waiting forever.
    """

    def handle(escalation: Mapping[str, Any]) -> bool:
        out = stream or sys.stdout
        stdin = sys.stdin
        print(_render(escalation), file=out)
        print(f"  approve? [y/N]  ({timeout}s to answer) ", end="", flush=True, file=out)

        if not stdin or stdin.closed or not stdin.readable():
            print("\n  → refused (no input available)", file=out)
            return False
        try:
            ready, _, _ = select.select([stdin], [], [], timeout)
        except (OSError, ValueError):
            print("\n  → refused (cannot wait on input)", file=out)
            return False
        if not ready:
            print("\n  → refused (timed out)", file=out)
            return False

        answer = stdin.readline().strip().lower()
        approved = answer in ("y", "yes")
        print(f"  → {'approved' if approved else 'refused'}", file=out)
        return approved

    return handle


def scripted_handler(answers: Sequence[bool]):
    """Replay a fixed sequence of answers, then refuse. For evals and demos.

    Refusing once the script runs out matters: an eval that silently starts
    approving everything after its script ends would report a containment
    boundary that had quietly stopped existing.
    """
    remaining = list(answers)

    def handle(_escalation: Mapping[str, Any]) -> bool:
        return remaining.pop(0) if remaining else False

    return handle
