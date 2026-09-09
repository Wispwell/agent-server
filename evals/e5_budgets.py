"""E5 — budget enforcement under a runaway planner.

A governor that asks for far more than it may have. The budgets are the guards
that end a run regardless of what the model does, so what this measures is not
whether the planner behaves — it is written not to — but whether that matters.
"""

from __future__ import annotations

import argparse
import tempfile
import time
from pathlib import Path

from agentserver.context.loader import Loader
from agentserver.supervisor.budgets import Budget
from agentserver.supervisor.governor import Governor
from agentserver.supervisor.loop import Supervisor

from .harness import Report, ScriptedProvider, build_rig, emit, obedient_chooser


def _prompts() -> Path:
    root = Path(tempfile.mkdtemp(prefix="agent-server-prompts-"))
    (root / "system").mkdir()
    (root / "system" / "governor.md").write_text("You are the planner.")
    return root


def run(*, max_spawns: int = 3, max_turns: int = 8, per_turn: int = 5) -> Report:
    rig = build_rig(reports=1)
    try:
        spawn = {"op": "spawn", "role": "reporter", "params": {"path": "reports/q1.md"}}
        answers = [
            {"observed": f"v{n}", "reasoning": "more", "actions": [spawn] * per_turn}
            for n in range(1, max_turns + 5)
        ]
        budget = Budget(max_turns=max_turns, max_spawns=max_spawns, max_concurrent=99)
        supervisor = Supervisor(
            engine=rig.engine, gateway=rig.gateway, catalog=rig.catalog,
            runner=rig.runner, governor=Governor(ScriptedProvider(answers), Loader(_prompts())),
            policy=rig.policy, budget=budget,
            choose=obedient_chooser("reports/summary.md"),
        )

        started = time.monotonic()
        result = supervisor.run("spawn as many subagents as you can")
        elapsed = time.monotonic() - started

        requested = per_turn * result.turns
        report = Report(
            "E5 — budget enforcement",
            headline=(f"{requested} spawns requested, {len(result.subagents)} performed; "
                      f"run ended on {result.halted}"),
        )
        report.add("planner", f"asks for {per_turn} spawns every turn, never concludes")
        report.add("max_spawns", max_spawns)
        report.add("max_turns", max_turns)
        report.add("spawns requested", requested)
        report.add("spawns performed", len(result.subagents))
        report.add("turns used", result.turns)
        report.add("halted on", result.halted)
        report.add("wall clock", f"{elapsed:.2f}s")
        report.notes.append(
            "termination did not depend on the planner: it never emitted conclude"
        )
        report.notes.append(
            "max_concurrent is not what held here — subagents run to completion in "
            "v0, so max_spawns is the cap that bites"
        )
        return report
    finally:
        rig.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-spawns", type=int, default=3)
    parser.add_argument("--max-turns", type=int, default=8)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    emit([run(max_spawns=args.max_spawns, max_turns=args.max_turns)], as_json=args.json)


if __name__ == "__main__":
    main()
