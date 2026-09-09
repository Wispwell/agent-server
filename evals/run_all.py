"""Run every evaluation and emit one report.

Deterministic and offline by default: no API key, no network, same numbers
every time. `--live` puts a real model behind the Decide leaf for E2, which is
the only figure that changes meaning when a model is actually involved.
"""

from __future__ import annotations

import argparse

from . import e1_stateless_vs_stateful, e2_injection, e3_ceiling, e4_bar, e5_budgets
from .harness import emit


def run_all(*, live_chooser=None, mode: str = "scripted") -> list:
    return [
        e1_stateless_vs_stateful.run(),
        e2_injection.run(chooser=live_chooser, mode=mode),
        e3_ceiling.run(),
        e4_bar.run(),
        e5_budgets.run(),
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="real model for E2")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    chooser, mode = None, "scripted"
    if args.live:
        from agentserver.config import Config
        from agentserver.providers.openrouter import OpenRouterClient
        from agentserver.subagent.decide import model_chooser

        config = Config.load()
        chooser = model_chooser(OpenRouterClient(config.provider), [("tools", "write_file")])
        mode = f"live ({config.provider.model})"

    emit(run_all(live_chooser=chooser, mode=mode), as_json=args.json)


if __name__ == "__main__":
    main()
