"""E1 — stateless versus stateful admission.

The headline number, and the argument for the whole data plane.

A permission list can express "this agent may read files under
workspace/reports". It cannot express "not its twenty-first read in sixty
seconds", because that is a property of an execution *trace* rather than of a
request. So: replay one stream of individually-valid requests through both, and
count what each admits.

Driven by a scripted stream rather than a live agent, deliberately. Comparing
two engines requires the same input reaching both, and a model would not
produce the same sequence twice.
"""

from __future__ import annotations

import argparse

from .harness import (
    Report,
    build_rig,
    emit,
    make_request,
    new_agent,
    stateless_decision,
)

NOW = 1_757_200_000


def run(*, requests: int = 60, rate_limit: int = 20) -> Report:
    rig = build_rig(rate_limit=rate_limit)
    try:
        key, token = new_agent(rig)
        stateless_ok = stateful_ok = 0
        reasons: dict[str, int] = {}

        for _ in range(requests):
            probe = make_request(rig, key, token, path="reports/q1.md")
            if stateless_decision(rig, probe):
                stateless_ok += 1

            live = make_request(rig, key, token, path="reports/q1.md")
            decision = rig.engine.evaluate(live, now=NOW)
            if decision.allowed:
                stateful_ok += 1
            else:
                reasons[str(decision.reason)] = reasons.get(str(decision.reason), 0) + 1

        report = Report(
            "E1 — stateless vs stateful",
            headline=(
                f"every request is individually valid: a stateless check admits "
                f"{stateless_ok}/{requests}, the admission engine admits {stateful_ok}"
            ),
        )
        report.add("requests replayed", requests)
        report.add("rate limit", f"{rate_limit} per 60s per PatternKey")
        report.add("stateless engine — approved", f"{stateless_ok}/{requests}")
        report.add("admission engine — approved", f"{stateful_ok}/{requests}")
        for reason, count in sorted(reasons.items()):
            report.add(f"  refused: {reason}", count)
        report.notes.append(
            "the stateless check is not a weakened engine — it is the whole of "
            "what a policy without history can express"
        )
        return report
    finally:
        rig.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requests", type=int, default=60)
    parser.add_argument("--rate-limit", type=int, default=20)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    emit([run(requests=args.requests, rate_limit=args.rate_limit)], as_json=args.json)


if __name__ == "__main__":
    main()
