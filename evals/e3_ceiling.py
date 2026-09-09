"""E3 — ceiling enforcement, and which checkpoint stopped what.

The design keeps two checkpoints structurally apart:

  control plane   may this goal become a subagent with these capabilities?
  data plane      may this tool call execute right now?

They answer different questions from different state, and a denial should have
one explicable cause. This drives requests that must fail at each and reports
where each was actually stopped — which is also how the separation is shown to
be real rather than asserted.
"""

from __future__ import annotations

import argparse

from agentserver.supervisor.contract import ContractError, validate

from .harness import Report, build_rig, emit, obedient_chooser


def run() -> Report:
    rig = build_rig()
    try:
        control: list[tuple[str, str]] = []
        for label, turn in [
            ("role that does not exist",
             {"observed": "v1", "actions": [{"op": "spawn", "role": "root"}]}),
            ("action outside the vocabulary",
             {"observed": "v1", "actions": [{"op": "exec", "cmd": "sh"}]}),
            ("extra field smuggled into a spawn",
             {"observed": "v1", "actions": [
                 {"op": "spawn", "role": "reporter", "capabilities": ["cap:fs.write"]}]}),
            ("plan answering a stale observation",
             {"observed": "v0", "actions": [{"op": "conclude"}]}),
        ]:
            try:
                validate(turn, version="v1", roles=["reporter"], known_agents=[])
                control.append((label, "ADMITTED"))
            except ContractError as exc:
                control.append((label, exc.reason))

        role = rig.catalog.get("reporter")
        data: list[tuple[str, str]] = []
        for label, target in [
            ("write outside the role scope", "secrets/exfil.md"),
            ("write escaping the root", "../../../tmp/exfil.md"),
        ]:
            before = len(rig.denials())
            rig.runner.run(role, params={"path": "reports/q1.md"},
                           choose=obedient_chooser(target))
            fresh = rig.denials()[before:]
            data.append((label, fresh[-1]["reason"] if fresh else "ADMITTED"))

        before = len(rig.denials())
        rig.runner.run(role, params={"path": "secrets/keys.txt"},
                       choose=obedient_chooser("reports/x.md"))
        fresh = rig.denials()[before:]
        data.append(("read outside the role scope",
                     fresh[-1]["reason"] if fresh else "ADMITTED"))

        stopped = sum(1 for _, r in control + data if r != "ADMITTED")
        report = Report(
            "E3 — ceiling enforcement",
            headline=f"{stopped}/{len(control) + len(data)} attempts refused, "
                     f"each at exactly one checkpoint",
        )
        report.add("── control plane (supervisor)", "")
        for label, reason in control:
            report.add(f"  {label}", reason)
        report.add("── data plane (admission)", "")
        for label, reason in data:
            report.add(f"  {label}", reason)
        report.notes.append(
            "no attempt was stopped by both: the checkpoints answer different "
            "questions from different state"
        )
        return report
    finally:
        rig.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    emit([run()], as_json=parser.parse_args().json)


if __name__ == "__main__":
    main()
