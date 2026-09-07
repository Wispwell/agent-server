"""Counterfactual probe.

Submits deliberately-refusable variants of a real request and confirms the
engine *can still* produce DENIED — a necessary condition for containment to
mean anything.

This exists because of deviation collapse (design §8.7): a deployment where the
enforcement engine is perfectly correct and never fires, because upstream
stages removed every signal that could have triggered it. Invariants hold,
tests pass, and the boundary is simply never reached. A competent governor
plans safe tasks, so without probing there is no way to distinguish "the
containment layer works" from "the containment layer is dormant".

Every probe runs with ``dry_run=True``. That is not an optimisation: a probe
that moved the counters would trip the cooldown it is measuring, and asking
whether the boundary works would break it.

The probes reuse the base request's proof-of-possession. They test
*authorisation* capacity, not transport integrity, and re-signing each variant
would test the harness rather than the engine.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from agentserver.containment.admission import (
    AdmissionEngine,
    Decision,
    Outcome,
    Reason,
    Request,
    ToolCall,
)

__all__ = ["DEFAULT_MUTATIONS", "ProbeReport", "ProbeResult", "probe"]

Mutation = Callable[[AdmissionEngine, Request], tuple[Request, int | None] | None]


@dataclass
class ProbeResult:
    name: str
    applicable: bool
    outcome: Outcome | None = None
    reason: Reason | None = None
    detail: str = ""

    @property
    def activated(self) -> bool:
        return self.outcome in (Outcome.DENIED, Outcome.ESCALATED)


@dataclass
class ProbeReport:
    baseline: Decision
    results: list[ProbeResult] = field(default_factory=list)

    @property
    def applicable(self) -> list[ProbeResult]:
        return [r for r in self.results if r.applicable]

    @property
    def can_deny(self) -> bool:
        """The property that matters: DENIED is still reachable."""
        return any(r.outcome is Outcome.DENIED for r in self.results)

    @property
    def bar(self) -> float:
        """Boundary Activation Rate across the probe set."""
        rows = self.applicable
        return sum(r.activated for r in rows) / len(rows) if rows else 0.0

    def summary(self) -> str:
        lines = [
            f"baseline           {self.baseline.outcome}  ({self.baseline.reason})",
            (
                f"counterfactual BAR {self.bar:.2f}   denial reachable: "
                f"{'yes' if self.can_deny else 'NO — enforcement is vacuous'}"
            ),
            "",
        ]
        for r in self.results:
            if not r.applicable:
                lines.append(f"  {r.name:<26} n/a  ({r.detail})")
            else:
                mark = "✓" if r.activated else "✗"
                lines.append(f"  {mark} {r.name:<24} {r.outcome:<10} {r.reason}")
        return "\n".join(lines)


# -- mutations --------------------------------------------------------------


def _unbound_tool(engine: AdmissionEngine, request: Request):
    call = ToolCall("__probe__", "__unbound__", dict(request.call.args))
    return Request(call=call, token=request.token, pop=request.pop), None


def _path_traversal(engine: AdmissionEngine, request: Request):
    binding = engine.bindings.get((request.call.server, request.call.tool))
    if binding is None or binding.resolver != "path_under_root":
        return None
    field_name = binding.resolver_config.get("field")
    args = {**request.call.args, field_name: "../" * 8 + "etc/passwd"}
    call = ToolCall(request.call.server, request.call.tool, args)
    return Request(call=call, token=request.token, pop=request.pop), None


def _ungranted_capability(engine: AdmissionEngine, request: Request):
    granted = set(request.token.get("cap", []))
    for (server, tool), binding in engine.bindings.items():
        if binding.capability in granted:
            continue
        field_name = binding.resolver_config.get("field")
        sample = "https://probe.invalid/" if binding.resolver == "url_host" else "probe"
        call = ToolCall(server, tool, {field_name: sample})
        return Request(call=call, token=request.token, pop=request.pop), None
    return None


def _expired_token(engine: AdmissionEngine, request: Request):
    expiry = request.token.get("exp")
    if not isinstance(expiry, int):
        return None
    return request, expiry + 1


DEFAULT_MUTATIONS: dict[str, Mutation] = {
    "unbound_tool": _unbound_tool,
    "path_traversal": _path_traversal,
    "ungranted_capability": _ungranted_capability,
    "expired_token": _expired_token,
}


# -- driver -----------------------------------------------------------------


def probe(
    engine: AdmissionEngine,
    request: Request,
    *,
    now: int | None = None,
    mutations: Mapping[str, Mutation] | None = None,
) -> ProbeReport:
    """Evaluate `request` and a set of refusable variants, writing nothing."""
    mutations = DEFAULT_MUTATIONS if mutations is None else mutations
    report = ProbeReport(baseline=engine.evaluate(request, now=now, dry_run=True))

    for name, mutate in mutations.items():
        produced = mutate(engine, request)
        if produced is None:
            report.results.append(
                ProbeResult(name, applicable=False, detail="not applicable to this request")
            )
            continue
        mutated, at = produced
        decision = engine.evaluate(mutated, now=at if at is not None else now, dry_run=True)
        report.results.append(
            ProbeResult(name, applicable=True, outcome=decision.outcome,
                        reason=decision.reason, detail=decision.detail)
        )
    return report
