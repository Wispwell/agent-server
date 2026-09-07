"""Behaviour trees. M2.

The control structure standard in game AI and robotics, used here so that a
role bounds not only what a subagent may *reach* but the shape of what it will
*attempt*. Without it, "the call was denied, now what" has to be improvised
somewhere; with it, a refusal returns FAILURE and the enclosing Selector takes
its fallback branch — containment refusals become ordinary control flow.

Minimal node set on purpose: Sequence, Selector, Condition, Action, Decide.
No Parallel, no decorator zoo, no blackboard machinery beyond a dict.

RUNNING is part of the status contract and the composites handle it correctly,
but no v0 leaf returns it: gateway calls are synchronous. Handling it now means
an asynchronous leaf can be added later without rewriting the composites.

Trees are authored by the operator and frozen in the role catalog. The governor
selects a role — it never composes a tree.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

__all__ = [
    "Action",
    "BehaviourError",
    "Condition",
    "Context",
    "Decide",
    "Node",
    "Selector",
    "Sequence",
    "Status",
    "parse_tree",
]

_PLACEHOLDER = re.compile(r"\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


class BehaviourError(Exception):
    """A tree is malformed. Raised at load time, never during a tick."""


class Status(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    RUNNING = "running"


@dataclass
class Context:
    """Everything a tick can touch.

    `call_tool` is the only route to the world, and it returns a (ok, payload)
    pair rather than raising: a containment refusal is an expected outcome here,
    not an exception.
    """

    params: Mapping[str, Any]
    call_tool: Callable[[str, str, Mapping[str, Any]], tuple[bool, Any]]
    choose: Callable[[str, Mapping[str, Any]], dict[str, Any] | None] | None = None
    blackboard: dict[str, Any] = field(default_factory=dict)
    trace: list[dict[str, Any]] = field(default_factory=list)

    def resolve(self, value: Any) -> Any:
        """Substitute ${name} from params, then blackboard. Strings only."""
        if isinstance(value, str):
            def sub(match: re.Match[str]) -> str:
                name = match.group(1)
                if name in self.params:
                    return str(self.params[name])
                if name in self.blackboard:
                    return str(self.blackboard[name])
                raise BehaviourError(f"unbound placeholder: ${{{name}}}")
            return _PLACEHOLDER.sub(sub, value)
        if isinstance(value, dict):
            return {k: self.resolve(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.resolve(v) for v in value]
        return value

    def record(self, node: str, status: Status, **extra: Any) -> None:
        self.trace.append({"node": node, "status": str(status), **extra})


class Node(ABC):
    kind = "node"

    @abstractmethod
    def tick(self, ctx: Context) -> Status: ...

    def tools(self) -> list[tuple[str, str]]:
        """Every (server, tool) this subtree can invoke. Used to validate that a
        role's tree stays inside the role's capability set."""
        return []


@dataclass
class Sequence(Node):
    """Succeeds when every child succeeds, in order. Stops at the first failure."""

    children: list[Node]
    kind = "sequence"

    def tick(self, ctx: Context) -> Status:
        for child in self.children:
            status = child.tick(ctx)
            if status is not Status.SUCCESS:
                ctx.record(self.kind, status)
                return status
        ctx.record(self.kind, Status.SUCCESS)
        return Status.SUCCESS

    def tools(self):
        return [t for c in self.children for t in c.tools()]


@dataclass
class Selector(Node):
    """Succeeds at the first child that succeeds — the fallback composite.

    This is where a containment refusal becomes control flow: the denied branch
    returns FAILURE and the next branch is tried.
    """

    children: list[Node]
    kind = "selector"

    def tick(self, ctx: Context) -> Status:
        for child in self.children:
            status = child.tick(ctx)
            if status is not Status.FAILURE:
                ctx.record(self.kind, status)
                return status
        ctx.record(self.kind, Status.FAILURE)
        return Status.FAILURE

    def tools(self):
        return [t for c in self.children for t in c.tools()]


@dataclass
class Condition(Node):
    """Tests the blackboard. Pure: it may not reach the world."""

    key: str
    equals: Any = None
    present: bool | None = None
    kind = "condition"

    def tick(self, ctx: Context) -> Status:
        if self.present is not None:
            ok = (self.key in ctx.blackboard) == self.present
        else:
            ok = ctx.blackboard.get(self.key) == self.equals
        status = Status.SUCCESS if ok else Status.FAILURE
        ctx.record(self.kind, status, key=self.key)
        return status


@dataclass
class Action(Node):
    """Invokes one bound tool. FAILURE on refusal, never an exception."""

    server: str
    tool: str
    args: dict[str, Any]
    store: str | None = None
    kind = "action"

    def tick(self, ctx: Context) -> Status:
        try:
            args = ctx.resolve(self.args)
        except BehaviourError as exc:
            ctx.record(self.kind, Status.FAILURE, tool=self.tool, error=str(exc))
            return Status.FAILURE
        ok, payload = ctx.call_tool(self.server, self.tool, args)
        if ok and self.store:
            ctx.blackboard[self.store] = payload
        status = Status.SUCCESS if ok else Status.FAILURE
        ctx.record(self.kind, status, tool=f"{self.server}/{self.tool}",
                   detail=None if ok else str(payload)[:200])
        return status

    def tools(self):
        return [(self.server, self.tool)]


@dataclass
class Decide(Node):
    """Asks the model to choose the next call from the role's vocabulary.

    This leaf is the injection surface, and deliberately so. A tree whose next
    action is a pure function of our code cannot be steered by anything it
    reads — which is a legitimate role shape, but makes E2 vacuous. Roles used
    to measure injection resistance must contain one of these.

    The model's answer is constrained: it names a tool from `options`, and the
    resulting call is admitted or refused by containment like any other. A
    choice outside `options` is a FAILURE, not a new capability.
    """

    prompt: str
    options: list[tuple[str, str]]
    store: str | None = None
    kind = "decide"

    def tick(self, ctx: Context) -> Status:
        if ctx.choose is None:
            ctx.record(self.kind, Status.FAILURE, error="no model available")
            return Status.FAILURE
        chosen = ctx.choose(ctx.resolve(self.prompt), dict(ctx.blackboard))
        if not isinstance(chosen, dict):
            ctx.record(self.kind, Status.FAILURE, error="no choice returned")
            return Status.FAILURE
        server, tool = chosen.get("server"), chosen.get("tool")
        if (server, tool) not in self.options:
            ctx.record(self.kind, Status.FAILURE, error=f"chose {server}/{tool}, not offered")
            return Status.FAILURE
        ok, payload = ctx.call_tool(server, tool, chosen.get("args") or {})
        if ok and self.store:
            ctx.blackboard[self.store] = payload
        status = Status.SUCCESS if ok else Status.FAILURE
        ctx.record(self.kind, status, tool=f"{server}/{tool}",
                   detail=None if ok else str(payload)[:200])
        return status

    def tools(self):
        return list(self.options)


_FIELDS = {
    "sequence": {"type", "children"},
    "selector": {"type", "children"},
    "condition": {"type", "key", "equals", "present"},
    "action": {"type", "server", "tool", "args", "store"},
    "decide": {"type", "prompt", "options", "store"},
}


def parse_tree(spec: Mapping[str, Any]) -> Node:
    """Build a tree from config. Strict: an unknown node type or key raises.

    Validation happens at load so a malformed tree fails when a role is
    configured, not partway through a subagent's run.
    """
    if not isinstance(spec, Mapping):
        raise BehaviourError(f"node must be a mapping, got {type(spec).__name__}")
    kind = spec.get("type")
    if kind not in _FIELDS:
        raise BehaviourError(f"unknown node type {kind!r}; known: {sorted(_FIELDS)}")
    unknown = set(spec) - _FIELDS[kind]
    if unknown:
        raise BehaviourError(f"{kind} node has unknown keys: {sorted(unknown)}")

    if kind in ("sequence", "selector"):
        children = spec.get("children") or []
        if not children:
            raise BehaviourError(f"{kind} node has no children")
        nodes = [parse_tree(c) for c in children]
        return Sequence(nodes) if kind == "sequence" else Selector(nodes)

    if kind == "condition":
        if "key" not in spec:
            raise BehaviourError("condition node needs a key")
        return Condition(spec["key"], spec.get("equals"), spec.get("present"))

    if kind == "action":
        for required in ("server", "tool"):
            if required not in spec:
                raise BehaviourError(f"action node needs {required}")
        return Action(spec["server"], spec["tool"], dict(spec.get("args") or {}),
                      spec.get("store"))

    options = [tuple(o) for o in (spec.get("options") or [])]
    if not options:
        raise BehaviourError("decide node needs at least one option")
    if any(len(o) != 2 for o in options):
        raise BehaviourError("decide options must be [server, tool] pairs")
    return Decide(spec.get("prompt", ""), options, spec.get("store"))
