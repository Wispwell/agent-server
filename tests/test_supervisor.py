"""Tests for the control plane: lifecycle, budgets, catalog, contract."""

from __future__ import annotations

import pytest

from agentserver.supervisor.budgets import Budget, BudgetExceeded
from agentserver.supervisor.catalog import Catalog, CatalogError
from agentserver.supervisor.contract import ContractError, validate
from agentserver.supervisor.lifecycle import LifecycleError, State, check_transition

# --------------------------------------------------------------------------
# lifecycle
# --------------------------------------------------------------------------


def test_the_normal_path_is_legal():
    for a, b in [(State.SPAWNED, State.BOUND), (State.BOUND, State.RUNNING),
                 (State.RUNNING, State.COMPLETED)]:
        check_transition(a, b)


def test_capabilities_cannot_be_attached_to_a_running_agent():
    """No runtime privilege mutation — enforced by the table, not by memory."""
    with pytest.raises(LifecycleError):
        check_transition(State.RUNNING, State.BOUND)


def test_terminal_states_are_terminal():
    for terminal in (State.COMPLETED, State.KILLED, State.FAULTED):
        for target in State:
            with pytest.raises(LifecycleError):
                check_transition(terminal, target)


def test_an_agent_can_be_killed_or_fault_from_any_live_state():
    for live in (State.SPAWNED, State.BOUND, State.RUNNING):
        check_transition(live, State.KILLED)
        check_transition(live, State.FAULTED)


# --------------------------------------------------------------------------
# budgets
# --------------------------------------------------------------------------


def test_a_run_ends_on_turns_regardless_of_what_the_model_wants():
    budget = Budget(max_turns=3)
    for _ in range(3):
        budget.check_turn()
        budget.spend_turn()
    with pytest.raises(BudgetExceeded, match="max_turns"):
        budget.check_turn()


def test_concurrency_is_what_refuses_an_extra_spawn():
    """This is why there is no separate cap on actions per turn."""
    budget = Budget(max_spawns=10, max_concurrent=2)
    budget.check_spawn(live=1)
    with pytest.raises(BudgetExceeded, match="max_concurrent"):
        budget.check_spawn(live=2)


def test_total_spawns_are_capped_independently_of_concurrency():
    budget = Budget(max_spawns=2, max_concurrent=5)
    for _ in range(2):
        budget.check_spawn(live=0)
        budget.spend_spawn()
    with pytest.raises(BudgetExceeded, match="max_spawns"):
        budget.check_spawn(live=0)


def test_tool_calls_are_capped_per_agent_and_in_total():
    budget = Budget(max_tool_calls_per_subagent=2, max_tool_calls_total=3)
    for _ in range(2):
        budget.check_tool_call("a")
        budget.spend_tool_call("a")
    with pytest.raises(BudgetExceeded, match="per_subagent"):
        budget.check_tool_call("a")

    budget.check_tool_call("b")
    budget.spend_tool_call("b")
    with pytest.raises(BudgetExceeded, match="total"):
        budget.check_tool_call("b")


def test_wall_clock_ends_the_run():
    budget = Budget(max_wall_clock=60)
    budget.started_at = 1000
    budget.check_wall_clock(1059)
    with pytest.raises(BudgetExceeded, match="wall_clock"):
        budget.check_wall_clock(1060)


def test_remaining_reports_what_is_left():
    budget = Budget(max_turns=5, max_spawns=3)
    budget.spend_turn()
    assert budget.remaining()["turns"] == 4
    assert budget.remaining()["spawns"] == 3


# --------------------------------------------------------------------------
# catalog
# --------------------------------------------------------------------------


def role_spec(**kw):
    spec = {
        "capabilities": ["cap:fs.read"],
        "resource": "workspace/reports/**",
        "tree": {"type": "action", "server": "fs", "tool": "read_file",
                 "args": {"path": "${path}"}},
    }
    spec.update(kw)
    return {"roles": {"reader": spec}}


def build(env, **kw):
    return Catalog.from_dict(role_spec(**kw), policy=env["policy"],
                             bindings=env["engine"].bindings)


def test_a_valid_role_loads(env):
    catalog = build(env)
    role = catalog.get("reader")
    assert role.capabilities == frozenset({"cap:fs.read"})
    assert role.tools() == [("fs", "read_file")]


def test_a_role_granting_an_undeclared_capability_is_refused(env):
    with pytest.raises(CatalogError, match="undeclared capability"):
        build(env, capabilities=["cap:shell.exec"])


def test_a_role_whose_tree_calls_an_unbound_tool_is_refused(env):
    with pytest.raises(CatalogError, match="unbound tool"):
        build(env, tree={"type": "action", "server": "shell", "tool": "exec"})


def test_a_tree_cannot_reach_outside_the_role_capability_set(env):
    """Caught when the catalog loads, not when a subagent is halfway through."""
    with pytest.raises(CatalogError, match="does not grant"):
        build(env, capabilities=["cap:fs.read"],
              tree={"type": "action", "server": "web", "tool": "fetch"})


def test_a_role_with_no_capabilities_or_scope_is_refused(env):
    with pytest.raises(CatalogError, match="no capabilities"):
        build(env, capabilities=[])
    with pytest.raises(CatalogError, match="resource scope"):
        build(env, resource="")


def test_unknown_role_keys_are_refused(env):
    with pytest.raises(CatalogError, match="unknown keys"):
        build(env, sandbox=False)


def test_an_unknown_role_lookup_raises(env):
    with pytest.raises(CatalogError, match="unknown role"):
        build(env).get("writer")


def test_describe_is_the_action_vocabulary(env):
    described = build(env).describe()
    assert described[0]["role"] == "reader"
    assert described[0]["capabilities"] == ["cap:fs.read"]
    assert "tree" not in described[0], "the governor selects roles, not trees"


# --------------------------------------------------------------------------
# governor output contract
# --------------------------------------------------------------------------


BASE = {"observed": "v1", "reasoning": "because", "actions": []}


def check(raw, **kw):
    return validate(raw, version=kw.get("version", "v1"),
                    roles=kw.get("roles", ["reader"]),
                    known_agents=kw.get("known_agents", ["agent-1"]))


def test_a_valid_turn_parses():
    turn = check({**BASE, "actions": [
        {"op": "spawn", "role": "reader", "task": "read it", "params": {"path": "a.md"}},
        {"op": "wait"},
    ]})
    assert [a.op for a in turn.actions] == ["spawn", "wait"]
    assert turn.actions[0].params == {"path": "a.md"}


def test_an_empty_action_list_means_wait():
    assert [a.op for a in check(BASE).actions] == ["wait"]


def test_a_stale_turn_is_rejected_whole():
    """Optimistic concurrency: the world moved while the governor was thinking."""
    with pytest.raises(ContractError) as exc:
        check({**BASE, "observed": "v0", "actions": [{"op": "conclude"}]})
    assert exc.value.reason == "stale_observation"


def test_a_turn_without_a_version_is_rejected():
    with pytest.raises(ContractError, match="observed"):
        check({"reasoning": "x", "actions": []})


@pytest.mark.parametrize("bad", [
    {**BASE, "extra": 1},
    {**BASE, "actions": [{"op": "spawn", "role": "reader", "shell": True}]},
    {**BASE, "actions": [{"op": "exec"}]},
    {**BASE, "actions": [{"op": "spawn", "role": "hacker"}]},
    {**BASE, "actions": [{"op": "kill", "agent_id": "nobody"}]},
    {**BASE, "actions": "not a list"},
    {**BASE, "actions": ["not an object"]},
    {**BASE, "reasoning": 42},
    "not an object",
])
def test_any_deviation_rejects_the_whole_turn(bad):
    with pytest.raises(ContractError):
        check(bad)


def test_an_unknown_key_is_rejected_rather_than_ignored():
    """Silently dropping it would hide the model doing something undesigned."""
    with pytest.raises(ContractError, match="unknown keys"):
        check({**BASE, "plan": "..."})


def test_there_is_no_cap_on_action_count():
    """max_concurrent refuses a spawn that cannot run; a second limit would
    enforce the same property with its own failure modes."""
    many = [{"op": "spawn", "role": "reader"} for _ in range(50)]
    assert len(check({**BASE, "actions": many}).actions) == 50
