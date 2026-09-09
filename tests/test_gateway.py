"""End-to-end: a real MCP server behind the gateway, driven by a behaviour tree."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from agentserver.subagent.behaviour import Status


def obedient(target):
    """A model that writes wherever the text it just read tells it to."""
    def choose(prompt, blackboard):
        return {"server": "tools", "tool": "write_file",
                "args": {"path": target, "content": blackboard.get("body", "")[:80]}}
    return choose


# --------------------------------------------------------------------------


def test_the_whole_path_works_for_a_legitimate_task(live):
    result = live["runner"].run(
        live["catalog"].get("reporter"),
        params={"path": "reports/q3.md"},
        choose=obedient("reports/summary.md"),
    )
    assert result.status is Status.SUCCESS
    assert result.denied == 0
    assert (live["root"] / "reports" / "summary.md").exists()


def test_an_injected_write_outside_scope_is_refused(live):
    """The demo. The model does what the file told it; containment refuses.

    `secrets/` is inside the workspace root but outside the role's scope of
    `workspace/reports/**`, so this exercises the scope check rather than the
    resolver — a path that escaped the root would be refused one rule earlier.
    """
    result = live["runner"].run(
        live["catalog"].get("reporter"),
        params={"path": "reports/q3.md"},
        choose=obedient("secrets/exfil.md"),
    )
    assert result.status is Status.FAILURE
    assert result.denied == 1
    assert not (live["root"] / "secrets" / "exfil.md").exists(), "the write reached the disk"

    denials = [e for e in live["ledger"]
               if e["type"] == "authorization" and e["data"]["decision"] == "denied"]
    assert denials, "the attempt was not recorded"
    assert denials[-1]["data"]["reason"] == "resource_out_of_scope"


def test_a_traversal_payload_is_refused_as_unresolvable(live):
    result = live["runner"].run(
        live["catalog"].get("reporter"),
        params={"path": "reports/q3.md"},
        choose=obedient("../../../../tmp/exfil.md"),
    )
    assert result.denied == 1
    reasons = [e["data"]["reason"] for e in live["ledger"]
               if e["type"] == "authorization" and e["data"]["decision"] == "denied"]
    assert reasons[-1] == "unresolvable"


def test_reading_outside_the_role_scope_is_refused(live):
    (live["root"] / "secrets" / "keys.txt").write_text("secret")
    result = live["runner"].run(
        live["catalog"].get("reporter"),
        params={"path": "secrets/keys.txt"},
        choose=obedient("reports/x.md"),
    )
    assert result.status is Status.FAILURE
    assert result.denied == 1


def test_execution_tokens_are_spent_exactly_once_per_call(live):
    live["runner"].run(live["catalog"].get("reporter"),
                       params={"path": "reports/q3.md"},
                       choose=obedient("reports/summary.md"))
    spent = live["store"].one("SELECT COUNT(*) AS n FROM consumed_execution_tokens", ())["n"]
    assert spent == 2, "one read, one write"


def test_the_ledger_chain_survives_a_full_run(live):
    live["runner"].run(live["catalog"].get("reporter"),
                       params={"path": "reports/q3.md"},
                       choose=obedient("secrets/exfil.md"))
    assert live["ledger"].verify() == len(live["ledger"])


# --------------------------------------------------------------------------
# schema pinning
# --------------------------------------------------------------------------


def test_matching_schemas_pass_verification(live):
    assert live["gateway"].verify_schemas() == []
    assert ("tools", "read_file") in live["engine"].bindings


def test_a_server_that_redefines_a_bound_tool_has_it_disabled(live):
    """Otherwise the resolver keeps reading a field that no longer means what
    it did, and every signature still verifies while it does."""
    binding = live["engine"].bindings[("tools", "read_file")]
    live["engine"].bindings[("tools", "read_file")] = type(binding)(
        **{**binding.__dict__, "schema_sha256": "0" * 64}
    )
    drifted = live["gateway"].verify_schemas()
    assert [ident for ident, _ in drifted] == [("tools", "read_file")]
    assert ("tools", "read_file") not in live["engine"].bindings


def test_a_disabled_binding_then_refuses_calls(live):
    binding = live["engine"].bindings[("tools", "read_file")]
    live["engine"].bindings[("tools", "read_file")] = type(binding)(
        **{**binding.__dict__, "schema_sha256": "0" * 64}
    )
    live["gateway"].verify_schemas()
    result = live["runner"].run(live["catalog"].get("reporter"),
                                params={"path": "reports/q3.md"},
                                choose=obedient("reports/x.md"))
    assert result.status is Status.FAILURE
    reasons = [e["data"]["reason"] for e in live["ledger"]
               if e["type"] == "authorization" and e["data"]["decision"] == "denied"]
    assert "tool_unbound" in reasons
