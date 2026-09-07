"""Tests for the admission engine."""

from __future__ import annotations

import json

import pytest

from agentserver.containment.admission import (
    AdmissionConfig,
    AdmissionEngine,
    Outcome,
    ProofOfPossession,
    Reason,
    Request,
    ToolCall,
)
from agentserver.containment.store import Store
from agentserver.crypto.keys import agent_id, generate_keypair, public_bytes
from agentserver.crypto.signing import b64u_encode, pop_message, sign
from agentserver.crypto.tokens import issue_capability_token, verify_execution_token
from agentserver.ledger.chain import Ledger
from agentserver.policy import Policy
from agentserver.tools.bindings import sign_binding, verify_binding

NOW = 1_757_200_000


@pytest.fixture
def env(tmp_path):
    """A complete containment server with one bound tool and one agent."""
    (tmp_path / "workspace" / "reports").mkdir(parents=True)
    (tmp_path / "workspace" / "reports" / "q3.md").write_text("data")
    (tmp_path / "secret.txt").write_text("secret")

    operator, issuer, agent = generate_keypair(), generate_keypair(), generate_keypair()
    policy = Policy.from_dict({
        "operators": {agent_id(operator): b64u_encode(public_bytes(operator))},
        "capabilities": {
            "cap:fs.read": {"resolver": "path_under_root"},
            "cap:net.fetch": {"resolver": "url_host"},
        },
        "roots": {"workspace": str(tmp_path / "workspace")},
    })

    def bind(**kw):
        fields = {
            "server": "fs", "tool": "read_file", "capability": "cap:fs.read",
            "resolver": "path_under_root",
            "resolver_config": {"field": "path", "root": "workspace"},
            "schema_sha256": "ab" * 32, "requires_review": False,
        }
        fields.update(kw)
        return verify_binding(policy, sign_binding(operator, **fields))

    bindings = {b.key: b for b in [
        bind(),
        bind(server="web", tool="fetch", capability="cap:net.fetch",
             resolver="url_host", resolver_config={"field": "url"}),
    ]}

    store = Store(tmp_path / "state.db")
    ledger = Ledger(tmp_path / "ledger.jsonl")
    engine = AdmissionEngine(
        store, policy, ledger, issuer, bindings,
        config=AdmissionConfig(rate_limit_count=3, rate_limit_window=60, cooldown_denials=3),
    )
    engine.register_agent(agent_id(agent), b64u_encode(public_bytes(agent)), now=NOW)

    token = issue_capability_token(
        issuer, subject=agent_id(agent), capabilities=["cap:fs.read"],
        resource="workspace/reports/**", expires_at=NOW + 3600,
    )
    yield {
        "engine": engine, "store": store, "ledger": ledger, "policy": policy,
        "issuer": issuer, "agent": agent, "operator": operator, "token": token,
        "tmp": tmp_path, "bind": bind,
    }
    store.close()


def request(env, path="reports/q3.md", *, key=None, now=NOW, server="fs", tool="read_file",
            token=None, args=None):
    engine, agent = env["engine"], key or env["agent"]
    call = ToolCall(server, tool, args if args is not None else {"path": path})
    challenge = engine.issue_challenge(now=now)
    body = json.dumps(call.action(), sort_keys=True).encode()
    sig = b64u_encode(sign(agent, pop_message(challenge, "POST", "/authorize", body)))
    return Request(
        call=call, token=token or env["token"],
        pop=ProofOfPossession(challenge, "POST", "/authorize", body, sig),
    )


def denial_count(env):
    return env["store"].one(
        "SELECT denial_count, cooldown_until FROM agents WHERE agent_id=?",
        (agent_id(env["agent"]),),
    )


# --------------------------------------------------------------------------
# the happy path
# --------------------------------------------------------------------------


def test_a_valid_call_is_approved_with_an_execution_token(env):
    d = env["engine"].evaluate(request(env), now=NOW)
    assert d.outcome is Outcome.APPROVED and d.reason is Reason.OK
    assert d.resource == "workspace/reports/q3.md"
    assert d.capability == "cap:fs.read"
    verify_execution_token(
        env["issuer"].public_key(), d.execution_token,
        subject=agent_id(env["agent"]),
        action={"server": "fs", "tool": "read_file", "args": {"path": "reports/q3.md"}},
        now=NOW,
    )


# --------------------------------------------------------------------------
# phase 1 — authentication must not move state
# --------------------------------------------------------------------------


def test_an_unauthenticated_request_cannot_lock_an_agent_out(env):
    """The attack the phase split exists to prevent.

    Three malformed requests stamped with a victim's AgentID, sent by someone
    holding no key at all, must not put that agent into cooldown.
    """
    engine = env["engine"]
    for _ in range(5):
        bad = request(env, key=generate_keypair())      # wrong signing key
        d = engine.evaluate(bad, now=NOW)
        assert d.outcome is Outcome.DENIED and d.reason is Reason.BAD_POP

    row = denial_count(env)
    assert row["denial_count"] == 0, "unauthenticated requests moved the counter"
    assert row["cooldown_until"] is None, "an attacker locked out an agent"

    # and the agent is still able to work
    assert engine.evaluate(request(env), now=NOW).outcome is Outcome.APPROVED


def test_an_unknown_agent_is_refused(env):
    stranger = generate_keypair()
    token = issue_capability_token(
        env["issuer"], subject=agent_id(stranger), capabilities=["cap:fs.read"],
        resource="workspace/**", expires_at=NOW + 3600,
    )
    d = env["engine"].evaluate(request(env, key=stranger, token=token), now=NOW)
    assert d.reason is Reason.UNKNOWN_AGENT


def test_a_token_from_another_issuer_is_refused(env):
    forged = issue_capability_token(
        generate_keypair(), subject=agent_id(env["agent"]), capabilities=["cap:fs.read"],
        resource="workspace/**", expires_at=NOW + 3600,
    )
    d = env["engine"].evaluate(request(env, token=forged), now=NOW)
    assert d.reason is Reason.BAD_SIGNATURE


def test_an_expired_token_is_refused(env):
    d = env["engine"].evaluate(request(env, now=NOW), now=NOW + 4000)
    assert d.reason is Reason.TOKEN_EXPIRED


def test_a_request_without_proof_of_possession_is_refused(env):
    req = request(env)
    d = env["engine"].evaluate(Request(call=req.call, token=req.token, pop=None), now=NOW)
    assert d.reason is Reason.BAD_POP


def test_a_replayed_challenge_is_refused(env):
    engine = env["engine"]
    req = request(env)
    assert engine.evaluate(req, now=NOW).outcome is Outcome.APPROVED
    replay = engine.evaluate(req, now=NOW)
    assert replay.reason is Reason.BAD_POP
    assert "already used" in replay.detail


def test_an_expired_challenge_is_refused(env):
    req = request(env, now=NOW)
    d = env["engine"].evaluate(req, now=NOW + 31)
    assert d.reason is Reason.BAD_POP and "expired" in d.detail


def test_a_challenge_is_spent_even_when_the_request_then_fails(env):
    """Anti-replay is not a reward for a valid request."""
    engine = env["engine"]
    req = request(env, path="../../secret.txt")
    assert engine.evaluate(req, now=NOW).reason is Reason.UNRESOLVABLE
    again = engine.evaluate(req, now=NOW)
    assert again.reason is Reason.BAD_POP


# --------------------------------------------------------------------------
# phase 2 — authorisation
# --------------------------------------------------------------------------


def test_an_unbound_tool_is_refused(env):
    d = env["engine"].evaluate(request(env, server="shell", tool="exec"), now=NOW)
    assert d.reason is Reason.TOOL_UNBOUND


def test_traversal_is_refused_as_unresolvable_not_out_of_scope(env):
    """Rule order: if the resource cannot be named there is nothing to scope-check."""
    d = env["engine"].evaluate(request(env, path="../../secret.txt"), now=NOW)
    assert d.reason is Reason.UNRESOLVABLE


def test_a_capability_the_token_does_not_grant_is_refused(env):
    d = env["engine"].evaluate(
        request(env, server="web", tool="fetch", args={"url": "https://example.com/"}), now=NOW
    )
    assert d.reason is Reason.CAPABILITY_NOT_GRANTED


def test_a_resource_outside_the_token_scope_is_refused(env):
    (env["tmp"] / "workspace" / "other.md").write_text("x")
    d = env["engine"].evaluate(request(env, path="other.md"), now=NOW)
    assert d.reason is Reason.RESOURCE_OUT_OF_SCOPE
    assert d.resource == "workspace/other.md"


@pytest.mark.parametrize(("state", "reason"),
                         [("revoked", Reason.AGENT_REVOKED), ("suspended", Reason.AGENT_SUSPENDED)])
def test_a_disabled_agent_is_refused(env, state, reason):
    env["engine"].set_agent_state(agent_id(env["agent"]), state)
    assert env["engine"].evaluate(request(env), now=NOW).reason is reason


# --------------------------------------------------------------------------
# escalation
# --------------------------------------------------------------------------


def test_a_binding_under_review_escalates_and_can_be_approved(env):
    engine = env["engine"]
    engine.bindings[("fs", "read_file")] = env["bind"](requires_review=True)
    engine.escalation_handler = lambda record: True

    d = engine.evaluate(request(env), now=NOW)
    assert d.outcome is Outcome.APPROVED
    assert d.execution_token is not None
    row = env["store"].one("SELECT state FROM escalations", ())
    assert row["state"] == "approved"


def test_a_refused_escalation_becomes_a_denial_and_counts_as_one(env):
    engine = env["engine"]
    engine.bindings[("fs", "read_file")] = env["bind"](requires_review=True)
    engine.escalation_handler = lambda record: False

    d = engine.evaluate(request(env), now=NOW)
    assert d.outcome is Outcome.DENIED and d.reason is Reason.ESCALATION_REFUSED
    assert denial_count(env)["denial_count"] == 1
    assert env["store"].one("SELECT state FROM escalations", ())["state"] == "refused"


def test_a_handler_that_raises_refuses(env):
    """Fail closed: a broken approver must not become an approver."""
    engine = env["engine"]
    engine.bindings[("fs", "read_file")] = env["bind"](requires_review=True)

    def explode(_):
        raise RuntimeError("no terminal attached")

    engine.escalation_handler = explode
    assert engine.evaluate(request(env), now=NOW).outcome is Outcome.DENIED


def test_exceeding_the_rate_limit_escalates(env):
    engine = env["engine"]
    engine.escalation_handler = lambda record: False
    outcomes = [engine.evaluate(request(env), now=NOW).outcome for _ in range(5)]
    assert outcomes[:3] == [Outcome.APPROVED] * 3
    assert Outcome.DENIED in outcomes[3:]   # escalated, then refused


def test_the_rate_window_slides(env):
    """Calls outside the trailing window do not count toward it."""
    engine = env["engine"]
    for i in range(3):
        assert engine.evaluate(request(env, now=NOW + i), now=NOW + i).outcome is Outcome.APPROVED
    later = NOW + 61
    assert engine.evaluate(request(env, now=later), now=later).outcome is Outcome.APPROVED


# --------------------------------------------------------------------------
# cooldown
# --------------------------------------------------------------------------


def test_repeated_denials_start_a_cooldown_that_then_blocks_everything(env):
    engine = env["engine"]
    (env["tmp"] / "workspace" / "other.md").write_text("x")
    for _ in range(3):
        assert engine.evaluate(request(env, path="other.md"), now=NOW).reason is Reason.RESOURCE_OUT_OF_SCOPE

    row = denial_count(env)
    assert row["cooldown_until"] == NOW + 300
    assert row["denial_count"] == 0, "the counter must reset with the lock"

    blocked = engine.evaluate(request(env), now=NOW + 1)
    assert blocked.reason is Reason.COOLDOWN_ACTIVE

    freed = engine.evaluate(request(env, now=NOW + 301), now=NOW + 301)
    assert freed.outcome is Outcome.APPROVED


# --------------------------------------------------------------------------
# dry run — the counterfactual probe must not trip what it measures
# --------------------------------------------------------------------------


def test_a_dry_run_decides_without_writing_anything(env):
    engine, store, ledger = env["engine"], env["store"], env["ledger"]
    before = (
        len(ledger),
        store.one("SELECT COUNT(*) AS n FROM pattern_events", ())["n"],
        denial_count(env)["denial_count"],
    )
    (env["tmp"] / "workspace" / "other.md").write_text("x")

    assert engine.evaluate(request(env), now=NOW, dry_run=True).outcome is Outcome.APPROVED
    for _ in range(5):
        d = engine.evaluate(request(env, path="other.md"), now=NOW, dry_run=True)
        assert d.reason is Reason.RESOURCE_OUT_OF_SCOPE

    after = (
        len(ledger),
        store.one("SELECT COUNT(*) AS n FROM pattern_events", ())["n"],
        denial_count(env)["denial_count"],
    )
    assert before == after, "probing the boundary changed the state it measures"
    assert denial_count(env)["cooldown_until"] is None


def test_a_dry_run_still_reports_that_denial_is_reachable(env):
    """The counterfactual property: DENIED must remain producible."""
    (env["tmp"] / "workspace" / "other.md").write_text("x")
    d = env["engine"].evaluate(request(env, path="other.md"), now=NOW, dry_run=True)
    assert d.outcome is Outcome.DENIED


# --------------------------------------------------------------------------
# the ledger
# --------------------------------------------------------------------------


def test_every_decision_is_recorded_with_its_reason(env):
    engine = env["engine"]
    (env["tmp"] / "workspace" / "other.md").write_text("x")
    engine.evaluate(request(env), now=NOW)
    engine.evaluate(request(env, path="other.md"), now=NOW)
    engine.evaluate(request(env, key=generate_keypair()), now=NOW)

    entries = [e for e in env["ledger"] if e["type"] == "authorization"]
    assert [e["data"]["reason"] for e in entries] == [
        "ok", "resource_out_of_scope", "bad_pop",
    ]
    assert [e["data"]["authenticated"] for e in entries] == [True, True, False]
    assert env["ledger"].verify() == len(env["ledger"])
