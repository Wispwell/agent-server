"""Tests for M0 capability and execution tokens."""

from __future__ import annotations

import pytest

from agentserver.crypto.keys import agent_id, generate_keypair
from agentserver.crypto.tokens import (
    DelegationError,
    ExpiredError,
    MalformedError,
    ScopeError,
    SignatureError,
    TokenError,
    capability_covers,
    check_delegation,
    issue_capability_token,
    issue_execution_token,
    resource_matches,
    token_hash,
    verify_capability_token,
    verify_execution_token,
)

NOW = 1_757_200_000


@pytest.fixture
def issuer():
    return generate_keypair()


def make_ct(issuer, **kw):
    params = {
        "subject": "subagent-1",
        "capabilities": ["cap:fs.read"],
        "resource": "workspace/**",
        "expires_at": NOW + 600,
    }
    params.update(kw)
    return issue_capability_token(issuer, **params)


# --------------------------------------------------------------------------
# capability tokens
# --------------------------------------------------------------------------


def test_issue_and_verify_round_trip(issuer):
    token = make_ct(issuer)
    assert verify_capability_token(issuer.public_key(), token, now=NOW) is token
    assert token["iss"] == agent_id(issuer)
    assert token["typ"] == "ct"
    assert token["cap"] == ["cap:fs.read"]


def test_capabilities_are_deduplicated_and_ordered(issuer):
    token = make_ct(issuer, capabilities=["cap:b", "cap:a", "cap:b"])
    assert token["cap"] == ["cap:a", "cap:b"]


def test_every_field_is_covered_by_the_signature(issuer):
    token = make_ct(issuer)
    for field, value in [
        ("sub", "someone-else"),
        ("res", "/"),
        ("exp", NOW + 999_999),
        ("cap", ["cap:fs.write"]),
    ]:
        with pytest.raises(SignatureError):
            verify_capability_token(issuer.public_key(), {**token, field: value}, now=NOW)


def test_a_token_from_another_issuer_is_refused(issuer):
    assert verify_capability_token  # sanity
    with pytest.raises(SignatureError):
        verify_capability_token(generate_keypair().public_key(), make_ct(issuer), now=NOW)


def test_expiry_is_enforced(issuer):
    token = make_ct(issuer, expires_at=NOW - 1)
    with pytest.raises(ExpiredError):
        verify_capability_token(issuer.public_key(), token, now=NOW)


def test_expiry_is_exclusive_at_the_boundary(issuer):
    token = make_ct(issuer, expires_at=NOW)
    with pytest.raises(ExpiredError):
        verify_capability_token(issuer.public_key(), token, now=NOW)
    assert verify_capability_token(issuer.public_key(), token, now=NOW - 1)


def test_a_token_granting_nothing_is_refused_at_issue(issuer):
    with pytest.raises(MalformedError):
        make_ct(issuer, capabilities=[])


def test_delegable_without_depth_is_refused_at_issue(issuer):
    with pytest.raises(MalformedError, match="max_depth"):
        make_ct(issuer, delegable=True, max_depth=0)


def test_signature_is_checked_before_anything_semantic(issuer):
    """A malformed token with a bad signature must fail as a signature error."""
    token = make_ct(issuer)
    del token["exp"]
    with pytest.raises(SignatureError):
        verify_capability_token(issuer.public_key(), token, now=NOW)


def test_wrong_token_type_is_malformed(issuer):
    et = issue_execution_token(
        issuer, subject="s", capability="cap:fs.read",
        resource="workspace/a", action={"x": 1}, now=NOW,
    )
    with pytest.raises(MalformedError, match="typ"):
        verify_capability_token(issuer.public_key(), et, now=NOW)


def test_every_refusal_carries_a_reason_code():
    for err in (MalformedError, SignatureError, ExpiredError, ScopeError, DelegationError):
        assert issubclass(err, TokenError)
        assert isinstance(err.reason, str) and err.reason


# --------------------------------------------------------------------------
# scope
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "resource", "expected"),
    [
        ("workspace/**", "workspace/a/b.md", True),
        ("workspace/**", "workspace/a.md", True),
        ("workspace/*", "workspace/a.md", True),
        ("workspace/*", "workspace/a/b.md", False),   # * must not cross a separator
        ("workspace/a", "workspace/a", True),
        ("workspace/a", "workspace/ab", False),        # anchored at the end
        ("workspace/a", "xworkspace/a", False),        # anchored at the start
        ("**", "anything/at/all", True),
    ],
)
def test_resource_pattern_matching(pattern, resource, expected):
    assert resource_matches(pattern, resource) is expected


def test_capability_covers_requires_both_capability_and_scope(issuer):
    token = make_ct(issuer, capabilities=["cap:fs.read"], resource="workspace/**")
    assert capability_covers(token, "cap:fs.read", "workspace/a.md")
    assert not capability_covers(token, "cap:fs.write", "workspace/a.md")
    assert not capability_covers(token, "cap:fs.read", "etc/passwd")


# --------------------------------------------------------------------------
# delegation
# --------------------------------------------------------------------------


def make_pair(issuer, *, child_kw=None, parent_kw=None):
    parent = make_ct(issuer, delegable=True, max_depth=1,
                     capabilities=["cap:fs.read", "cap:fs.write"], **(parent_kw or {}))
    kw = {
        "subject": "grandchild",
        "capabilities": ["cap:fs.read"],
        "resource": "workspace/**",
        "expires_at": parent["exp"],
        "parent_hash": token_hash(parent),
    }
    kw.update(child_kw or {})
    return parent, issue_capability_token(issuer, **kw)


def test_a_proper_delegation_is_accepted(issuer):
    parent, child = make_pair(issuer)
    check_delegation(parent, child)


def test_delegation_must_chain_to_the_actual_parent(issuer):
    parent, _ = make_pair(issuer)
    _, orphan = make_pair(issuer, child_kw={"parent_hash": "0" * 64})
    with pytest.raises(DelegationError, match="chain"):
        check_delegation(parent, orphan)


def test_a_non_delegable_parent_cannot_delegate(issuer):
    parent = make_ct(issuer)  # delegable=False
    child = issue_capability_token(
        issuer, subject="c", capabilities=["cap:fs.read"], resource="workspace/**",
        expires_at=parent["exp"], parent_hash=token_hash(parent),
    )
    with pytest.raises(DelegationError, match="not delegable"):
        check_delegation(parent, child)


def test_delegation_cannot_add_capabilities(issuer):
    parent, child = make_pair(issuer, child_kw={"capabilities": ["cap:fs.read", "cap:net.send"]})
    with pytest.raises(DelegationError, match="capabilities the parent lacks"):
        check_delegation(parent, child)


def test_delegation_cannot_widen_scope(issuer):
    parent, child = make_pair(
        issuer, parent_kw={"resource": "workspace/reports/**"}, child_kw={"resource": "workspace/**"}
    )
    with pytest.raises(DelegationError, match="scope"):
        check_delegation(parent, child)


def test_delegation_cannot_outlive_its_parent(issuer):
    parent, child = make_pair(issuer, child_kw={"expires_at": NOW + 6000})
    with pytest.raises(DelegationError, match="outlives"):
        check_delegation(parent, child)


def test_delegation_depth_is_consumed(issuer):
    parent, child = make_pair(issuer, child_kw={"delegable": True, "max_depth": 1})
    with pytest.raises(DelegationError, match="depth"):
        check_delegation(parent, child)


def test_narrowing_to_a_concrete_resource_is_accepted(issuer):
    parent, child = make_pair(
        issuer, parent_kw={"resource": "workspace/**"},
        child_kw={"resource": "workspace/reports/q3.md"},
    )
    check_delegation(parent, child)


def test_conservative_scope_check_refuses_some_valid_narrowings(issuer):
    """Documented deliberate limitation, asserted so it is visible.

    ``workspace/reports/**`` really is narrower than ``workspace/**``, but
    deciding glob containment in general is not something to get subtly wrong
    in an authority check. A false refusal costs a failed spawn; a false
    acceptance is privilege escalation.
    """
    parent, child = make_pair(
        issuer, parent_kw={"resource": "workspace/**"},
        child_kw={"resource": "workspace/reports/**"},
    )
    with pytest.raises(DelegationError, match="scope"):
        check_delegation(parent, child)


# --------------------------------------------------------------------------
# execution tokens
# --------------------------------------------------------------------------

ACTION = {"tool": "fs.read", "args": {"path": "workspace/a.md"}}


def make_et(issuer, **kw):
    params = {
        "subject": "subagent-1",
        "capability": "cap:fs.read",
        "resource": "workspace/a.md",
        "action": ACTION,
        "now": NOW,
    }
    params.update(kw)
    return issue_execution_token(issuer, **params)


def test_execution_token_round_trip(issuer):
    et = make_et(issuer)
    assert verify_execution_token(
        issuer.public_key(), et, subject="subagent-1", action=ACTION, now=NOW
    ) is et
    assert et["typ"] == "et"
    assert et["exp"] > et["iat"]


def test_execution_tokens_are_individually_identified(issuer):
    """`id` is what the issuer records as consumed; two must never collide."""
    ids = {make_et(issuer)["id"] for _ in range(50)}
    assert len(ids) == 50


def test_an_execution_token_is_bound_to_its_action(issuer):
    et = make_et(issuer)
    other = {"tool": "fs.read", "args": {"path": "etc/passwd"}}
    with pytest.raises(ScopeError, match="action"):
        verify_execution_token(
            issuer.public_key(), et, subject="subagent-1", action=other, now=NOW
        )


def test_an_execution_token_is_bound_to_its_bearer(issuer):
    et = make_et(issuer)
    with pytest.raises(ScopeError, match="not issued to this agent"):
        verify_execution_token(
            issuer.public_key(), et, subject="subagent-2", action=ACTION, now=NOW
        )


def test_an_expired_execution_token_is_invalid_even_if_never_used(issuer):
    et = make_et(issuer, ttl=30)
    with pytest.raises(ExpiredError):
        verify_execution_token(
            issuer.public_key(), et, subject="subagent-1", action=ACTION, now=NOW + 31
        )


def test_execution_token_fields_are_covered_by_the_signature(issuer):
    et = make_et(issuer)
    for field, value in [("sub", "other"), ("cap", "cap:fs.write"), ("exp", NOW + 99999)]:
        with pytest.raises(SignatureError):
            verify_execution_token(
                issuer.public_key(), {**et, field: value},
                subject=et["sub"], action=ACTION, now=NOW,
            )
