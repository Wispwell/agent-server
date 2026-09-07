"""Tests for the trust root and signed tool bindings."""

from __future__ import annotations

import json

import pytest

from agentserver.containment.store import Store
from agentserver.crypto.keys import agent_id, generate_keypair, public_bytes
from agentserver.crypto.signing import b64u_encode
from agentserver.policy import Policy, PolicyError
from agentserver.tools.bindings import (
    BindingError,
    ResolverMismatch,
    UnknownCapability,
    UnknownOperator,
    UnsignedBinding,
    load_bindings,
    sign_binding,
    verify_binding,
)
from agentserver.tools.resolvers import ResolutionError


@pytest.fixture
def operator():
    return generate_keypair()


@pytest.fixture
def policy(operator, tmp_path):
    (tmp_path / "workspace").mkdir()
    return Policy.from_dict(
        {
            "operators": {agent_id(operator): b64u_encode(public_bytes(operator))},
            "capabilities": {
                "cap:fs.read": {"resolver": "path_under_root"},
                "cap:net.fetch": {"resolver": "url_host"},
            },
            "roots": {"workspace": str(tmp_path / "workspace")},
        }
    )


def make_row(operator, **kw):
    fields = {
        "server": "fs",
        "tool": "read_file",
        "capability": "cap:fs.read",
        "resolver": "path_under_root",
        "resolver_config": {"field": "path", "root": "workspace"},
        "schema_sha256": "9f2c" * 16,
    }
    fields.update(kw)
    return sign_binding(operator, **fields)


# --------------------------------------------------------------------------
# trust root
# --------------------------------------------------------------------------


def test_policy_requires_at_least_one_operator(tmp_path):
    with pytest.raises(PolicyError, match="no operator keys"):
        Policy.from_dict({"capabilities": {"cap:x": {"resolver": "url_host"}}})


def test_policy_rejects_a_capability_naming_an_unknown_resolver(operator):
    with pytest.raises(PolicyError, match="unknown resolver"):
        Policy.from_dict({
            "operators": {agent_id(operator): b64u_encode(public_bytes(operator))},
            "capabilities": {"cap:shell.exec": {"resolver": "eval_python"}},
        })


def test_policy_rejects_an_unusable_operator_key(operator):
    with pytest.raises(PolicyError, match="unusable public key"):
        Policy.from_dict({
            "operators": {"whoever": "not-a-key"},
            "capabilities": {"cap:x": {"resolver": "url_host"}},
        })


# --------------------------------------------------------------------------
# signature is the authorisation
# --------------------------------------------------------------------------


def test_a_properly_signed_binding_verifies(policy, operator):
    binding = verify_binding(policy, make_row(operator))
    assert binding.key == ("fs", "read_file")
    assert binding.capability == "cap:fs.read"
    assert binding.issued_by == agent_id(operator)


def test_a_new_binding_is_born_requiring_review(policy, operator):
    """A mistaken binding should cost a prompt, not a breach."""
    assert verify_binding(policy, make_row(operator)).requires_review is True


def test_an_unsigned_row_is_not_authority(policy, operator):
    row = make_row(operator)
    del row["sig"]
    with pytest.raises(UnsignedBinding):
        verify_binding(policy, row)


def test_a_row_signed_by_a_stranger_is_not_authority(policy):
    """The whole point: writing the database is not the same as being trusted."""
    with pytest.raises(UnknownOperator):
        verify_binding(policy, make_row(generate_keypair()))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("capability", "cap:net.fetch"),
        ("resolver_config", {"field": "path", "root": "etc"}),
        ("schema_sha256", "0" * 64),
        ("requires_review", False),
        ("enabled", False),
        ("tool", "write_file"),
        ("credential_ref", "prod-token"),
    ],
)
def test_every_field_is_covered_by_the_signature(policy, operator, field, value):
    row = {**make_row(operator), field: value}
    with pytest.raises(UnsignedBinding, match="not valid"):
        verify_binding(policy, row)


def test_promotion_out_of_review_requires_a_fresh_signature(policy, operator):
    """Flipping requires_review in the database must not silently take effect."""
    row = make_row(operator)
    tampered = {**row, "requires_review": False}
    with pytest.raises(UnsignedBinding):
        verify_binding(policy, tampered)
    promoted = make_row(operator, requires_review=False)
    assert verify_binding(policy, promoted).requires_review is False


# --------------------------------------------------------------------------
# what a signed binding still cannot do
# --------------------------------------------------------------------------


def test_a_binding_cannot_name_an_undeclared_capability(policy, operator):
    with pytest.raises(UnknownCapability):
        verify_binding(policy, make_row(operator, capability="cap:shell.exec"))


def test_a_binding_cannot_pair_a_capability_with_the_wrong_resolver(policy, operator):
    """This is what stops `shell.exec` being bound to a capability agents hold:
    a tool with no nameable resource has no resolver its capability accepts."""
    row = make_row(operator, capability="cap:fs.read", resolver="literal_field",
                   resolver_config={"field": "command"})
    with pytest.raises(ResolverMismatch):
        verify_binding(policy, row)


def test_resource_extraction_still_applies_to_a_valid_binding(policy, operator):
    binding = verify_binding(policy, make_row(operator))
    assert binding.resource_for({"path": "notes.md"}, policy) == "workspace/notes.md"
    with pytest.raises(ResolutionError):
        binding.resource_for({"path": "../../etc/passwd"}, policy)


# --------------------------------------------------------------------------
# loading from the store
# --------------------------------------------------------------------------


def insert(store, row):
    stored = dict(row)
    stored["resolver_config"] = json.dumps(stored["resolver_config"])
    stored["requires_review"] = int(stored["requires_review"])
    stored["enabled"] = int(stored["enabled"])
    cols = ", ".join(stored)
    marks = ", ".join("?" * len(stored))
    with store.write() as conn:
        conn.execute(f"INSERT INTO bindings ({cols}) VALUES ({marks})", tuple(stored.values()))


def test_loading_accepts_valid_rows_and_reports_the_rest(policy, operator, tmp_path):
    store = Store(tmp_path / "state.db")
    insert(store, make_row(operator))
    insert(store, make_row(operator, server="web", tool="fetch",
                           capability="cap:net.fetch", resolver="url_host",
                           resolver_config={"field": "url"}))
    insert(store, make_row(generate_keypair(), server="evil", tool="exfil"))

    accepted, rejected = load_bindings(store, policy)

    assert set(accepted) == {("fs", "read_file"), ("web", "fetch")}
    assert [ident for ident, _ in rejected] == [("evil", "exfil")]
    assert isinstance(rejected[0][1], UnknownOperator)
    store.close()


def test_one_bad_row_does_not_blind_the_system_to_the_others(policy, operator, tmp_path):
    store = Store(tmp_path / "state.db")
    bad = make_row(operator, server="broken", tool="t")
    bad["sig"] = "!!!"
    insert(store, bad)
    insert(store, make_row(operator))

    accepted, rejected = load_bindings(store, policy)
    assert ("fs", "read_file") in accepted
    assert len(rejected) == 1
    assert isinstance(rejected[0][1], BindingError)
    store.close()


def test_disabled_bindings_are_loaded_but_not_offered(policy, operator, tmp_path):
    store = Store(tmp_path / "state.db")
    insert(store, make_row(operator, enabled=False))
    accepted, rejected = load_bindings(store, policy)
    assert accepted == {} and rejected == []
    store.close()


def test_resolver_config_survives_the_json_round_trip(policy, operator, tmp_path):
    store = Store(tmp_path / "state.db")
    insert(store, make_row(operator))
    accepted, _ = load_bindings(store, policy)
    binding = accepted[("fs", "read_file")]
    assert binding.resolver_config == {"field": "path", "root": "workspace"}
    store.close()
