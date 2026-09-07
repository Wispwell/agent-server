"""Tests for the M0 crypto floor: canonicalization, identity, signing."""

from __future__ import annotations

import os

import pytest

from agentserver.crypto.canonical import (
    MAX_SAFE_INTEGER,
    CanonicalizationError,
    canonicalize,
)
from agentserver.crypto.keys import (
    AGENT_ID_ALPHABET,
    agent_id,
    b58decode,
    b58encode,
    generate_keypair,
    load_private_key,
    public_bytes,
    public_key_from_bytes,
    save_private_key,
)
from agentserver.crypto.signing import (
    b64u_decode,
    b64u_encode,
    new_challenge,
    pop_message,
    sign,
    sign_object,
    verify,
    verify_object,
)

# --------------------------------------------------------------------------
# canonicalization
# --------------------------------------------------------------------------


def test_returns_utf8_bytes():
    assert canonicalize({"a": "é"}) == b'{"a":"\xc3\xa9"}'


def test_insertion_order_is_irrelevant():
    a = {"b": 1, "a": 2, "c": 3}
    b = {"c": 3, "a": 2, "b": 1}
    assert canonicalize(a) == canonicalize(b) == b'{"a":2,"b":1,"c":3}'


def test_no_insignificant_whitespace():
    out = canonicalize({"a": [1, 2], "b": {"c": 3}})
    assert out == b'{"a":[1,2],"b":{"c":3}}'
    assert b" " not in out


def test_keys_sort_by_utf16_code_unit_not_code_point():
    """RFC 8785 sorts by UTF-16 code unit, which is NOT Python's native order.

    U+FF3A is one code unit (0xFF3A). U+1F600 is a surrogate pair whose first
    unit is 0xD83D. So the astral character sorts FIRST under UTF-16, and last
    under code-point ordering. Sorting naively puts these the wrong way round.
    """
    obj = {"Ｚ": 1, "\U0001f600": 2}
    out = canonicalize(obj).decode()
    assert out.index("\U0001f600") < out.index("Ｚ")
    # and confirm that is genuinely the opposite of Python's default
    assert sorted(obj) == ["Ｚ", "\U0001f600"]


def test_short_escapes_and_control_characters():
    out = canonicalize({"k": '\n\t\r\b\f"\\'}).decode()
    assert out == '{"k":"\\n\\t\\r\\b\\f\\"\\\\"}'
    # control characters without a short escape use lowercase \u00xx
    assert canonicalize({"k": "\x01\x1f"}).decode() == '{"k":"\\u0001\\u001f"}'


def test_non_ascii_is_not_escaped():
    assert canonicalize({"k": "€ö"}).decode() == '{"k":"€ö"}'


def test_floats_are_rejected():
    with pytest.raises(CanonicalizationError, match="float"):
        canonicalize({"n": 1.5})


def test_integers_beyond_double_precision_are_rejected():
    assert canonicalize({"n": MAX_SAFE_INTEGER}) == b'{"n":9007199254740991}'
    with pytest.raises(CanonicalizationError, match="IEEE-754"):
        canonicalize({"n": MAX_SAFE_INTEGER + 1})


def test_bools_and_null_are_not_numbers():
    assert canonicalize({"a": True, "b": False, "c": None}) == b'{"a":true,"b":false,"c":null}'


def test_non_string_keys_and_unknown_types_are_rejected():
    with pytest.raises(CanonicalizationError):
        canonicalize({1: "x"})
    with pytest.raises(CanonicalizationError):
        canonicalize({"k": {1, 2}})


def test_nested_structures_are_canonical_throughout():
    obj = {"z": [{"b": 1, "a": 2}], "a": {"d": [3, 2, 1]}}
    assert canonicalize(obj) == b'{"a":{"d":[3,2,1]},"z":[{"a":2,"b":1}]}'


# --------------------------------------------------------------------------
# identity
# --------------------------------------------------------------------------


def test_base58_roundtrip_including_leading_zero_bytes():
    for raw in (b"", b"\x00", b"\x00\x00\x01", os.urandom(32), b"\xff" * 32):
        assert b58decode(b58encode(raw)) == raw


def test_base58_rejects_out_of_alphabet_characters():
    for bad in "0OIl":
        assert bad not in AGENT_ID_ALPHABET
        with pytest.raises(ValueError):
            b58decode("1" + bad)


def test_agent_id_is_deterministic_and_key_derived():
    key = generate_keypair()
    assert agent_id(key) == agent_id(key.public_key()) == agent_id(key)
    assert agent_id(generate_keypair()) != agent_id(key)


def test_agent_id_shape():
    for _ in range(20):
        aid = agent_id(generate_keypair())
        assert 43 <= len(aid) <= 44
        assert set(aid) <= set(AGENT_ID_ALPHABET)


def test_public_bytes_accepts_either_half():
    key = generate_keypair()
    assert public_bytes(key) == public_bytes(key.public_key())
    assert len(public_bytes(key)) == 32


def test_private_key_is_saved_owner_only_and_round_trips(tmp_path):
    key = generate_keypair()
    path = save_private_key(key, tmp_path / "sub" / "agent.key")
    assert path.stat().st_mode & 0o777 == 0o600
    assert agent_id(load_private_key(path)) == agent_id(key)


def test_loading_a_world_readable_key_is_refused(tmp_path):
    path = save_private_key(generate_keypair(), tmp_path / "agent.key")
    os.chmod(path, 0o644)
    with pytest.raises(PermissionError, match="loose permissions"):
        load_private_key(path)


# --------------------------------------------------------------------------
# signing
# --------------------------------------------------------------------------


def test_base64url_roundtrip_has_no_padding():
    for raw in (b"", b"\x00", os.urandom(64)):
        encoded = b64u_encode(raw)
        assert "=" not in encoded
        assert b64u_decode(encoded) == raw


def test_sign_and_verify_roundtrip():
    key = generate_keypair()
    sig = sign(key, b"payload")
    assert len(sig) == 64
    assert verify(key.public_key(), b"payload", sig)


def test_verify_rejects_tampering_and_wrong_keys_without_raising():
    key, other = generate_keypair(), generate_keypair()
    sig = sign(key, b"payload")
    assert not verify(key.public_key(), b"payload!", sig)
    assert not verify(other.public_key(), b"payload", sig)
    assert not verify(key.public_key(), b"payload", b"garbage")


def test_sign_object_roundtrip_and_no_mutation():
    key = generate_keypair()
    original = {"sub": "abc", "cap": ["cap:fs.read"], "exp": 1757200000}
    snapshot = dict(original)
    signed = sign_object(key, original)
    assert original == snapshot, "sign_object must not mutate its input"
    assert "sig" in signed
    assert verify_object(key.public_key(), signed)


def test_object_signature_is_independent_of_key_order():
    key = generate_keypair()
    a = sign_object(key, {"a": 1, "b": 2})
    b = sign_object(key, {"b": 2, "a": 1})
    assert a["sig"] == b["sig"]


def test_any_field_change_breaks_the_object_signature():
    key = generate_keypair()
    signed = sign_object(key, {"sub": "abc", "cap": ["cap:fs.read"]})
    for mutation in (
        {"sub": "abd"},
        {"cap": ["cap:fs.write"]},
        {"extra": 1},
    ):
        assert not verify_object(key.public_key(), {**signed, **mutation})


def test_missing_or_malformed_signature_is_a_failure_not_an_error():
    pub = generate_keypair().public_key()
    assert not verify_object(pub, {"sub": "abc"})
    assert not verify_object(pub, {"sub": "abc", "sig": None})
    assert not verify_object(pub, {"sub": "abc", "sig": "!!!not base64!!!"})
    assert not verify_object(pub, {"sub": "abc", "sig": b64u_encode(b"short")})


def test_signature_verifies_against_a_reconstructed_public_key():
    """A verifier only ever has the registered 32 raw bytes, not the object."""
    key = generate_keypair()
    signed = sign_object(key, {"sub": "abc"})
    assert verify_object(public_key_from_bytes(public_bytes(key)), signed)


# --------------------------------------------------------------------------
# proof of possession
# --------------------------------------------------------------------------


def test_challenges_are_unique_and_128_bit():
    seen = {new_challenge() for _ in range(200)}
    assert len(seen) == 200
    assert all(len(b64u_decode(c)) == 16 for c in seen)


def test_pop_message_binds_every_component():
    base = pop_message("chal", "POST", "/authorize", b"body")
    assert pop_message("other", "POST", "/authorize", b"body") != base
    assert pop_message("chal", "GET", "/authorize", b"body") != base
    assert pop_message("chal", "POST", "/other", b"body") != base
    assert pop_message("chal", "POST", "/authorize", b"body2") != base
    assert pop_message("chal", "post", "/authorize", b"body") == base


def test_pop_message_framing_is_unambiguous():
    """Naive concatenation would let a crafted path forge another request.

    challenge='a', path='/b/c' must not collide with challenge='a/b', path='c'
    or any similar re-split of the same characters.
    """
    assert pop_message("a", "GET", "/b/c") != pop_message("a/b", "GET", "/c")
    assert pop_message("a", "GET", "") != pop_message("", "GET", "a")


def test_pop_signature_round_trip():
    key = generate_keypair()
    challenge = new_challenge()
    msg = pop_message(challenge, "POST", "/acp/v1/authorize", b'{"x":1}')
    sig = sign(key, msg)
    assert verify(key.public_key(), msg, sig)
    replayed = pop_message(new_challenge(), "POST", "/acp/v1/authorize", b'{"x":1}')
    assert not verify(key.public_key(), replayed, sig)
