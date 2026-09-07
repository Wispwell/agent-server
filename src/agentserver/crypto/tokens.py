"""Capability and Execution tokens. M0.

**CapabilityToken** — issued when a subagent is bound. States what an agent may
do, on what resource, until when, and whether it may delegate. `exp` is
mandatory: a token without expiry is invalid by definition.

**ExecutionToken** — issued per approved action. Single-use, short-lived, and
names exactly one capability on one concrete resource, bound to the hash of the
action itself. The ET, not the ledger, is the artifact that gates state
mutation: the gateway attaches real credentials only when presented with one.

Errors carry a `reason` code rather than only a message, because every refusal
is written to the ledger and the reason is what the evals count.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import time
from typing import Any

from .canonical import canonicalize
from .keys import agent_id
from .signing import b64u_encode, sign_object, verify_object

__all__ = [
    "CAPABILITY_TOKEN_VERSION",
    "DEFAULT_EXECUTION_TOKEN_TTL",
    "EXECUTION_TOKEN_VERSION",
    "DelegationError",
    "ExpiredError",
    "MalformedError",
    "ScopeError",
    "SignatureError",
    "TokenError",
    "action_hash",
    "capability_covers",
    "check_delegation",
    "issue_capability_token",
    "issue_execution_token",
    "new_nonce",
    "resource_matches",
    "token_hash",
    "verify_capability_token",
    "verify_execution_token",
]

CAPABILITY_TOKEN_VERSION = "1.0"
EXECUTION_TOKEN_VERSION = "1.0"
DEFAULT_EXECUTION_TOKEN_TTL = 30  # seconds; an ET should outlive one round trip


class TokenError(Exception):
    """Base for every token refusal. `reason` is what reaches the ledger."""

    reason = "token_error"


class MalformedError(TokenError):
    reason = "malformed"


class SignatureError(TokenError):
    reason = "bad_signature"


class ExpiredError(TokenError):
    reason = "expired"


class ScopeError(TokenError):
    reason = "out_of_scope"


class DelegationError(TokenError):
    reason = "bad_delegation"


def _now(now: int | None) -> int:
    return int(time.time()) if now is None else now


def new_nonce() -> str:
    """128-bit CSPRNG nonce, base64url. Makes otherwise-identical tokens distinct."""
    return b64u_encode(secrets.token_bytes(16))


def token_hash(token: dict[str, Any]) -> str:
    """SHA-256 of the token's canonical form, hex. Used as `parent_hash`."""
    return hashlib.sha256(canonicalize(token)).hexdigest()


def action_hash(action: dict[str, Any]) -> str:
    """SHA-256 of the canonical action, hex. Binds an ET to one exact call."""
    return hashlib.sha256(canonicalize(action)).hexdigest()


# --------------------------------------------------------------------------
# resource patterns
# --------------------------------------------------------------------------

_PATTERN_TOKEN = re.compile(r"\*\*|\*|[^*]+")


def _pattern_to_regex(pattern: str) -> re.Pattern[str]:
    """`*` matches within one path segment, `**` matches across segments."""
    parts = []
    for piece in _PATTERN_TOKEN.findall(pattern):
        if piece == "**":
            parts.append(".*")
        elif piece == "*":
            parts.append("[^/]*")
        else:
            parts.append(re.escape(piece))
    return re.compile("".join(parts) + r"\Z")


def resource_matches(pattern: str, resource: str) -> bool:
    """True if `resource` falls inside `pattern`."""
    return _pattern_to_regex(pattern).match(resource) is not None


def _has_wildcard(pattern: str) -> bool:
    return "*" in pattern


def _scope_is_narrower(parent: str, child: str) -> bool:
    """Conservative containment test for delegation.

    Deciding whether one glob's language is a subset of another's is not
    something to get subtly wrong in an authority check, so this accepts only
    two cases that are certainly safe:

      1. the child pattern is identical to the parent's, or
      2. the child pattern is wildcard-free and the parent matches it.

    This refuses some legitimately narrower patterns (``a/**`` delegating
    ``a/b/**``). That is the correct direction to err: a false refusal is a
    failed spawn, a false acceptance is privilege escalation. A general
    subset test can replace this if delegation ever needs depth > 1.
    """
    if parent == child:
        return True
    if _has_wildcard(child):
        return False
    return resource_matches(parent, child)


# --------------------------------------------------------------------------
# capability tokens
# --------------------------------------------------------------------------

_CT_FIELDS = {
    "ver": str,
    "typ": str,
    "iss": str,
    "sub": str,
    "cap": list,
    "res": str,
    "exp": int,
    "nonce": str,
    "deleg": dict,
}


def issue_capability_token(
    issuer_key,
    *,
    subject: str,
    capabilities: list[str],
    resource: str,
    expires_at: int,
    delegable: bool = False,
    max_depth: int = 0,
    parent_hash: str | None = None,
) -> dict[str, Any]:
    """Sign a capability token. `expires_at` is an absolute unix timestamp."""
    if not capabilities:
        raise MalformedError("a capability token with no capabilities grants nothing")
    if delegable and max_depth < 1:
        raise MalformedError("delegable token needs max_depth >= 1")
    token = {
        "ver": CAPABILITY_TOKEN_VERSION,
        "typ": "ct",
        "iss": agent_id(issuer_key),
        "sub": subject,
        "cap": sorted(set(capabilities)),
        "res": resource,
        "exp": int(expires_at),
        "nonce": new_nonce(),
        "deleg": {"allowed": bool(delegable), "max_depth": int(max_depth)},
        "parent_hash": parent_hash,
    }
    return sign_object(issuer_key, token)


def _check_shape(token: dict[str, Any], expected_typ: str, fields: dict) -> None:
    if not isinstance(token, dict):
        raise MalformedError("token is not an object")
    for name, kind in fields.items():
        if name not in token:
            raise MalformedError(f"missing field: {name}")
        if not isinstance(token[name], kind) or isinstance(token[name], bool) and kind is int:
            raise MalformedError(f"field {name} has wrong type")
    if token["typ"] != expected_typ:
        raise MalformedError(f"expected typ={expected_typ!r}, got {token['typ']!r}")


def verify_capability_token(
    issuer_public_key,
    token: dict[str, Any],
    *,
    now: int | None = None,
) -> dict[str, Any]:
    """Validate signature, shape and expiry. Returns the token, or raises.

    Signature verification precedes every semantic check: a token with a bad
    signature is refused without its contents being trusted for anything.
    """
    if not isinstance(token, dict):
        raise MalformedError("token is not an object")
    if not verify_object(issuer_public_key, token):
        raise SignatureError("capability token signature is not valid")
    _check_shape(token, "ct", _CT_FIELDS)
    if not token["cap"] or not all(isinstance(c, str) for c in token["cap"]):
        raise MalformedError("cap must be a non-empty list of strings")
    if token["exp"] <= _now(now):
        raise ExpiredError("capability token has expired")
    return token


def capability_covers(token: dict[str, Any], capability: str, resource: str) -> bool:
    """True if this token authorises `capability` on `resource`."""
    return capability in token["cap"] and resource_matches(token["res"], resource)


def check_delegation(parent: dict[str, Any], child: dict[str, Any]) -> None:
    """Raise unless `child` is a legitimate delegation of `parent`.

    Enforces the property the whole ceiling rests on: a delegated token's
    authority is always a subset of its delegator's, verified by arithmetic on
    sets rather than by anyone behaving.
    """
    if child.get("parent_hash") != token_hash(parent):
        raise DelegationError("child does not chain to this parent")
    if not parent["deleg"]["allowed"]:
        raise DelegationError("parent token is not delegable")
    if parent["deleg"]["max_depth"] < 1:
        raise DelegationError("parent has no delegation depth remaining")
    if child["deleg"]["max_depth"] > parent["deleg"]["max_depth"] - 1:
        raise DelegationError("child exceeds the remaining delegation depth")
    if not set(child["cap"]) <= set(parent["cap"]):
        extra = sorted(set(child["cap"]) - set(parent["cap"]))
        raise DelegationError(f"child claims capabilities the parent lacks: {extra}")
    if not _scope_is_narrower(parent["res"], child["res"]):
        raise DelegationError("child resource scope is not contained by the parent's")
    if child["exp"] > parent["exp"]:
        raise DelegationError("child outlives its parent")


# --------------------------------------------------------------------------
# execution tokens
# --------------------------------------------------------------------------

_ET_FIELDS = {
    "ver": str,
    "typ": str,
    "id": str,
    "iss": str,
    "sub": str,
    "cap": str,
    "res": str,
    "act_sha256": str,
    "iat": int,
    "exp": int,
}


def issue_execution_token(
    issuer_key,
    *,
    subject: str,
    capability: str,
    resource: str,
    action: dict[str, Any],
    now: int | None = None,
    ttl: int = DEFAULT_EXECUTION_TOKEN_TTL,
) -> dict[str, Any]:
    """Sign a single-use execution token for exactly one action.

    Single-use enforcement is the issuer's job: `id` is what it records as
    consumed. Nothing here can prevent a second presentation on its own.
    """
    issued = _now(now)
    token = {
        "ver": EXECUTION_TOKEN_VERSION,
        "typ": "et",
        "id": new_nonce(),
        "iss": agent_id(issuer_key),
        "sub": subject,
        "cap": capability,
        "res": resource,
        "act_sha256": action_hash(action),
        "iat": issued,
        "exp": issued + int(ttl),
    }
    return sign_object(issuer_key, token)


def verify_execution_token(
    issuer_public_key,
    token: dict[str, Any],
    *,
    subject: str,
    action: dict[str, Any],
    now: int | None = None,
) -> dict[str, Any]:
    """Validate an ET against the bearer and the action actually presented.

    An expired ET is invalid even if it was never used, and an ET presented
    with a different action than the one it was issued for is refused — that
    binding is what stops an approved call being swapped for another.
    """
    if not isinstance(token, dict):
        raise MalformedError("token is not an object")
    if not verify_object(issuer_public_key, token):
        raise SignatureError("execution token signature is not valid")
    _check_shape(token, "et", _ET_FIELDS)
    if token["exp"] <= _now(now):
        raise ExpiredError("execution token has expired")
    if token["sub"] != subject:
        raise ScopeError("execution token was not issued to this agent")
    if token["act_sha256"] != action_hash(action):
        raise ScopeError("execution token does not match the action presented")
    return token
