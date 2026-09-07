"""Sign and verify. M0.

Signature verification precedes all semantic validation: an object with an
invalid signature is rejected without its content being read.

Everything signed here is signed over the JCS canonical form (see
`canonical.py`), never over an ad-hoc string. That matters for the
proof-of-possession message in particular — concatenating a challenge, a method
and a path into one string is ambiguous, because a path containing the
separator can be made to produce the same bytes as a different request.
Canonicalizing a structured object makes the framing unambiguous by
construction.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonicalize

__all__ = [
    "CHALLENGE_BYTES",
    "b64u_decode",
    "b64u_encode",
    "new_challenge",
    "pop_message",
    "sign",
    "sign_object",
    "verify",
    "verify_object",
]

CHALLENGE_BYTES = 16  # 128 bits


def b64u_encode(data: bytes) -> str:
    """base64url without padding, as used for every signature and nonce here."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def sign(key: Ed25519PrivateKey, message: bytes) -> bytes:
    """Raw 64-byte Ed25519 signature over `message`."""
    return key.sign(message)


def verify(key: Ed25519PublicKey, message: bytes, signature: bytes) -> bool:
    """True if `signature` is valid for `message` under `key`. Never raises."""
    try:
        key.verify(signature, message)
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def sign_object(
    key: Ed25519PrivateKey,
    obj: dict[str, Any],
    *,
    signature_field: str = "sig",
) -> dict[str, Any]:
    """Return a copy of `obj` with `signature_field` set to its signature.

    The signature covers every field except the signature field itself. The
    input is not mutated.
    """
    body = {k: v for k, v in obj.items() if k != signature_field}
    signed = dict(body)
    signed[signature_field] = b64u_encode(sign(key, canonicalize(body)))
    return signed


def verify_object(
    key: Ed25519PublicKey,
    obj: dict[str, Any],
    *,
    signature_field: str = "sig",
) -> bool:
    """True if `obj` carries a valid signature over its remaining fields.

    A missing or malformed signature is a verification failure, not an error:
    callers must not have to distinguish "unsigned" from "badly signed" to
    reach the same decision, which is to refuse.
    """
    raw = obj.get(signature_field)
    if not isinstance(raw, str):
        return False
    try:
        signature = b64u_decode(raw)
    except (ValueError, TypeError):
        return False
    body = {k: v for k, v in obj.items() if k != signature_field}
    try:
        payload = canonicalize(body)
    except ValueError:
        return False
    return verify(key, payload, signature)


def new_challenge() -> str:
    """A single-use 128-bit challenge, base64url encoded.

    Lifetime and single-use enforcement belong to whoever issues it (the
    containment server), not here; this only produces the value.
    """
    return b64u_encode(secrets.token_bytes(CHALLENGE_BYTES))


def pop_message(challenge: str, method: str, path: str, body: bytes = b"") -> bytes:
    """The exact bytes an agent signs to prove possession for one request.

    Binds four things at once: that the agent holds the private key, that this
    is the request that was authorised, that it is not a replay of an earlier
    one, and that the body was not altered in transit.
    """
    return canonicalize(
        {
            "challenge": challenge,
            "method": method.upper(),
            "path": path,
            "body_sha256": hashlib.sha256(body).hexdigest(),
        }
    )
