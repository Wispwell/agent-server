"""Ed25519 keypairs and agent identity. M0.

    AgentID = base58(SHA-256(public_key))

A username is a claim; a key is a proof. Identity is demonstrated per request,
never asserted. Private keys never leave the agent that owns them.

base58 rather than base64: the alphabet omits the characters that are easy to
confuse when read or transcribed by a person (0/O, I/l), and it produces no
'+' or '/' that would need escaping in a URL or a path.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

__all__ = [
    "AGENT_ID_ALPHABET",
    "agent_id",
    "b58decode",
    "b58encode",
    "generate_keypair",
    "load_private_key",
    "private_bytes",
    "private_key_from_bytes",
    "public_bytes",
    "public_key_from_bytes",
    "save_private_key",
]

AGENT_ID_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(AGENT_ID_ALPHABET)}


def b58encode(data: bytes) -> str:
    """Base58 (Bitcoin alphabet), preserving leading zero bytes as '1'."""
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = AGENT_ID_ALPHABET[rem] + out
    # each leading zero byte encodes to one leading '1'
    for byte in data:
        if byte:
            break
        out = "1" + out
    # empty input encodes to the empty string; returning "1" here would collide
    # with b"\x00" and break the round trip
    return out


def b58decode(text: str) -> bytes:
    """Inverse of b58encode. Raises ValueError on an out-of-alphabet character."""
    n = 0
    for ch in text:
        try:
            n = n * 58 + _B58_INDEX[ch]
        except KeyError:
            raise ValueError(f"invalid base58 character: {ch!r}") from None
    leading = len(text) - len(text.lstrip("1"))
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * leading + body


def generate_keypair() -> Ed25519PrivateKey:
    """A fresh Ed25519 private key. The public key comes from `.public_key()`."""
    return Ed25519PrivateKey.generate()


def public_bytes(key: Ed25519PublicKey | Ed25519PrivateKey) -> bytes:
    """The raw 32-byte public key, whichever half is passed in."""
    if isinstance(key, Ed25519PrivateKey):
        key = key.public_key()
    return key.public_bytes_raw()


def private_bytes(key: Ed25519PrivateKey) -> bytes:
    """The raw 32-byte private key. Handle accordingly."""
    return key.private_bytes_raw()


def public_key_from_bytes(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)


def private_key_from_bytes(raw: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(raw)


def agent_id(key: Ed25519PublicKey | Ed25519PrivateKey) -> str:
    """Derive the AgentID from a public key.

    Deriving from the key rather than assigning a name means an agent cannot
    claim an identity it has no key for, and two agents cannot collide on one.
    """
    return b58encode(hashlib.sha256(public_bytes(key)).digest())


def save_private_key(key: Ed25519PrivateKey, path: str | Path) -> Path:
    """Write the raw private key to `path`, readable only by its owner.

    Created via os.open with mode 0600 rather than written and then chmod'd:
    the latter leaves a window in which the key exists with default
    permissions.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, private_bytes(key))
    finally:
        os.close(fd)
    return path


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    """Read a raw private key written by `save_private_key`.

    Refuses a key file that is readable by anyone else — a private key with
    loose permissions is not private, and continuing would silently weaken the
    identity guarantee everything else rests on.
    """
    path = Path(path)
    mode = path.stat().st_mode
    if mode & 0o077:
        raise PermissionError(
            f"{path} is accessible beyond its owner (mode {mode & 0o777:03o}); "
            f"refusing to load a private key with loose permissions"
        )
    return private_key_from_bytes(path.read_bytes())
