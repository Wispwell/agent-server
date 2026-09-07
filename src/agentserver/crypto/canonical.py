"""JCS canonical JSON serialization (RFC 8785). M0.

Signatures are over bytes, so both sides must agree on an exact serialization
before hashing: sorted keys, no insignificant whitespace, defined escaping.
Getting this wrong produces signatures that fail across languages and libraries
for no visible reason.

Deliberate restriction: floats are REJECTED.

    RFC 8785 requires ECMAScript `Number::toString` semantics for numbers,
    which is fiddly to reproduce exactly and, done wrong, yields a canonical
    form that differs from other implementations only for some values — the
    worst possible failure mode for a signature scheme, because it passes every
    local test and fails against a peer. Nothing in this system needs a
    non-integer: timestamps, counts, depths and limits are all integers. So
    floats raise instead of being serialized approximately. If a float ever
    reaches here it is a bug, and a loud one is better than a signature that
    verifies on our side and nowhere else.

Integers are restricted to the exact IEEE-754 double range for the same reason:
beyond 2^53 a peer parsing into a double cannot reproduce our bytes.
"""

from __future__ import annotations

from typing import Any

__all__ = ["MAX_SAFE_INTEGER", "CanonicalizationError", "canonicalize"]

MAX_SAFE_INTEGER = 2**53 - 1


class CanonicalizationError(ValueError):
    """A value cannot be canonicalized deterministically."""


_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _escape_string(s: str) -> str:
    out = ['"']
    for ch in s:
        esc = _ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ch < " ":
            # control characters not covered by a short escape: \u00xx, lowercase hex
            out.append(f"\\u{ord(ch):04x}")
        else:
            # everything else is emitted literally; non-ASCII is NOT escaped
            out.append(ch)
    out.append('"')
    return "".join(out)


def _number(value: int) -> str:
    if abs(value) > MAX_SAFE_INTEGER:
        raise CanonicalizationError(
            f"integer {value} is outside the exact IEEE-754 double range "
            f"(±{MAX_SAFE_INTEGER}); a peer parsing into a double could not "
            f"reproduce these bytes"
        )
    return str(value)


def _sort_key(key: str) -> bytes:
    """RFC 8785 sorts object keys by UTF-16 code unit.

    Encoding to UTF-16 big-endian and comparing the resulting bytes is exactly
    that ordering. This differs from Python's native string ordering for
    non-BMP characters, whose surrogate pairs (0xD800-0xDFFF) sort *below* the
    high BMP range rather than above it.
    """
    return key.encode("utf-16-be")


def _write(value: Any, out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(_escape_string(value))
    elif isinstance(value, int):
        # bool is a subclass of int and is handled above
        out.append(_number(value))
    elif isinstance(value, float):
        raise CanonicalizationError(
            "floats are not canonicalizable here; see module docstring. "
            f"got {value!r}"
        )
    elif isinstance(value, dict):
        # validate before sorting: _sort_key assumes str, and a type error must
        # surface as CanonicalizationError rather than from inside the sort
        for key in value:
            if not isinstance(key, str):
                raise CanonicalizationError(f"object keys must be strings, got {key!r}")
        out.append("{")
        first = True
        for key in sorted(value, key=_sort_key):
            if not first:
                out.append(",")
            first = False
            out.append(_escape_string(key))
            out.append(":")
            _write(value[key], out)
        out.append("}")
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _write(item, out)
        out.append("]")
    else:
        raise CanonicalizationError(f"cannot canonicalize {type(value).__name__}")


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 encoding of `value`.

    Deterministic: equal values always produce identical bytes, regardless of
    the order keys were inserted in.
    """
    out: list[str] = []
    _write(value, out)
    return "".join(out).encode("utf-8")
