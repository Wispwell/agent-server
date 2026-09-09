"""Signed tool bindings. M1. Trusted.

A binding maps ``(server, tool)`` to the capability it requires and the
resolver that extracts its resource. Bindings are **data** — adding a tool is
an INSERT, not a release — made safe by signing rather than by review:
admission verifies an operator signature on load, so an unsigned or
badly-signed row is invisible. Whoever can write the database gains nothing
without a key.

Three rules bound what a signed binding can do:

  1. Its capability must be declared in the trust root, and the binding's
     resolver must be the one that capability accepts. A tool whose resource
     cannot be named has no valid resolver and therefore cannot be bound at all.
  2. New bindings are born requiring review, so a mistaken one costs a prompt
     rather than a breach.
  3. Extraction may refuse, and a refusal is a denial.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..crypto.canonical import canonicalize
from ..crypto.keys import agent_id
from ..crypto.signing import b64u_decode, b64u_encode, sign, verify
from ..policy import Policy
from .resolvers import resolve

__all__ = ["Binding", "BindingError", "install_binding", "load_bindings",
           "sign_binding", "verify_binding"]

_SIGNED_FIELDS = (
    "server", "tool", "capability", "resolver", "resolver_config",
    "schema_sha256", "requires_review", "credential_ref", "enabled", "issued_by",
)


class BindingError(Exception):
    reason = "binding_error"


class UnsignedBinding(BindingError):
    reason = "binding_unsigned"


class UnknownOperator(BindingError):
    reason = "binding_unknown_operator"


class UnknownCapability(BindingError):
    reason = "binding_unknown_capability"


class ResolverMismatch(BindingError):
    reason = "binding_resolver_mismatch"


@dataclass(frozen=True)
class Binding:
    server: str
    tool: str
    capability: str
    resolver: str
    resolver_config: dict[str, Any]
    schema_sha256: str
    requires_review: bool
    credential_ref: str | None
    enabled: bool
    issued_by: str

    @property
    def key(self) -> tuple[str, str]:
        return (self.server, self.tool)

    def resource_for(self, args: Mapping[str, Any], policy: Policy) -> str:
        """Extract the resource this call touches, or raise ResolutionError."""
        return resolve(self.resolver, args, self.resolver_config, roots=policy.roots)


def _payload(row: Mapping[str, Any]) -> bytes:
    """Canonical bytes a binding signature covers.

    Normalises storage artefacts first, so signing and verifying agree no
    matter which side of SQLite the row came from: `resolver_config` is a dict
    in memory and a JSON string in the database, and the booleans come back as
    integers. Canonicalizing the storage form instead of the logical one makes
    every stored binding fail its own signature.
    """
    body = {}
    for field in _SIGNED_FIELDS:
        value = row.get(field)
        if field == "resolver_config" and isinstance(value, str):
            value = json.loads(value)
        elif field in ("requires_review", "enabled"):
            value = bool(value)
        body[field] = value
    return canonicalize(body)


def sign_binding(operator_key, **fields: Any) -> dict[str, Any]:
    """Produce a signed binding row. `issued_by` is derived from the key."""
    row = {
        "requires_review": True,   # born under review
        "credential_ref": None,
        "enabled": True,
        **fields,
        "issued_by": agent_id(operator_key),
    }
    row.setdefault("resolver_config", {})
    missing = [f for f in _SIGNED_FIELDS if f not in row]
    if missing:
        raise BindingError(f"missing binding fields: {missing}")
    row["sig"] = b64u_encode(sign(operator_key, _payload(row)))
    return row


def verify_binding(policy: Policy, row: Mapping[str, Any]) -> Binding:
    """Validate a row against the trust root. Raises BindingError on refusal."""
    issued_by = row.get("issued_by")
    key = policy.operators.get(issued_by) if isinstance(issued_by, str) else None
    if key is None:
        raise UnknownOperator(f"binding issued by unknown operator {issued_by!r}")

    raw_sig = row.get("sig")
    if not isinstance(raw_sig, str):
        raise UnsignedBinding("binding carries no signature")
    try:
        signature = b64u_decode(raw_sig)
    except (ValueError, TypeError):
        raise UnsignedBinding("binding signature is not decodable") from None
    if not verify(key, _payload(row), signature):
        raise UnsignedBinding("binding signature is not valid")

    capability = row.get("capability")
    expected = policy.resolver_for(capability) if isinstance(capability, str) else None
    if expected is None:
        raise UnknownCapability(f"binding names undeclared capability {capability!r}")
    if row.get("resolver") != expected:
        raise ResolverMismatch(
            f"capability {capability!r} accepts resolver {expected!r}, "
            f"binding uses {row.get('resolver')!r}"
        )

    config = row.get("resolver_config")
    if isinstance(config, str):
        config = json.loads(config)

    return Binding(
        server=row["server"],
        tool=row["tool"],
        capability=capability,
        resolver=row["resolver"],
        resolver_config=config or {},
        schema_sha256=row["schema_sha256"],
        requires_review=bool(row["requires_review"]),
        credential_ref=row.get("credential_ref"),
        enabled=bool(row["enabled"]),
        issued_by=issued_by,
    )


def load_bindings(
    store, policy: Policy
) -> tuple[dict[tuple[str, str], Binding], list[tuple[tuple[str, str], BindingError]]]:
    """Load every binding, verifying each. Returns (accepted, rejected).

    Rejections are returned rather than raised: one bad row must not blind the
    system to every other binding, and the caller records each refusal in the
    ledger. An unverifiable row is simply not authority.
    """
    accepted: dict[tuple[str, str], Binding] = {}
    rejected: list[tuple[tuple[str, str], BindingError]] = []
    for row in store.query("SELECT * FROM bindings"):
        row = dict(row)
        ident = (row.get("server"), row.get("tool"))
        try:
            binding = verify_binding(policy, row)
        except BindingError as exc:
            rejected.append((ident, exc))
            continue
        if binding.enabled:
            accepted[binding.key] = binding
    return accepted, rejected


def install_binding(store, row: Mapping[str, Any]) -> None:
    """Insert or replace a signed binding row."""
    stored = dict(row)
    stored["resolver_config"] = json.dumps(stored["resolver_config"], sort_keys=True)
    stored["requires_review"] = int(stored["requires_review"])
    stored["enabled"] = int(stored["enabled"])
    columns = ", ".join(stored)
    marks = ", ".join("?" * len(stored))
    with store.write() as conn:
        conn.execute(
            f"INSERT OR REPLACE INTO bindings ({columns}) VALUES ({marks})",
            tuple(stored.values()),
        )
