"""Role catalog — compiled subagents. M2.

A subagent is a program, not configuration. It is authored as a
``*.subagent.yaml`` artifact, compiled by the CLI, and installed as a signed
row. Writing behaviour trees into a config file would be coding in YAML under a
configuration heading, and the validation that belongs at compile time would
instead run at every startup.

Signing matters more here than for bindings: a role **declares its own
capabilities**, so an unsigned row would let whoever can write the database
mint a role with any authority. Verification on load is what makes the store a
transport rather than a trust boundary.

A role is a capability set **and** a behaviour tree, both frozen at config time
and authored by the operator. The governor selects a role and supplies
parameters; it can never define a capability set or compose a tree. That is the
largest single reduction in attack surface — it collapses the governor's output
space from "arbitrary capability request" to a small enum, and bounds not only
what a subagent may reach but the shape of what it will attempt.

Validation happens at load, against the trust root and the bindings: every
capability a role grants must be declared, every tool its tree can invoke must
be bound, and every one of those tools' capabilities must be inside the role's
own set. A tree that could call something the role is not permitted is a
configuration error, and it should surface when the catalog is read rather than
when a subagent is halfway through a task.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from ..crypto.canonical import canonicalize
from ..crypto.keys import agent_id
from ..crypto.signing import b64u_decode, b64u_encode, sign, verify
from ..policy import Policy
from ..subagent.behaviour import BehaviourError, Node, parse_tree
from ..tools.bindings import Binding

__all__ = [
    "Catalog",
    "CatalogError",
    "Role",
    "compile_subagent",
    "install",
    "load_roles",
    "sign_role",
    "verify_role",
]

_SIGNED_FIELDS = ("name", "description", "capabilities", "resource", "tree",
                  "enabled", "issued_by")


class CatalogError(Exception):
    reason = "catalog_error"


class UnsignedRole(CatalogError):
    reason = "role_unsigned"


class UnknownRoleOperator(CatalogError):
    reason = "role_unknown_operator"


@dataclass(frozen=True)
class Role:
    name: str
    capabilities: frozenset[str]
    resource: str
    tree: Node
    description: str = ""
    spec: Mapping[str, Any] = field(default_factory=dict, repr=False)
    issued_by: str = ""

    def tools(self) -> list[tuple[str, str]]:
        return self.tree.tools()


class Catalog:
    def __init__(self, roles: Mapping[str, Role]):
        self.roles = dict(roles)

    def __contains__(self, name: object) -> bool:
        return name in self.roles

    def __len__(self) -> int:
        return len(self.roles)

    def get(self, name: str) -> Role:
        role = self.roles.get(name)
        if role is None:
            raise CatalogError(f"unknown role {name!r}; known: {sorted(self.roles)}")
        return role

    @classmethod
    def from_dict(
        cls,
        raw: Mapping[str, Any],
        *,
        policy: Policy,
        bindings: Mapping[tuple[str, str], Binding],
    ) -> Catalog:
        """Build a catalog from inline specs. Used by tests and by compilation."""
        roles = {
            name: validate_role(name, spec or {}, policy=policy, bindings=bindings)
            for name, spec in (raw.get("roles") or {}).items()
        }
        if not roles:
            raise CatalogError("catalog declares no roles")
        return cls(roles)

    @classmethod
    def from_store(
        cls,
        store,
        *,
        policy: Policy,
        bindings: Mapping[tuple[str, str], Binding],
    ) -> tuple[Catalog, list[tuple[str, CatalogError]]]:
        """Load installed subagents, verifying each. Returns (catalog, rejected).

        Rejections are returned rather than raised: one unverifiable row must
        not blind the server to every other role, and the caller records each
        refusal. A row that does not verify is simply not a role.
        """
        roles, rejected = load_roles(store, policy, bindings)
        return cls(roles), rejected

    def describe(self) -> list[dict[str, Any]]:
        """The action vocabulary, as it appears in an observation."""
        return [
            {
                "role": role.name,
                "description": role.description,
                "capabilities": sorted(role.capabilities),
                "resource": role.resource,
            }
            for role in sorted(self.roles.values(), key=lambda r: r.name)
        ]


# --------------------------------------------------------------------------
# validation — runs at compile time, not at every startup
# --------------------------------------------------------------------------


def validate_role(
    name: str,
    spec: Mapping[str, Any],
    *,
    policy: Policy,
    bindings: Mapping[tuple[str, str], Binding],
) -> Role:
    """Check one subagent spec completely, or raise CatalogError.

    Everything a role could get wrong is caught here: an undeclared capability,
    a tree that will not parse, a tool that is not bound, and — the one that
    matters — a tree that can reach a tool whose capability the role does not
    hold. That last check is why a role cannot quietly out-reach its own
    authority.
    """
    unknown = set(spec) - {"name", "capabilities", "resource", "tree", "description"}
    if unknown:
        raise CatalogError(f"role {name!r} has unknown keys: {sorted(unknown)}")

    capabilities = frozenset(spec.get("capabilities") or [])
    if not capabilities:
        raise CatalogError(f"role {name!r} grants no capabilities")
    for capability in sorted(capabilities):
        if policy.resolver_for(capability) is None:
            raise CatalogError(
                f"role {name!r} grants undeclared capability {capability!r}"
            )

    resource = spec.get("resource")
    if not isinstance(resource, str) or not resource:
        raise CatalogError(f"role {name!r} has no resource scope")

    tree_spec = spec.get("tree") or {}
    try:
        tree = parse_tree(tree_spec)
    except BehaviourError as exc:
        raise CatalogError(f"role {name!r}: {exc}") from None

    for server, tool in tree.tools():
        binding = bindings.get((server, tool))
        if binding is None:
            raise CatalogError(f"role {name!r} can invoke unbound tool {server}/{tool}")
        if binding.capability not in capabilities:
            raise CatalogError(
                f"role {name!r} can invoke {server}/{tool}, which needs "
                f"{binding.capability!r}, but the role does not grant it"
            )

    return Role(name, capabilities, resource, tree,
                str(spec.get("description") or ""), dict(spec))


def compile_subagent(
    artifact: Mapping[str, Any],
    *,
    policy: Policy,
    bindings: Mapping[tuple[str, str], Binding],
) -> Role:
    """Validate a *.subagent.yaml artifact. The name comes from the file."""
    name = artifact.get("name")
    if not isinstance(name, str) or not name:
        raise CatalogError("subagent artifact has no name")
    spec = {k: v for k, v in artifact.items() if k != "name"}
    return validate_role(name, spec, policy=policy, bindings=bindings)


# --------------------------------------------------------------------------
# signed installation
# --------------------------------------------------------------------------


def _payload(row: Mapping[str, Any]) -> bytes:
    body: dict[str, Any] = {}
    for field_name in _SIGNED_FIELDS:
        value = row.get(field_name)
        if field_name in ("capabilities", "tree") and isinstance(value, str):
            value = json.loads(value)
        elif field_name == "capabilities":
            value = sorted(value)
        elif field_name == "enabled":
            value = bool(value)
        body[field_name] = value
    return canonicalize(body)


def sign_role(operator_key, role: Role, *, enabled: bool = True) -> dict[str, Any]:
    """Produce a signed row for an already-validated role."""
    row = {
        "name": role.name,
        "description": role.description,
        "capabilities": sorted(role.capabilities),
        "resource": role.resource,
        "tree": dict(role.spec.get("tree") or {}),
        "enabled": enabled,
        "issued_by": agent_id(operator_key),
    }
    row["sig"] = b64u_encode(sign(operator_key, _payload(row)))
    return row


def verify_role(
    policy: Policy,
    row: Mapping[str, Any],
    bindings: Mapping[tuple[str, str], Binding],
) -> Role:
    """Validate a stored row against the trust root, then re-check it."""
    issued_by = row.get("issued_by")
    key = policy.operators.get(issued_by) if isinstance(issued_by, str) else None
    if key is None:
        raise UnknownRoleOperator(f"role issued by unknown operator {issued_by!r}")

    raw_sig = row.get("sig")
    if not isinstance(raw_sig, str):
        raise UnsignedRole("role carries no signature")
    try:
        signature = b64u_decode(raw_sig)
    except (ValueError, TypeError):
        raise UnsignedRole("role signature is not decodable") from None
    if not verify(key, _payload(row), signature):
        raise UnsignedRole("role signature is not valid")

    capabilities = row["capabilities"]
    tree = row["tree"]
    spec = {
        "capabilities": json.loads(capabilities) if isinstance(capabilities, str) else capabilities,
        "resource": row["resource"],
        "tree": json.loads(tree) if isinstance(tree, str) else tree,
        "description": row.get("description") or "",
    }
    role = validate_role(row["name"], spec, policy=policy, bindings=bindings)
    return Role(role.name, role.capabilities, role.resource, role.tree,
                role.description, role.spec, str(issued_by))


def load_roles(
    store, policy: Policy, bindings: Mapping[tuple[str, str], Binding]
) -> tuple[dict[str, Role], list[tuple[str, CatalogError]]]:
    accepted: dict[str, Role] = {}
    rejected: list[tuple[str, CatalogError]] = []
    for raw in store.query("SELECT * FROM roles"):
        row = dict(raw)
        try:
            role = verify_role(policy, row, bindings)
        except CatalogError as exc:
            rejected.append((row.get("name", "?"), exc))
            continue
        if row.get("enabled", 1):
            accepted[role.name] = role
    return accepted, rejected


def install(store, row: Mapping[str, Any], *, now: int | None = None) -> None:
    """Insert or replace a signed role row."""
    stored = dict(row)
    stored["capabilities"] = json.dumps(sorted(stored["capabilities"]))
    stored["tree"] = json.dumps(stored["tree"], sort_keys=True)
    stored["enabled"] = int(stored.get("enabled", True))
    stored["compiled_at"] = int(time.time()) if now is None else int(now)
    columns = ", ".join(stored)
    marks = ", ".join("?" * len(stored))
    with store.write() as conn:
        conn.execute(f"INSERT OR REPLACE INTO roles ({columns}) VALUES ({marks})",
                     tuple(stored.values()))
