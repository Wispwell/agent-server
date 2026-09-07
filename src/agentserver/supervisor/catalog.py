"""Role catalog. M2.

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

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..policy import Policy
from ..subagent.behaviour import BehaviourError, Node, parse_tree
from ..tools.bindings import Binding

__all__ = ["Catalog", "CatalogError", "Role"]


class CatalogError(Exception):
    reason = "catalog_error"


@dataclass(frozen=True)
class Role:
    name: str
    capabilities: frozenset[str]
    resource: str
    tree: Node
    description: str = ""

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
        roles: dict[str, Role] = {}
        for name, spec in (raw.get("roles") or {}).items():
            spec = spec or {}
            unknown = set(spec) - {"capabilities", "resource", "tree", "description"}
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

            try:
                tree = parse_tree(spec.get("tree") or {})
            except BehaviourError as exc:
                raise CatalogError(f"role {name!r}: {exc}") from None

            for server, tool in tree.tools():
                binding = bindings.get((server, tool))
                if binding is None:
                    raise CatalogError(
                        f"role {name!r} can invoke unbound tool {server}/{tool}"
                    )
                if binding.capability not in capabilities:
                    raise CatalogError(
                        f"role {name!r} can invoke {server}/{tool}, which needs "
                        f"{binding.capability!r}, but the role does not grant it"
                    )

            roles[name] = Role(name, capabilities, resource, tree,
                               str(spec.get("description") or ""))

        if not roles:
            raise CatalogError("catalog declares no roles")
        return cls(roles)

    @classmethod
    def from_file(cls, path: str | Path, **kw: Any) -> Catalog:
        return cls.from_dict(yaml.safe_load(Path(path).read_text()) or {}, **kw)

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
