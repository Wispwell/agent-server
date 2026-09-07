"""Trust root. M1. Trusted, and deliberately *not* in the database.

A mutable store cannot contain its own trust root. If operator public keys
lived in the bindings table, anyone able to write that file would insert their
own operator key and sign whatever they liked, and the signature check would be
theatre.

So the split is:

  * **here (startup configuration)** — the policy vocabulary: which operator
    keys may sign bindings, which capabilities exist, and which resolver kind
    each capability accepts. Rare, deliberate, reviewed.
  * **the database** — which tool maps to which capability, signed. Common,
    runtime, no release.

That keeps "adding a tool is data" intact while putting friction only where it
belongs: on granting someone the power to sign bindings at all.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto.keys import public_key_from_bytes
from .crypto.signing import b64u_decode
from .tools.resolvers import RESOLVERS, Root

__all__ = ["Policy", "PolicyError"]


class PolicyError(Exception):
    """The trust configuration is unusable. Never recoverable at runtime."""


class Policy:
    def __init__(
        self,
        *,
        operators: Mapping[str, Ed25519PublicKey],
        capabilities: Mapping[str, str],
        roots: Mapping[str, Root],
    ):
        self.operators = dict(operators)
        self.capabilities = dict(capabilities)   # capability -> resolver name
        self.roots = dict(roots)

    def resolver_for(self, capability: str) -> str | None:
        return self.capabilities.get(capability)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any], *, base: Path | None = None) -> Policy:
        operators: dict[str, Ed25519PublicKey] = {}
        for agent_id, encoded in (raw.get("operators") or {}).items():
            if not isinstance(encoded, str):
                raise PolicyError(f"operator {agent_id}: public key must be a string")
            try:
                operators[agent_id] = public_key_from_bytes(b64u_decode(encoded))
            except (ValueError, TypeError) as exc:
                # narrow deliberately: a malformed key is a PolicyError, but a
                # typo in this module should still surface as the bug it is
                raise PolicyError(f"operator {agent_id}: unusable public key ({exc})") from None
        if not operators:
            raise PolicyError("no operator keys configured; nothing could ever be bound")

        capabilities: dict[str, str] = {}
        for name, spec in (raw.get("capabilities") or {}).items():
            resolver = (spec or {}).get("resolver")
            if resolver not in RESOLVERS:
                raise PolicyError(
                    f"capability {name!r} names unknown resolver {resolver!r}; "
                    f"known: {sorted(RESOLVERS)}"
                )
            capabilities[name] = resolver
        if not capabilities:
            raise PolicyError("no capabilities declared")

        roots: dict[str, Root] = {}
        for name, path in (raw.get("roots") or {}).items():
            resolved = Path(path)
            if not resolved.is_absolute() and base is not None:
                resolved = (base / resolved).resolve()
            roots[name] = Root(name, resolved)

        return cls(operators=operators, capabilities=capabilities, roots=roots)

    @classmethod
    def from_file(cls, path: str | Path) -> Policy:
        path = Path(path)
        return cls.from_dict(yaml.safe_load(path.read_text()) or {}, base=path.parent)
