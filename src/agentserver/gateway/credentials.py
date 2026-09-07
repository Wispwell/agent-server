"""Credential injection. M2. Trusted — secrets never cross the boundary.

A subagent authorised to reach a tool never receives a credential; it receives
an execution token, and the gateway attaches the real secret on the way out.
This is what makes the system containment rather than governance: an injected
subagent that talks its way past every other check still holds nothing it could
exfiltrate.

The vault is loaded from the environment rather than from any file the agent
side can read, and a reference that is not configured is a refusal, not an
empty string — silently sending no credential turns an authorisation failure
into a confusing tool error.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

__all__ = ["CredentialError", "Vault"]

#: Reserved argument name the gateway fills in. A binding that wants a secret
#: names its reference; the tool receives the value under this key.
CREDENTIAL_ARG = "_credential"


class CredentialError(Exception):
    reason = "credential_unavailable"


class Vault:
    def __init__(self, secrets: Mapping[str, str] | None = None):
        self._secrets = dict(secrets or {})

    @classmethod
    def from_env(cls, refs: Mapping[str, str]) -> Vault:
        """`refs` maps credential_ref -> environment variable name."""
        found = {}
        for ref, var in refs.items():
            value = os.environ.get(var)
            if value:
                found[ref] = value
        return cls(found)

    def __contains__(self, ref: object) -> bool:
        return ref in self._secrets

    def inject(self, ref: str | None, args: Mapping[str, Any]) -> dict[str, Any]:
        """Return args with the referenced secret attached, or raise."""
        out = dict(args)
        out.pop(CREDENTIAL_ARG, None)   # never honour an agent-supplied value
        if ref is None:
            return out
        secret = self._secrets.get(ref)
        if secret is None:
            raise CredentialError(f"no credential configured for {ref!r}")
        out[CREDENTIAL_ARG] = secret
        return out
