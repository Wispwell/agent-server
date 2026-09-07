"""The MCP gateway. M2. Trusted.

Every tool call passes through here, and nothing routes around it:

    verify proof-of-possession → admission decides → consume the execution
    token → attach real credentials → invoke the MCP server → record

One process with the containment server in v0, two modules with a clean
interface. Splitting them is a deployment concern; splitting early doubles the
debugging surface.

Two things this deliberately does *not* shortcut, even though the engine that
issued the token is right here:

  * The execution token is consumed rather than assumed. An ET travels out
    through an untrusted subagent and back, and re-checking the action binding
    at consumption is what stops an approved call being swapped for a different
    one after approval.
  * Tool schemas are checked against the pinned hash at connect time. A server
    that redefines a bound tool's arguments has that tool disabled until
    someone re-pins deliberately — otherwise the resolver keeps reading a field
    that no longer means what it did.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..containment.admission import AdmissionEngine, Outcome, Request
from ..crypto.canonical import canonicalize
from ..ledger.events import EventType
from ..supervisor.budgets import Budget, BudgetExceeded
from .credentials import CredentialError, Vault
from .transport import MCPTransport

__all__ = ["Gateway", "schema_hash"]


def schema_hash(schema: Mapping[str, Any]) -> str:
    """SHA-256 of a tool's declared input schema, canonically serialised."""
    return hashlib.sha256(canonicalize(json.loads(json.dumps(schema)))).hexdigest()


@dataclass
class Gateway:
    engine: AdmissionEngine
    transports: Mapping[str, MCPTransport]
    vault: Vault
    budget: Budget | None = None

    def verify_schemas(self) -> list[tuple[tuple[str, str], str]]:
        """Disable bindings whose server has changed the tool's arguments.

        Returns the drifted bindings. Called at connect time; a drifted tool is
        removed from the engine's binding set rather than left to misresolve.
        """
        drifted: list[tuple[tuple[str, str], str]] = []
        for (server, tool), binding in list(self.engine.bindings.items()):
            transport = self.transports.get(server)
            if transport is None:
                continue
            advertised = transport.list_tools().get(tool)
            if advertised is None:
                drifted.append(((server, tool), "not advertised"))
                del self.engine.bindings[(server, tool)]
                continue
            actual = schema_hash(advertised.input_schema)
            if actual != binding.schema_sha256:
                drifted.append(((server, tool), f"schema changed to {actual[:12]}…"))
                del self.engine.bindings[(server, tool)]
        for ident, why in drifted:
            self.engine.ledger.append(
                EventType.SPAWN_REFUSED,
                {"stage": "schema_pin", "server": ident[0], "tool": ident[1], "detail": why},
            )
        return drifted

    def call(self, request: Request, *, now: int | None = None) -> tuple[bool, Any]:
        """Admit and execute one tool call. Returns (ok, payload).

        A refusal is a value rather than an exception: for a behaviour tree a
        denial is ordinary control flow, and raising would force every caller
        to re-implement the same handling.
        """
        subject = request.token.get("sub", "")

        if self.budget is not None:
            try:
                self.budget.check_tool_call(subject)
            except BudgetExceeded as exc:
                return (False, f"budget: {exc}")

        decision = self.engine.evaluate(request, now=now)
        if decision.outcome not in (Outcome.APPROVED, Outcome.AUTO_APPROVED):
            return (False, f"{decision.reason}: {decision.detail}")

        action = request.call.action()
        spend = self.engine.consume_execution_token(
            decision.execution_token, subject=subject, action=action, now=now
        )
        if spend.outcome is not Outcome.APPROVED:
            return (False, f"{spend.reason}: {spend.detail}")

        binding = self.engine.bindings.get((request.call.server, request.call.tool))
        try:
            args = self.vault.inject(binding.credential_ref if binding else None,
                                     request.call.args)
        except CredentialError as exc:
            return (False, str(exc))

        transport = self.transports.get(request.call.server)
        if transport is None:
            return (False, f"no transport for server {request.call.server!r}")

        if self.budget is not None:
            self.budget.spend_tool_call(subject)

        ok, payload = transport.call(request.call.tool, args)
        self.engine.ledger.append(
            EventType.EXECUTION_TOKEN_CONSUMED,
            {"id": decision.execution_token["id"], "executed": ok,
             "capability": decision.capability, "resource": decision.resource},
            now=now,
        )
        return (ok, payload)
