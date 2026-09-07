"""Subagent runner. M2. Drives one role's behaviour tree.

The subagent generates its own keypair; the supervisor learns only the public
half and issues a capability token against it. A private key that crosses a
process boundary ends up in argv, a file, or a log, and the identity guarantee
everything else rests on is only as good as that never happening.

**Isolation, stated plainly.** v0 runs the tree in-process. The subagent holds
no credentials — those live in the gateway's vault and are attached on the way
out — and every tool call goes through admission, so the authority boundary is
real. What is *not* yet real is the substrate boundary: nothing stops this code
reading a file directly instead of asking. That makes v0 honest containment
against a model steered by what it reads, and inadequate against one probing
for escape. Running the tree in a separate process with a scrubbed environment,
and later a container, is the immediate next step and is not done.

The result returned to the supervisor is normalised: state, exit reason,
counts, and a length-capped output field. Never raw output — raw text lets a
subagent inject the planner and lets two subagents pass messages through it.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from ..containment.admission import AdmissionEngine
from ..crypto.keys import agent_id, generate_keypair, public_bytes
from ..crypto.signing import b64u_encode
from ..crypto.tokens import issue_capability_token
from ..ledger.events import EventType
from ..supervisor.catalog import Role
from ..supervisor.lifecycle import State
from .behaviour import Context, Status
from .client import ToolClient

__all__ = ["OUTPUT_CAP", "Runner", "SubagentResult"]

#: Subagent output is attacker-influenceable and enters the governor's context.
#: It is capped and delimited rather than forwarded whole.
OUTPUT_CAP = 800


@dataclass
class SubagentResult:
    agent_id: str
    role: str
    state: State
    status: Status
    tool_calls: int = 0
    denied: int = 0
    output: str = ""
    trace: list[dict[str, Any]] = field(default_factory=list)

    def normalised(self) -> dict[str, Any]:
        """What the supervisor is willing to put in front of the governor."""
        return {
            "agent_id": self.agent_id,
            "role": self.role,
            "state": str(self.state),
            "status": str(self.status),
            "tool_calls": self.tool_calls,
            "denied": self.denied,
            "output": self.output[:OUTPUT_CAP],
            "output_truncated": len(self.output) > OUTPUT_CAP,
        }


class Runner:
    def __init__(
        self,
        engine: AdmissionEngine,
        gateway,
        issuer_key,
        *,
        token_ttl: int = 900,
    ):
        self.engine = engine
        self.gateway = gateway
        self.issuer_key = issuer_key
        self.token_ttl = token_ttl

    def run(
        self,
        role: Role,
        *,
        params: Mapping[str, Any] | None = None,
        choose: Callable[[str, Mapping[str, Any]], dict[str, Any] | None] | None = None,
        now: int | None = None,
    ) -> SubagentResult:
        now = int(time.time()) if now is None else now

        # generated here, inside the subagent; only the public half leaves
        key = generate_keypair()
        identity = agent_id(key)
        self.engine.register_agent(identity, b64u_encode(public_bytes(key)), now=now)
        self.engine.ledger.append(
            EventType.LIFECYCLE,
            {"agent_id": identity, "role": role.name, "state": str(State.SPAWNED)},
            now=now,
        )

        token = issue_capability_token(
            self.issuer_key,
            subject=identity,
            capabilities=sorted(role.capabilities),
            resource=role.resource,
            expires_at=now + self.token_ttl,
        )
        self.engine.ledger.append(
            EventType.LIFECYCLE,
            {"agent_id": identity, "role": role.name, "state": str(State.BOUND)},
            now=now,
        )

        client = ToolClient(key, token, self.gateway,
                            issue_challenge=self.engine.issue_challenge)

        calls = {"total": 0, "denied": 0}

        def call_tool(server: str, tool: str, args: Mapping[str, Any]):
            calls["total"] += 1
            ok, payload = client.call(server, tool, args)
            if not ok:
                calls["denied"] += 1
            return ok, payload

        ctx = Context(params=dict(params or {}), call_tool=call_tool, choose=choose)
        self.engine.ledger.append(
            EventType.LIFECYCLE,
            {"agent_id": identity, "role": role.name, "state": str(State.RUNNING)},
            now=now,
        )

        try:
            status = role.tree.tick(ctx)
            state = State.COMPLETED
        except Exception as exc:  # noqa: BLE001 — a role's tree must not take the run down
            ctx.record("runner", Status.FAILURE, error=f"{type(exc).__name__}: {exc}")
            status, state = Status.FAILURE, State.FAULTED

        output = ctx.blackboard.get("result") or ctx.blackboard.get("body") or ""
        result = SubagentResult(
            agent_id=identity, role=role.name, state=state, status=status,
            tool_calls=calls["total"], denied=calls["denied"],
            output=str(output), trace=ctx.trace,
        )
        self.engine.ledger.append(
            EventType.LIFECYCLE,
            {"agent_id": identity, "role": role.name, "state": str(state),
             "status": str(status), "tool_calls": result.tool_calls,
             "denied": result.denied},
            now=now,
        )
        return result
