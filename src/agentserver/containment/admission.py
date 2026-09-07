"""Admission engine. M1. Trusted.

Answers one question per tool call: may this execute right now.

Explicit rules that plainly pass or fail — no risk score. The stateful rules
are the ones a permission list cannot express: it can say "this agent may write
files"; it cannot say "not its fortieth write in ninety seconds".

Two phases, and the split is a security property rather than an implementation
detail. If a signature or proof-of-possession fails, the claimed AgentID cannot
be trusted — incrementing that agent's counters would let anyone lock out
anyone, with three malformed requests stamped with a victim's identity and no
key at all. **Nothing in phase 1 moves state.**

Escalation is resolved *outside* the write transaction. Asking a human is
unbounded in time, and holding the database's write lock while a CLI prompt
waits would stall every other decision. The counter arithmetic that needs
atomicity has already happened by then; the pending escalation is committed,
the human is asked, and the resolution lands in a second short transaction.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from ..crypto import tokens as tk
from ..crypto.keys import public_key_from_bytes
from ..crypto.signing import (
    b64u_decode,
    b64u_encode,
    new_challenge,
    pop_message,
    verify,
)
from ..ledger.chain import Ledger
from ..ledger.events import EventType
from ..policy import Policy
from ..tools.bindings import Binding
from ..tools.resolvers import ResolutionError
from .store import Store

__all__ = [
    "ACTIVATED",
    "AdmissionConfig",
    "AdmissionEngine",
    "Decision",
    "Outcome",
    "ProofOfPossession",
    "Reason",
    "Request",
    "ToolCall",
    "pattern_key",
]


class Outcome(StrEnum):
    APPROVED = "approved"
    AUTO_APPROVED = "auto_approved"   # preset-approved; counted apart for BAR
    ESCALATED = "escalated"
    DENIED = "denied"


class Reason(StrEnum):
    OK = "ok"
    # phase 1 — authentication; no state moves for any of these
    BAD_SIGNATURE = "bad_signature"
    BAD_POP = "bad_pop"
    UNKNOWN_AGENT = "unknown_agent"
    TOKEN_EXPIRED = "token_expired"
    TOKEN_MALFORMED = "token_malformed"
    BAD_DELEGATION = "bad_delegation"
    # phase 2 — authorisation
    AGENT_SUSPENDED = "agent_suspended"
    AGENT_REVOKED = "agent_revoked"
    COOLDOWN_ACTIVE = "cooldown_active"
    TOOL_UNBOUND = "tool_unbound"
    UNRESOLVABLE = "unresolvable"
    CAPABILITY_NOT_GRANTED = "capability_not_granted"
    RESOURCE_OUT_OF_SCOPE = "resource_out_of_scope"
    REQUIRES_REVIEW = "requires_review"
    RATE_LIMIT = "rate_limit"
    ESCALATION_REFUSED = "escalation_refused"


#: Outcomes counting as the boundary having activated (E4 / BAR).
ACTIVATED = frozenset({Outcome.ESCALATED, Outcome.DENIED})


@dataclass(frozen=True)
class ToolCall:
    server: str
    tool: str
    args: Mapping[str, Any]

    def action(self) -> dict[str, Any]:
        return {"server": self.server, "tool": self.tool, "args": dict(self.args)}


@dataclass(frozen=True)
class ProofOfPossession:
    challenge: str
    method: str
    path: str
    body: bytes
    signature: str


@dataclass(frozen=True)
class Request:
    call: ToolCall
    token: Mapping[str, Any]
    pop: ProofOfPossession | None = None


@dataclass
class Decision:
    outcome: Outcome
    reason: Reason
    detail: str = ""
    pattern_key: str | None = None
    capability: str | None = None
    resource: str | None = None
    execution_token: dict[str, Any] | None = None
    escalation_id: str | None = None

    @property
    def allowed(self) -> bool:
        return self.outcome in (Outcome.APPROVED, Outcome.AUTO_APPROVED)

    @property
    def activated_boundary(self) -> bool:
        return self.outcome in ACTIVATED


@dataclass
class AdmissionConfig:
    rate_limit_count: int = 20
    rate_limit_window: int = 60
    cooldown_denials: int = 3
    cooldown_duration: int = 300
    execution_token_ttl: int = 30
    challenge_ttl: int = 30

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any] | None) -> AdmissionConfig:
        raw = raw or {}
        return cls(**{k: int(v) for k, v in raw.items() if k in cls.__dataclass_fields__})


def pattern_key(agent_id: str, capability: str, resource: str) -> str:
    """SHA-256(agent ‖ capability ‖ resource) — counters are scoped to context,
    not to the agent, so a burst of harmless reads cannot poison an unrelated
    write."""
    return hashlib.sha256(f"{agent_id}\x1f{capability}\x1f{resource}".encode()).hexdigest()


#: Given a pending escalation record, return True to approve. The default
#: refuses: an unanswered question is not an approval.
EscalationHandler = Callable[[Mapping[str, Any]], bool]


def _refuse(_escalation: Mapping[str, Any]) -> bool:
    return False


def _now(now: int | None) -> int:
    return int(time.time()) if now is None else int(now)


class AdmissionEngine:
    def __init__(
        self,
        store: Store,
        policy: Policy,
        ledger: Ledger,
        issuer_key,
        bindings: Mapping[tuple[str, str], Binding],
        *,
        config: AdmissionConfig | None = None,
        escalation_handler: EscalationHandler = _refuse,
    ):
        self.store = store
        self.policy = policy
        self.ledger = ledger
        self.issuer_key = issuer_key
        self.bindings = dict(bindings)
        self.config = config or AdmissionConfig()
        self.escalation_handler = escalation_handler

    # -- registry ---------------------------------------------------------

    def register_agent(self, agent_id: str, public_key_b64u: str, *, now: int | None = None) -> None:
        with self.store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO agents "
                "(agent_id, public_key, state, denial_count, cooldown_until, registered_at) "
                "VALUES (?, ?, 'active', 0, NULL, ?)",
                (agent_id, public_key_b64u, _now(now)),
            )

    def set_agent_state(self, agent_id: str, state: str) -> None:
        with self.store.write() as conn:
            conn.execute("UPDATE agents SET state=? WHERE agent_id=?", (state, agent_id))

    def issue_challenge(self, *, now: int | None = None) -> str:
        challenge = new_challenge()
        with self.store.write() as conn:
            conn.execute(
                "INSERT INTO challenges (challenge, issued_at) VALUES (?, ?)",
                (challenge, _now(now)),
            )
        return challenge

    # -- evaluation -------------------------------------------------------

    def evaluate(
        self, request: Request, *, now: int | None = None, dry_run: bool = False
    ) -> Decision:
        """Admit or refuse one tool call.

        `dry_run` evaluates every rule and writes nothing — required by the
        counterfactual probe, which must ask "would this be denied?" without
        the asking itself tripping the boundary it is measuring.
        """
        now = _now(now)

        denial = self._authenticate(request, now, dry_run)
        if denial is not None:
            self._record(request, denial, now, dry_run, authenticated=False)
            return denial

        decision = self._authorise(request, now, dry_run)
        if decision.outcome is Outcome.ESCALATED and not dry_run:
            decision = self._resolve_escalation(request, decision, now)

        self._record(request, decision, now, dry_run, authenticated=True)
        return decision

    # -- phase 1 ----------------------------------------------------------

    def _authenticate(self, request: Request, now: int, dry_run: bool) -> Decision | None:
        token = request.token
        subject = token.get("sub") if isinstance(token, Mapping) else None
        if not isinstance(subject, str):
            return Decision(Outcome.DENIED, Reason.TOKEN_MALFORMED, "token has no subject")

        agent = self.store.one("SELECT * FROM agents WHERE agent_id=?", (subject,))
        if agent is None:
            return Decision(Outcome.DENIED, Reason.UNKNOWN_AGENT, f"no such agent: {subject}")

        try:
            tk.verify_capability_token(self.issuer_key.public_key(), token, now=now)
        except tk.SignatureError as exc:
            return Decision(Outcome.DENIED, Reason.BAD_SIGNATURE, str(exc))
        except tk.ExpiredError as exc:
            return Decision(Outcome.DENIED, Reason.TOKEN_EXPIRED, str(exc))
        except tk.DelegationError as exc:
            return Decision(Outcome.DENIED, Reason.BAD_DELEGATION, str(exc))
        except tk.TokenError as exc:
            return Decision(Outcome.DENIED, Reason.TOKEN_MALFORMED, str(exc))

        return self._check_pop(request, agent["public_key"], now, dry_run)

    def _check_pop(
        self, request: Request, public_key_b64u: str, now: int, dry_run: bool
    ) -> Decision | None:
        pop = request.pop
        if pop is None:
            return Decision(Outcome.DENIED, Reason.BAD_POP, "no proof of possession")

        row = self.store.one(
            "SELECT issued_at, consumed_at FROM challenges WHERE challenge=?", (pop.challenge,)
        )
        if row is None:
            return Decision(Outcome.DENIED, Reason.BAD_POP, "unknown challenge")
        if row["consumed_at"] is not None:
            return Decision(Outcome.DENIED, Reason.BAD_POP, "challenge already used")
        if now - row["issued_at"] > self.config.challenge_ttl:
            return Decision(Outcome.DENIED, Reason.BAD_POP, "challenge expired")

        try:
            signature = b64u_decode(pop.signature)
        except (ValueError, TypeError):
            return Decision(Outcome.DENIED, Reason.BAD_POP, "signature not decodable")

        key = public_key_from_bytes(b64u_decode(public_key_b64u))
        message = pop_message(pop.challenge, pop.method, pop.path, pop.body)
        if not verify(key, message, signature):
            return Decision(Outcome.DENIED, Reason.BAD_POP, "proof of possession invalid")

        # Spent whether or not the rest of the request succeeds: consuming the
        # challenge is anti-replay, not a reward for a valid request.
        if not dry_run:
            with self.store.write() as conn:
                conn.execute(
                    "UPDATE challenges SET consumed_at=? WHERE challenge=? AND consumed_at IS NULL",
                    (now, pop.challenge),
                )
        return None

    # -- phase 2 ----------------------------------------------------------

    def _authorise(self, request: Request, now: int, dry_run: bool) -> Decision:
        if dry_run:
            return self._decide(self.store, request, now, dry_run=True)
        with self.store.write() as conn:
            return self._decide(conn, request, now, dry_run=False)

    def _decide(self, conn, request: Request, now: int, *, dry_run: bool) -> Decision:
        token, call = request.token, request.call
        subject = token["sub"]

        agent = _fetch(conn, "SELECT * FROM agents WHERE agent_id=?", (subject,))
        if agent["state"] == "revoked":
            return self._deny(conn, subject, Reason.AGENT_REVOKED, "agent is revoked", now, dry_run)
        if agent["state"] == "suspended":
            return self._deny(conn, subject, Reason.AGENT_SUSPENDED, "agent is suspended", now, dry_run)
        if agent["cooldown_until"] and agent["cooldown_until"] > now:
            return self._deny(
                conn, subject, Reason.COOLDOWN_ACTIVE,
                f"{agent['cooldown_until'] - now}s remaining", now, dry_run,
            )

        binding = self.bindings.get((call.server, call.tool))
        if binding is None:
            return self._deny(
                conn, subject, Reason.TOOL_UNBOUND,
                f"{call.server}/{call.tool} is not bound", now, dry_run,
            )

        try:
            resource = binding.resource_for(call.args, self.policy)
        except ResolutionError as exc:
            return self._deny(conn, subject, Reason.UNRESOLVABLE, str(exc), now, dry_run)

        capability = binding.capability
        pkey = pattern_key(subject, capability, resource)
        scope = {"pattern_key": pkey, "capability": capability, "resource": resource}

        if capability not in token.get("cap", []):
            return self._deny(conn, subject, Reason.CAPABILITY_NOT_GRANTED,
                              f"token does not grant {capability}", now, dry_run, **scope)
        if not tk.resource_matches(token["res"], resource):
            return self._deny(conn, subject, Reason.RESOURCE_OUT_OF_SCOPE,
                              f"{resource} is outside {token['res']}", now, dry_run, **scope)

        # The request counts toward its own window, so the limit is the last
        # call that passes rather than the first that trips.
        if not dry_run:
            conn.execute("INSERT INTO pattern_events (pattern_key, ts) VALUES (?, ?)", (pkey, now))
        rate = self._rate(conn, pkey, now) + (1 if dry_run else 0)

        if binding.requires_review:
            return self._raise_escalation(conn, subject, Reason.REQUIRES_REVIEW,
                                          call, now, dry_run, **scope)
        if rate > self.config.rate_limit_count:
            return self._raise_escalation(
                conn, subject, Reason.RATE_LIMIT, call, now, dry_run,
                detail=f"{rate} within {self.config.rate_limit_window}s", **scope,
            )
        return self._approve(subject, call, now, dry_run, **scope)

    # -- outcomes ---------------------------------------------------------

    def _rate(self, conn, pkey: str, now: int) -> int:
        row = _fetch(
            conn, "SELECT COUNT(*) AS n FROM pattern_events WHERE pattern_key=? AND ts > ?",
            (pkey, now - self.config.rate_limit_window),
        )
        return int(row["n"])

    def _approve(self, subject, call, now, dry_run, *, pattern_key, capability, resource) -> Decision:
        et = None
        if not dry_run:
            et = tk.issue_execution_token(
                self.issuer_key, subject=subject, capability=capability, resource=resource,
                action=call.action(), now=now, ttl=self.config.execution_token_ttl,
            )
        return Decision(Outcome.APPROVED, Reason.OK, pattern_key=pattern_key,
                        capability=capability, resource=resource, execution_token=et)

    def _deny(self, conn, subject, reason, detail, now, dry_run, *,
              pattern_key=None, capability=None, resource=None) -> Decision:
        if not dry_run:
            self._count_denial(conn, subject, now)
        return Decision(Outcome.DENIED, reason, detail, pattern_key=pattern_key,
                        capability=capability, resource=resource)

    def _raise_escalation(self, conn, subject, reason, call, now, dry_run, *,
                          pattern_key, capability, resource, detail="") -> Decision:
        """Record a pending escalation. The human is asked after this commits."""
        escalation_id = b64u_encode(secrets.token_bytes(12))
        if not dry_run:
            conn.execute(
                "INSERT INTO escalations (id, agent_id, capability, resource, action_sha256, "
                "reason, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (escalation_id, subject, capability, resource,
                 tk.action_hash(call.action()), str(reason), now),
            )
        return Decision(Outcome.ESCALATED, reason, detail, pattern_key=pattern_key,
                        capability=capability, resource=resource, escalation_id=escalation_id)

    def _resolve_escalation(self, request: Request, pending: Decision, now: int) -> Decision:
        """Ask the human, outside any transaction, then record the answer."""
        record = {
            "id": pending.escalation_id,
            "agent_id": request.token["sub"],
            "capability": pending.capability,
            "resource": pending.resource,
            "reason": str(pending.reason),
            "detail": pending.detail,
        }
        self.ledger.append(EventType.ESCALATION_RAISED, record, now=now)

        try:
            approved = bool(self.escalation_handler(record))
        except Exception:  # noqa: BLE001 — deliberately broad
            # The handler is arbitrary caller code: a CLI prompt now, a preset
            # engine or a web UI later. Any failure in it must refuse rather
            # than propagate, or a crashed approver leaves the escalation
            # pending and the denial unrecorded.
            approved = False

        with self.store.write() as conn:
            conn.execute(
                "UPDATE escalations SET state=?, resolved_at=? WHERE id=?",
                ("approved" if approved else "refused", now, pending.escalation_id),
            )
            if not approved:
                # A refused escalation became a denial, and counts as one.
                self._count_denial(conn, request.token["sub"], now)

        self.ledger.append(
            EventType.ESCALATION_RESOLVED,
            {"id": pending.escalation_id, "approved": approved}, now=now,
        )
        if approved:
            return self._approve(
                request.token["sub"], request.call, now, False,
                pattern_key=pending.pattern_key, capability=pending.capability,
                resource=pending.resource,
            )
        return Decision(Outcome.DENIED, Reason.ESCALATION_REFUSED, pending.detail,
                        pattern_key=pending.pattern_key, capability=pending.capability,
                        resource=pending.resource, escalation_id=pending.escalation_id)

    def _count_denial(self, conn, subject: str, now: int) -> None:
        conn.execute("UPDATE agents SET denial_count = denial_count + 1 WHERE agent_id=?", (subject,))
        row = _fetch(conn, "SELECT denial_count FROM agents WHERE agent_id=?", (subject,))
        if row["denial_count"] >= self.config.cooldown_denials:
            until = now + self.config.cooldown_duration
            # Reset the count with the lock, or the agent re-locks the instant
            # its first cooldown expires.
            conn.execute(
                "UPDATE agents SET cooldown_until=?, denial_count=0 WHERE agent_id=?",
                (until, subject),
            )
            self.ledger.append(
                EventType.COOLDOWN_STARTED, {"agent_id": subject, "until": until}, now=now
            )

    # -- recording --------------------------------------------------------

    def _record(self, request, decision, now, dry_run, *, authenticated) -> None:
        if dry_run:
            return
        self.ledger.append(
            EventType.AUTHORIZATION,
            {
                "decision": str(decision.outcome),
                "reason": str(decision.reason),
                "authenticated": authenticated,
                "server": request.call.server,
                "tool": request.call.tool,
                "capability": decision.capability,
                "resource": decision.resource,
                "detail": decision.detail,
            },
            now=now,
        )


def _fetch(conn, sql: str, params: tuple) -> sqlite3.Row:
    """Read through either a Store (dry run) or a live connection."""
    if isinstance(conn, Store):
        return conn.one(sql, params)
    return conn.execute(sql, params).fetchone()
