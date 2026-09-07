# Design

Architecture and rationale for `agent-server`: a multi-agent system where the
planner holds no operational capability and the executors hold narrowly scoped,
cryptographically bound authority that a containment layer can revoke,
rate-limit or deny mid-run.

Status: architecture converged, implementation starting at M0.

---

## 1. What this is

The distinguishing claim is not "agents with permissions". It is that **no
component holding a language model is trusted, including the planner**, and the
system's safety properties are meant to hold anyway.

Most agent frameworks treat the orchestrator as trusted because it is the
operator's own code path. It is not. A planner that reads task descriptions,
tool results and subagent output is a planner that can be steered by any of
them.

## 2. Threat model and trust boundaries

This is the spine of the design; everything else follows from it.

**Trusted** — deterministic, auditable, small:

- the containment server: admission engine, ledger, secret vault
- the supervisor: control plane, role catalog, budgets
- the human at the escalation queue

**Untrusted** — contains or is driven by a language model:

- the governor
- every subagent

The governor is untrusted **not because it is malicious but because it is an
LLM reading untrusted data** — task descriptions, subagent outputs, tool
results — any of which can carry an injection. This is an established attack
class against deployed systems, not a hypothetical one (Greshake et al., 2023);
see §8.4.

### 2.1 The claim

An LLM that originates goals cannot be made trustworthy. So the property
claimed here is not trust, it is **bounded authority**:

> The governor's effects on the world are confined to what the supervisor's
> rules admit, regardless of what the model decides to want.

That is checkable. "The governor is safe" is not. Every decision below follows
from preferring the checkable claim.

### 2.2 Core invariant

An action executes only if all four predicates hold simultaneously:

```
Execute(action) => ValidIdentity(agent)
                 & ValidCapability(action in token.cap & resource in token.res)
                 & ValidDelegation(chain verified, depth <= max)
                 & Admissible(state, action)
```

Any predicate failing denies the action. Any *component* failing denies the
action — **fail closed, always**, including on internal error, timeout, or an
unreachable dependency. There is no default-allow path anywhere in the system.

## 3. Architecture

```
        UNTRUSTED                    │              TRUSTED
                                     │
   ┌─────────────┐                   │   ┌──────────────────────────────┐
   │  GOVERNOR   │  structured goal  │   │        SUPERVISOR            │
   │ (via        │──── output ──────────►│  owns the loop               │
   │  OpenRouter)│◄─── state digest ─────│  role catalog · budgets      │
   └─────────────┘   (injected)      │   │  spawn / kill / bind         │
      no tools                       │   └──────────┬───────────────────┘
                                     │              │
   ┌─────────────┐                   │   ┌──────────▼───────────────────┐
   │  SUBAGENT   │  call + PoP       │   │   CONTAINMENT SERVER         │
   │ (sandboxed) │──────────────────────►│   admission · ledger         │
   │  no creds   │◄──── ET / DENY ───────│   vault · escalation queue   │
   └──────┬──────┘                   │   └──────────┬───────────────────┘
          │ ET                       │              │ ESCALATE
          ▼                          │         ┌────▼─────┐
   ┌──────────────────────────────┐  │         │  HUMAN   │
   │        MCP GATEWAY           │  │         └──────────┘
   │  verify → inject real creds  │  │
   │  → call tool → report used   │  │
   └──────────────┬───────────────┘  │
                  ▼                  │
        real MCP servers / tools     │
```

Four decisions are embedded here:

1. **Gateway and containment server are one process in v0** — two modules with
   a clean interface. Splitting them is a deployment concern; splitting early
   doubles the debugging surface.
2. **Secrets never cross the boundary.** A subagent authorised to read a repo
   never receives a token; it receives an Execution Token, and the gateway
   attaches the real credential on the way out. This is what makes the system
   containment rather than governance.
3. **Sandboxing is load-bearing, not decorative.** A subagent that can open an
   arbitrary socket routes around everything above. See §9.1.
4. **Two state machines per subagent, kept separate.** Conflating them destroys
   the ability to explain a denial.

### 3.1 Subagent state machines

**Lifecycle** — orchestration, owned by the supervisor:

```
spawned → bound → running → { completed | killed | faulted }
```

`bound` is where the capability token is issued. Capabilities cannot be
attached to an already-`running` agent: no runtime privilege mutation.

**Risk state** — admission, owned by the containment server:

```
{ denial_count, pattern_count[PatternKey], cooldown_until, last_decision }
```

## 4. Control plane — the supervisor

### 4.1 Inversion of ownership

The deterministic mechanism does not live *inside* the governor as something
the governor calls — a compromised governor could decline to call it.

**The supervisor owns the loop.** It invokes the model, receives output,
validates, decides, acts, and injects results into the next turn. The LLM is a
subroutine of a deterministic program, not a program that consults a
deterministic helper.

The consequence is that **the governor has no callable tools at all in v0**. It
emits structured output, which the supervisor schema-validates. Everything the
governor knows about system state is injected by the supervisor each turn
rather than fetched by the governor. A read-only ledger query can be added
later if it demonstrably needs one.

### 4.2 What a deterministic supervisor can decide

The honest limit: **it cannot evaluate what a goal means, and must not pretend
to.** Deterministic code cannot judge whether "summarise the quarterly data" is
a reasonable thing to want. Rules that pretend to judge intent are brittle and
give false assurance. Refusing to build them is part of the design.

What it enforces instead, totally and cheaply:

- **Role catalog.** A fixed set of subagent roles, each with a capability set
  *and a behaviour tree* (§4.8) frozen at config time. The governor *selects* a
  role and supplies parameters; it can never *define* a capability set or
  compose a tree. This is the largest single reduction in attack surface — it
  collapses the governor's output space from "arbitrary capability request" to
  a small enum, and bounds not only what a subagent may reach but the shape of
  what it will attempt.
- **Budgets.** Max concurrent subagents, max spawns per task, max wall-clock,
  max tool calls per subagent and in total. Kills the runaway and amplification
  failure class outright.
- **Subset check.** requested ⊆ role's frozen set ⊆ governor's ceiling,
  verified cryptographically at the delegation hop.
- **Lifecycle legality.** No killing nonexistent agents, no binding
  capabilities to running ones, no resurrection.

### 4.3 Governor output contract

The governor emits one structured object per turn, in response to an
observation (§4.6). Everything in it is **hostile input to the supervisor** —
schema-validate, reject on any deviation, log the rejection. The supervisor
must never string-match model output to make a decision.

```json
{
  "observed": "<version string from the observation this answers>",
  "reasoning": "<free text, logged, never parsed>",
  "actions": [
    { "op": "spawn", "role": "<enum from catalog>", "params": {}, "budget": {} },
    { "op": "kill",  "agent_id": "<known id>" },
    { "op": "wait" },
    { "op": "conclude", "summary": "<free text>" }
  ]
}
```

Validation is deterministic and total:

- **An unknown key anywhere rejects the whole turn.** Not "ignore unexpected
  fields": an unexpected key means the model is doing something the design does
  not cover, and silently dropping it hides exactly that.
- **`observed` must match the current state version, or the batch is rejected
  whole.** The governor plans against a snapshot and the world moves while it
  thinks — a subagent exits, a budget fills. Applying half a plan against a
  changed world is worse than discarding it, so this is ordinary optimistic
  concurrency control: compare the version, re-observe, re-plan. The rejection
  rate is itself data; if it is high, the observation is being assembled too
  early or the model is too slow for the tick rate.
- **Empty `actions` means `wait`**, not an error.
- Actions execute **in order**, and every one is recorded with its outcome even
  if an earlier one failed. The supervisor is deterministic, so there is no
  reason to abandon the batch partway.
- **There is no cap on action count.** `max_concurrent` already refuses a spawn
  that cannot run, so a separate limit would be a second mechanism enforcing
  the same property, with its own failure modes and nothing to show for it.
- A rejected turn costs a turn and is logged. **N consecutive rejections end
  the run** — a governor that cannot emit valid output will not start.

### 4.4 The escalation rule

**The governor cannot resolve its own escalations.** If ESCALATE routed back to
the planner for approval, escalation would be decorative — an untrusted
component auditing itself. Escalations go to the human queue. In v0 that is a
CLI prompt.

### 4.5 Return channel

Subagent status flows back through the supervisor, **normalised to a fixed
schema** — state, exit reason, denied-action count, bounded output field. Never
raw stdout. Two reasons: raw output lets a subagent inject the planner, and it
lets two subagents pass messages through the governor and coordinate. The
second is the collusion channel that control evaluations take pains to close
between untrusted instances (Greenblatt et al., 2024); normalising the return
channel is what closes it here.

### 4.6 Observation

The governor has no tools, so everything it knows arrives here. Observation is
a **closed feedback loop**, not a status report: the supervisor senses the
environment, the governor decides, the supervisor acts, the actions change the
environment, and the next observation reflects that change.

The distinction matters because the obvious design is not a loop. Reporting
"your spawn succeeded, your subagent's call was denied" tells the governor what
happened to its *paperwork* and nothing about the world. The test for whether
the loop is genuinely closed: **if a subagent writes a report, does the next
observation show that the file exists?** If it only shows that the subagent
finished, this is an acknowledgement channel wearing a loop's clothes.

| field | contents |
|---|---|
| `version` | monotonic; the governor echoes it back (§4.3) |
| `roles` | available roles, their capabilities and resource scope — the action vocabulary |
| `environment` | resources currently present under the roots, structured and capped |
| `roster` | live subagents: lifecycle state, budget used, denied-action count |
| `outcomes` | last turn's actions with reason codes |
| `budgets` | what remains |

**Observation is scoped by the governor's own ceiling.** If the ceiling covers
`workspace/reports/**`, the environment view shows what is under
`workspace/reports/`, and nothing else. Least privilege applies to information,
not only to authority: an untrusted component learning about resources it can
never legitimately touch is free reconnaissance that buys nothing. This also
means observation and action derive from the *same* ceiling, so there is one
thing to get right rather than two.

**Assembled fresh each turn, never accumulated.** The observation is a function
of current state rather than an appended transcript, which removes the
truncation problem entirely: there is no growing history to decide where to cut.
Anything the governor needs to persist across turns it must carry in its own
output.

**Everything in it is tainted.** Filenames, directory structure and subagent
results are all attacker-influenceable. They are rendered as structured,
length-capped fields and never interpolated into instruction prose. As
throughout, this degrades usefulness rather than safety: the governor's
authority does not depend on what it believes.

**What it never contains:** the ledger, the binding table, operator keys,
configuration, or escalations belonging to other agents. The governor sees
decisions about its own requests; it never sees the mechanism that produced
them.

### 4.7 The loop and termination

```
observe()  → observation (version v)
decide()   → governor answers, asynchronously
validate() → schema, then version v
act()      → dispatch in order, record every outcome
```

**The governor is dispatched asynchronously and its pending status is a
variable, not a state of the loop.** The supervisor keeps servicing subagents,
escalations and budgets while the model is thinking; a slow response is dropped
on timeout rather than allowed to stall supervision. A synchronous call would
make every other guarantee hostage to model latency.

**Termination does not depend on the model choosing to stop.** `conclude` is an
action the governor emits, so a governor that never emits it must still be
stopped:

```
halt = no progress for N turns          convergence
     ∨ turn / spawn / wall-clock budget exhausted
     ∨ N consecutive schema or version rejections
     ∨ operator abort
     ∨ conclude                          the only model-supplied ending
```

The hard caps end the run regardless of what the model does, which is what
removes any need to reason about whether it *would* stop. Convergence and
success are recorded separately: a run can settle without achieving anything,
and conflating them would let a stalled governor report victory.

Every ending records which guard fired. "How did this run stop" is data for the
evaluation, not an implementation detail.

### 4.8 Subagents as behaviour trees

A role's behaviour is a **behaviour tree** — the control structure standard in
game AI and robotics — authored by the operator and frozen in the catalog.
Minimal node set: `Sequence`, `Selector`, `Condition`, `Action`, with the usual
`Success` / `Failure` / `Running` status.

Three properties earn it a place:

- **Behaviour is bounded, not just authority.** Containment already limits what
  a subagent may reach. A tree also limits what it will attempt, which is what
  makes a role a narrow executor rather than a small general agent wearing a
  capability set.
- **A containment refusal is ordinary control flow.** A denied call returns
  `Failure` and the enclosing `Selector` takes its fallback branch. Without a
  tree, "the call was denied, now what" has to be improvised somewhere.
- **The model shrinks to a leaf.** It is consulted to choose the next call from
  the role's vocabulary, or to produce a summary — never to drive control flow.

**The governor never composes a tree.** It selects a role, and the role is a
tree. Allowing an untrusted planner to compose behaviour would hand back the
authority §4.2 exists to remove.

One consequence worth stating for §12: a subagent whose next action is a pure
function of our code cannot be injected at all, and E2 would then measure
nothing. The model-chooses-next-call leaf is what gives an injection something
to pull on. A tree with no such leaf is a script, which is a legitimate role
shape — but roles used in E2 must contain one.

## 5. Data plane — the admission engine

Every tool call is admitted or refused individually, with state.

### 5.1 Why stateless permissions are insufficient

A stateless engine evaluates each request in isolation and therefore cannot
enforce any property defined over an execution *trace*. A permission list can
express "this agent may write files". It cannot express "this agent may not
write its 40th file in ninety seconds".

### 5.2 Rule set

Explicit rules that plainly pass or fail. No risk score: the ACP paper's
RS = B(c) + F_res + F_ctx + F_hist + F_anom with thresholds at 40/70 is
invented constants dressed as specification, and is deliberately not used here.

**Evaluation happens in two phases, and the split is a security property, not
an implementation detail.**

If a signature or proof-of-possession fails, the claimed AgentID cannot be
trusted. Incrementing that agent's counters would then let anyone lock out
anyone: three malformed requests stamped with a victim's AgentID, sent by an
attacker holding no key at all, and a legitimate subagent is in cooldown.

```
Phase 1 — authenticate        no state may move
    1  DENY  bad signature, or bad proof-of-possession
    2  DENY  token expired or malformed
    3  DENY  delegation chain invalid or too deep

Phase 2 — authorise           state moves, in one transaction
    4  DENY      agent suspended or revoked
    5  DENY      cooldown active
    6  DENY      tool unbound, or the resolver refused the arguments
    7  DENY      capability not in token, or resource out of scope
    8  ESCALATE  binding requires review
    9  ESCALATE  PatternKey rate over limit
   10  ALLOW     issue an execution token
```

First match wins, and the order is load-bearing because the *reason code* is
what the evaluation counts (E1, E4). Rule 6 precedes rule 7 deliberately: if
the resolver cannot name the resource there is nothing to scope-check, so
"unresolvable" is the honest reason rather than "out of scope".

Rules 5 and 9 are the stateful part — what a permission list cannot express. A
permission list can say "this agent may write files"; it cannot say "not its
fortieth write in ninety seconds".

### 5.3 PatternKey and the rate window

```
PatternKey(a, c, r) = SHA-256(agent_id ‖ capability ‖ resource)
```

Anomaly counters are keyed by *context*, not by agent. Keying by agent alone
lets a burst of harmless reads poison the score on an unrelated write, which
produces false denials a stateless engine would never generate. Building it
context-scoped costs one SHA-256 call.

**The rate window slides.** A tumbling window — fixed buckets, counter reset at
each boundary — is cheaper, but a burst straddling a boundary passes up to
twice the limit while no bucket ever exceeds it. At the throughput this system
sees, storing a timestamp per authenticated request and counting those inside
the trailing window is exact and costs nothing, so there is no reason to accept
a rule that can be doubled by timing.

**What moves the state:**

| Event | Effect |
|---|---|
| any *authenticated* request | append to that PatternKey's event log |
| final DENY | `denial_count += 1` |
| ESCALATE | nothing — an escalation is not yet a denial |
| escalation refused by a human | `denial_count += 1` — it became one |
| `denial_count ≥ N` within `W` | `cooldown_until = now + D`, count reset |

Resetting the count when the cooldown is set matters: without it the agent
re-locks the instant its first lock expires.

### 5.4 Two checkpoints

| | Supervisor (control plane) | Admission engine (data plane) |
|---|---|---|
| Question | May this goal become a subagent with these capabilities? | May this tool call execute right now? |
| State | Role catalog, budgets, agent graph | Tokens, rate counters, cooldowns, denial history |
| Fires at | Governor turn boundary | Every tool invocation |
| Stops | Runaway spawning, privilege creep | Injected / out-of-scope actions, floods |

Both fail closed. Both write to the same ledger. Kept rigorously separate.

### 5.5 Tool bindings

Tools are not implemented here. They are provided by MCP servers, which means
the tool surface is dynamic, externally controlled, and untrusted. What this
system owns is the **binding**: the mapping from a tool call to the
`(capability, resource)` pair admission reasons about.

That mapping is where containment actually lives. A server declares
`{"path": {"type": "string"}}`; that the argument is a path, that paths must be
resolved before comparison, and that the resolved path is what the scope check
sees, is entirely our interpretation. Get it wrong and every signature still
verifies, every rule still fires, and the boundary is decorative — a token
scoped to `workspace/**` admits `workspace/../../etc/passwd`, because as a raw
string it matches.

**Bindings are signed rows, not code.** A binding lives in the state backend:

```
(server, tool) -> capability, resolver, resolver_config,
                  schema_sha256, requires_review, credential_ref,
                  issued_by, sig
```

Adding a tool is an `INSERT`, not a release. The row is signed by an operator
key and admission verifies that signature on load, so an unsigned or
badly-signed row is invisible — exactly as for a capability token. Whoever can
write the database gains nothing without the key, which makes the store a
transport rather than a trust boundary.

**Resolvers are code.** `resolver` names one of a small fixed set —
`path_under_root`, `url_host`, `literal_field` — each implemented and tested
once. Extraction cannot be data: resolving `../`, or getting the host out of
`http://allowed.com@evil.com/`, is parsing, and a mini-language for
security-critical parsing evaluated from a mutable store is strictly worse than
a reviewed function. So: adding a tool of a known shape is a row; adding a new
*kind* of resource is a release. The common operation is data, the rare one is
code.

Three rules bound what a signed binding can do:

- **Capabilities declare which resolver kind they accept.** `cap:fs.read`
  accepts only `path_under_root`. A binding whose resolver does not match its
  capability is rejected at load. Since a call is admitted only if extraction
  *succeeds*, a tool with no nameable resource has no valid resolver and
  therefore cannot be bound at all — §4.2's "a tool whose resource cannot be
  named cannot be contained", enforced mechanically rather than by discipline.
- **New bindings are born requiring review.** `requires_review` defaults to
  set. The tool works immediately, but every call escalates to the human until
  a second signed row promotes it. A mistaken binding costs a prompt, not a
  breach.
- **Extraction may refuse.** Unparseable arguments are a denial, not a resource
  equal to the raw string.

**The advertised tool list is untrusted input.** Bindings are keyed by
`(server, tool)`, never tool name alone. A tool advertised but unbound is
denied — never "unknown, therefore allowed". And the declared input schema is
pinned by hash: a server that redefines a bound tool's arguments has that tool
disabled until someone re-pins it deliberately, because otherwise `resolver`
keeps reading a field that no longer means what it did. Tool *descriptions* are
untrusted text that reaches the model; they never reach the supervisor and
never influence admission, which reads `(server, tool, args)` and nothing else.

### 5.6 State backend

SQLite, holding both the signed bindings and the admission counters
(`pattern_count` per PatternKey, `denial_count`, `cooldown_until`).

One store rather than two, for a reason beyond tidiness: admission must read
counters, decide, and write both the decision and the updated counters **in a
single transaction**. Without that, two concurrent calls both read "two
denials" and are both approved when the third should have been refused — the
enforcement property is lost precisely under the load that matters. Serializable
evaluate-then-mutate is what makes the stateful rules in §5.2 true rather than
approximately true.

Admission opens the database read-only. Mutation goes through a separate path
that writes the corresponding ledger entry in the same transaction, so a
capability grant changing is as auditable as a denial.

### 5.7 Escalation

An escalation blocks the call and asks a human. In v0 that is a CLI prompt,
answered synchronously, with a timeout that **denies on expiry** — an
unanswered question must not become an approval.

Synchronous is the honest v0 choice and it has a cost worth naming: one
unanswered prompt stalls the supervisor loop, because the subagent's call is
still waiting. Asynchronous escalation — refuse now with `escalated`, let the
governor re-plan or wait, resolve out of band — is more faithful to a real
deployment and is post-v0.

**Rule presets** are planned: operator-configured rules that auto-approve
classes of escalation, so the same question is not asked repeatedly. They are a
generalisation of promoting a binding out of review.

They carry a specific hazard and it is the one in §8.7. Auto-approval is
exactly the mechanism that produces deviation collapse: approve enough
automatically and the boundary stops activating, BAR falls toward zero, and a
working containment layer becomes indistinguishable from a dormant one. So
auto-approvals are recorded as a **distinct outcome** in the ledger rather than
folded into `approved`, and E4 reports Boundary Activation Rate both with and
without them. A feature that quietly eats the metric proving the system works
is worse than no feature.

## 6. Cryptographic mechanisms

### 6.1 Identity

```
AgentID = base58(SHA-256(public_key))
```

A username is a claim; a key is a proof. Identity is demonstrated per request,
never asserted. Keypairs are generated per subagent at spawn; the private key
never leaves the subagent's sandbox, the public key is registered with the
containment server.

### 6.2 Capability Token

Issued at `bound`. Signed JSON, Ed25519.

```json
{
  "ver": "1.0",
  "iss": "<AgentID of supervisor>",
  "sub": "<AgentID of subagent>",
  "cap": ["cap:fs.read", "cap:fs.write"],
  "res": "workspace/reports/**",
  "exp": 1757200000,
  "nonce": "<128-bit CSPRNG, base64url>",
  "deleg": { "allowed": false, "max_depth": 0 },
  "parent_hash": "<hash of issuer's own token>",
  "sig": "<Ed25519 over JCS canonical form of all fields except sig>"
}
```

`exp` is mandatory — a token without expiry is invalid by definition.
Signature verification precedes all semantic validation; an object with a bad
signature is rejected without its content being read.

### 6.3 Proof of possession

Holding a token is not sufficient to act. Per request:

1. Server issues a 128-bit CSPRNG challenge, valid 30s, single use.
2. Agent signs `challenge ‖ method ‖ path ‖ SHA-256(body)`.
3. Server verifies against the registered public key.
4. Challenge is deleted; it cannot be reused.

This yields identity authentication, request binding and replay resistance in
one step. A stolen token is inert without the private key.

### 6.4 Execution Token

Authorisation and execution are separate. On ALLOW the engine returns an ET:
single-use, short-lived, naming exactly this action on this resource at this
moment. Second presentation is rejected. An expired ET is invalid even if never
used. The gateway reports consumption back, closing the audit loop.

The ET — not the ledger — is the artifact that actually gates state mutation.

This is also what keeps the gateway from becoming a confused deputy (Hardy,
1988). The gateway holds real credentials and acts on requests from a strictly
less-authorised party; if it carried ambient authority and simply took a
subagent's word for what to do with it, that is the classic failure. Per-action
execution tokens mean the gateway never exercises authority it was not handed
for that one action.

### 6.5 Delegation

Depth 1 in v0 (supervisor → subagent; no sub-subagents). The mechanism is still
built properly because it is the governor's ceiling: each token carries
`parent_hash`, verifiers walk the chain to a root, and **at every hop the
child's capability set must be a subset of the parent's**. Revoking a parent
invalidates all descendants transitively. The ceiling is enforced by arithmetic
on sets, not by the governor behaving.

### 6.6 Ledger

Append-only, hash-chained:

```
h_n = SHA-256(entry_n ‖ h_{n-1})
```

Records every decision — APPROVED, ESCALATED, DENIED — plus token
issue/revoke/consume and lifecycle transitions. Tamper-**evident**, not
tamper-proof: it does not prevent editing the file, it makes an edit
undeniable.

The ledger is evidence, not enforcement. It is also the entire empirical
dataset (§12), which is why it exists at M0 rather than being retrofitted.

## 7. The governor

Runs through **OpenRouter** using the OpenAI SDK — OpenRouter is
OpenAI-compatible and ships no SDK of its own. The model is a `vendor/model`
slug in `config/governor.yaml`, never hardcoded: swapping the governor's model
must not require a code change, and it is a variable the evals sweep.

The governor has no tools. It does not tool-call; it emits one structured
object per turn, requested via `response_format` json_schema where the routed
model supports it.

**Structured output is best-effort.** Support varies by model and by the
provider actually serving the request, so malformed or non-conforming output is
a *normal* case here, not an exceptional one. It lands as a schema rejection,
is logged to the ledger, and costs the governor a turn.

**Model output is never repaired to make it parse.** Silently fixing it up is
how an injected instruction gets laundered into a valid-looking action.

One property worth stating: routing an untrusted component through a third
party we do not control changes nothing about the security model. The governor
was already untrusted. That the architecture is indifferent to where it runs is
a demonstration of the design holding, not a compromise.

## 8. Prior art

Very little of the machinery below is new. This section separates what is
inherited — and from whom — from the small set of choices that are actually
this project's own. Full entries are in the References section.

### 8.1 Capability security

The token model is textbook object-capability design, not a recent invention.
Authority as an unforgeable, transferable reference dates to Dennis and Van
Horn (1966); the modern treatment of capabilities as the unit of access
control, including delegation that cannot amplify authority, is Miller (2006).
The principles the system is built to satisfy — least privilege, fail-safe
defaults, complete mediation, economy of mechanism — are Saltzer and Schroeder
(1975), and §2.2's fail-closed invariant is a restatement of fail-safe
defaults.

Concretely: §6.2's capability token, §6.5's subset-preserving delegation, and
the refusal to use bearer credentials (Appendix A) all follow from that
literature rather than from anything specific to LLM agents.

### 8.2 Enforcing properties over execution traces

§5.1's argument — that a stateless engine cannot enforce properties defined
over an execution trace — is a restatement of Schneider (2000). The formal
result is that a reference monitor observing a program's execution can enforce
exactly the safety properties expressible as a security automaton, which is
precisely the class "no 40th write in ninety seconds" belongs to and "may write
files" does not.

This matters for how the claim is stated. Stateful admission is not a novel
mechanism; it is a security automaton with a particular alphabet. What is
specific here is the alphabet — capability-scoped tool calls — and the choice
to key the automaton's state by context (§5.3) rather than by principal.

### 8.3 Tamper-evident logs

§6.6's hash chain is Haber and Stornetta (1991). The property it provides is
detection, not prevention, and the design says so.

### 8.4 Indirect prompt injection

The threat model in §2 rests on indirect prompt injection being a real and
practical attack rather than a hypothetical one: an LLM that reads attacker-
influenced content — retrieved documents, tool results, another agent's output
— can be made to act on instructions embedded in that content. Greshake et al.
(2023) demonstrated this against deployed LLM-integrated applications and
established the threat class this system is built around.

This is the entire justification for treating the governor as untrusted. It is
not a claim about model alignment; it is a claim about where the model's input
comes from.

### 8.5 Agent containment and AI control

Two lines of work sit closest to this design.

**CaMeL** (Debenedetti et al., 2025) extracts control and data flow from a
*trusted* query: a privileged LLM plans from the trusted prompt and never sees
untrusted data, while a quarantined LLM handles untrusted content and cannot
act, with capabilities enforced at tool invocation to prevent exfiltration. It
reports 77% utility on AgentDojo against 84% undefended.

This is the nearest prior art and the difference is worth stating precisely.
CaMeL's central move — keeping the planner clean — is unavailable here, because
this governor *does* read untrusted data by design: it re-plans on subagent
outputs, tool results and statuses. The response is not to protect the planner
but to stop trusting it, and to constrain it structurally instead (§4.1, §4.2).
**The threat model here is therefore strictly harder than CaMeL's**, and the
mechanisms differ accordingly: cryptographic identity, a multi-agent lifecycle,
human escalation, and admission over execution *traces* rather than per-call
dataflow. The two are complementary rather than competing.

**AI control** (Greenblatt et al., 2024) is the methodological home of the
untrusted-model framing. It evaluates protocols — trusted editing, trusted and
untrusted monitoring — against a deliberately subversive policy, with a red
team writing the untrusted model's strategy and a blue team writing the
protocol.

One structural difference matters. In that literature the *trusted* component
is a weaker model: GPT-3.5 monitoring GPT-4. Here the trusted component is
deterministic code — a supervisor and an admission engine with no model in
them. There is no monitor to persuade, no judgement to argue with, and no
second untrusted instance to collude with. The cost is exactly the one conceded
in §4.2: deterministic code cannot evaluate what a goal means, so this design
buys unfoolability by giving up semantic judgement, and compensates by
collapsing the planner's output space (§4.2) rather than by inspecting its
intent.

That literature also supplies the name for a hazard §4.5 addresses
independently: preventing untrusted instances from colluding.

### 8.6 Agent Control Protocol

Fernandez (2026) is a self-published draft standard, not peer-reviewed. It is
the most direct prior art for the specific problem of admitting agent actions,
and several concrete shapes here come from it.

**Adopted:** the four-predicate invariant as a single formulation (§2.2); the
separation of authorisation from execution into a capability token plus a
single-use execution token (§6.2, §6.4); PatternKey context scoping and the
cross-context state-mixing failure it fixes (§5.3); and — the most valuable
borrowing — deviation collapse and Boundary Activation Rate (§8.7 below, E4 in
§12).

**Not adopted:**

- *The risk score.* `RS = B(c) + F_res + F_ctx + F_hist + F_anom`, thresholds at
  40 and 70, `+20` for a non-corporate IP, `+15` for outside business hours.
  These are hand-tuned constants with no derivation or empirical justification
  given. The explicit rule set in §5.2 covers the same ground and can be
  explained to a reader.
- *Inter-institutional trust anchors, mutual recognition, reputation snapshot
  portability, B2B conformance levels.* Multi-organisation enterprise plumbing,
  irrelevant to a single-operator system.
- *The performance framing.* The paper leads with 739 ns decision latency and
  1.72M req/s. This system makes tens of decisions per minute.

**Adopted but deferred:** TLA+ verification and signed conformance vectors are
good practice and out of scope for v0.

A note on attribution: the paper is sometimes read as introducing capability
tokens and stateful enforcement to agent systems. It does not — those are
§8.1 and §8.2 above, and the paper cites Schneider itself. Its contribution is
the assembly and the two items named below.

### 8.7 Deviation collapse

The one idea taken wholesale. Fernandez (2026) identifies a failure mode in
which the enforcement engine is perfectly correct and *never fires*, because
upstream stages have removed every signal that could have triggered it.
Invariants hold, verification passes, and the boundary is simply never reached.

This is directly relevant: a competent governor will mostly plan safe tasks, so
without instrumentation there is no way to distinguish "containment works" from
"containment is a no-op". The detector is Boundary Activation Rate — the
fraction of decisions that were not APPROVED — together with a counterfactual
probe that submits mutated requests and confirms the engine *can still* produce
DENIED. Both land at M1 rather than at the end, and E4 (§12) exists because of
this paper.

### 8.8 Positioning

**No research contribution is claimed.** Every mechanism here is inherited from
one of the sections above; this is an engineering synthesis, and the sections
below list what it chooses differently, not what it invents. The list exists so
a reader can see which decisions are deliberate rather than accidental:

- **Inversion of loop ownership.** The deterministic supervisor invokes the
  model, rather than the model invoking a deterministic helper it could decline
  to call (§4.1). The governor holds no callable tools at all.
- **The untrusted-planner position.** Treating the orchestrator — not only the
  executors — as an untrusted component, and stating the resulting property as
  bounded authority rather than trust (§2.1).
- **The role catalog as output-space collapse.** Restricting the planner to
  selecting from frozen capability sets rather than describing capabilities,
  which converts an open-ended attack surface into a small enum (§4.2).
- **Two separated checkpoints.** Control-plane and data-plane admission kept
  structurally distinct so that any denial has a single explicable cause
  (§5.4).
- **Governance versus containment.** The insistence that a protocol boundary is
  not a substrate boundary, which makes the sandbox a load-bearing security
  component rather than a deployment detail (§9.1).
- **The no-repair rule.** Malformed planner output is a schema rejection, never
  something to fix up, because repairing it is a laundering path for injected
  instructions (§7).

None of these is offered as novel. Two are at least positions worth defending
in the terms §8.5 sets out — a trusted component that is deterministic code
rather than a weaker model, and a planner treated as untrusted despite reading
untrusted data — but they are design stances, not results. The contribution
this project aims at is a working, instrumented, honestly-measured system, not
a new idea.

## 9. Known limitations

### 9.1 Sandboxing is the weakest link

Governance sits between an agent's decision and a tool's execution and assumes
nothing routes around it. Containment is strictly stronger and requires a
substrate boundary, not merely a protocol one.

Full containment means: subagent in its own container, no ambient credentials,
no egress except to the gateway. **v0 ships process isolation** — subprocess
with a scrubbed environment, no credentials anywhere in its reachable state,
gateway as the only configured route to tools.

This is honest containment against an injected model that *follows its
instructions*, and inadequate against one that deliberately probes for escape.
Container isolation is the first post-v0 milestone. Any writeup must say so
rather than overclaiming.

### 9.2 Other bounds

- **Delegation depth 1.** No sub-subagents in v0. The chain mechanism is built
  properly regardless, since it enforces the governor's ceiling.
- **Structured output is best-effort.** See §7.
- **E2 tests injection, not deliberate subversion.** A control evaluation
  red-teams a policy that is actively trying to find the gap; an injected agent
  merely follows the instructions it was given. E2 is therefore a weaker
  adversary than the control literature's (Greenblatt et al., 2024), and its
  results should not be read as evidence against a scheming planner.
- **A false `conclude` is not covered.** Containment bounds what the governor
  can *reach*, not what it can *claim*. A steered governor cannot exceed its
  authority, but concluding is within that authority — so it can report success
  it did not achieve, to an operator who trusts the summary. Two partial
  mitigations: the summary is presented as untrusted, and the ledger records
  what actually executed so the claim can be checked against it. Neither is
  complete, and bounded authority should not be read as covering this.
- **Concurrent subagents are not arbitrated.** Two subagents holding write
  capability on overlapping scope both reach the gateway with nothing ordering
  them, and the last writer wins silently. Per-resource leases would fix it and
  are post-v0; until then, concurrent same-resource work is outside what the
  system claims.
- **Observation is a bounded view.** The environment listing is depth- and
  entry-capped so it can be assembled every turn, which means a governor can be
  unaware of resources that exist within its own ceiling. Cheap to reason about,
  but it is a partial view and not a complete one.
- **Escalation is a CLI prompt.** No queue UI, no notification path.
- **No formal verification.** The TLA+ work the prior art does is not
  replicated here.

## 10. Scope and milestones

Cut breadth, never soundness. Every layer is present in v0 and each one is
narrow; nothing built now should need discarding.

**In:** Ed25519 identity, capability tokens, PoP, execution tokens · admission
engine with the full rule set including stateful cooldown and rate limiting ·
hash-chained ledger · supervisor owning the loop, role catalog, budgets · MCP
gateway with server-side credential injection · process-isolated subagent
runner · governor via OpenRouter · escalation to CLI · counterfactual probe.

**Out for now:** container sandboxing · delegation depth > 1 · escalation UI ·
TLA+ · conformance vectors · scored risk layer · any multi-organisation
mechanism.

| Milestone | Contents |
|---|---|
| **M0 — trusted core** | Keypairs, sign/verify, JCS canonicalisation, tokens, ledger. No LLM; fully unit-testable in isolation. The piece that must be right. |
| **M1 — admission engine** | SQLite state backend, signed tool bindings and the resolver set (§5.5–5.6), rule set, PatternKey counters, cooldown, ET issue/consume with single-use enforcement, escalation queue, counterfactual probe. Driven by a scripted fake agent; still no LLM. |
| **M2 — control plane** | Supervisor loop with asynchronous dispatch and hard halt guards, observation assembly (§4.6), role catalog with behaviour trees (§4.8), budgets, behaviour-tree subagent runner, MCP gateway with server-side credential injection. |
| **M3 — governor** | Model in the loop, structured output contract, state digest injection, status normalisation. |
| **M4 — evaluation** | Demo scenario, eval runs, ledger dumps, diagrams, writeup. |

M0 and M1 are deliberately LLM-free: the trusted core gets tested without two
hard things failing at once. It also makes E1 possible — a stateless-versus-
stateful comparison needs a reproducible request stream.

**Language:** Python 3.13. The MCP SDK is native, Ed25519 comes from
`cryptography`, and the performance story is irrelevant at this scale.

## 11. The demo

> The governor decomposes a task → selects a role and spawns a subagent with a
> narrowly scoped capability token → the subagent's tool output contains a
> prompt injection → the subagent attempts the injected out-of-scope action →
> the containment server denies it, the subagent holds no credentials with
> which to route around the denial, the ledger records the attempt → the
> governor observes the denial and re-plans, or the action escalates and a
> human approves at the terminal.

Every component earns its place in that single run. Anything that does not
serve it is post-v0 work.

## 12. Empirical plan

The ledger *is* the dataset. Everything below is a query over it plus a small
harness.

| | Experiment | Measures |
|---|---|---|
| **E1** | Stateless vs stateful | Replay N individually-valid requests through a stateless capability check and through the full admission engine; report approvals under each. Driven by a scripted request stream rather than a live agent, because comparing two engines requires the same input reaching both. The headline number. |
| **E2** | Injection resistance | M tool outputs carrying injected instructions toward out-of-scope actions; report how many reached execution. Target zero; report the actual figure regardless. Requires roles whose tree contains a model-chooses-next-call leaf (§4.8) — against a fully scripted role there is nothing for an injection to steer, and the result would be vacuous. |
| **E3** | Ceiling enforcement | Induce the governor to request capabilities outside its ceiling; report where each was stopped, supervisor or admission engine. Also validates that the two checkpoints are independent. |
| **E4** | Boundary Activation Rate | Fraction of decisions that were not APPROVED, plus counterfactual probes confirming DENIED remains reachable. Guards against reporting a dormant system as a working one. |
| **E5** | Budget enforcement | Attempt runaway spawning; report the cap holding and the cost of the attempt. |

Incidental and free once the ledger exists: per-decision latency, chain
verification, decision counts by type.

E1 and E4 are the strongest pair — one shows the mechanism does something a
permission list cannot, the other shows it is actually firing.

These are internal measurements and are not comparable to published numbers.
The field's common harness is AgentDojo (Debenedetti et al., 2024) — 97 tasks
and 629 security cases — which CaMeL reports against (77% utility defended
versus 84% undefended). Building an AgentDojo harness is post-v0 work, but it
is the path to a number anyone else can situate, and is preferable to inventing
a bespoke metric.

Because the governor's model is a config value, E1–E4 can be swept across
models with no code change: whether containment holds with a weaker or stronger
planner is an empirical question this design can answer cheaply.

## 13. Open questions

- **Role catalog granularity.** Too coarse and the ceiling means little; too
  fine and the governor cannot plan. No principled answer yet — start with
  three roles and let friction teach the shape.
- **Governor re-planning after denial.** When the governor sees a DENIED
  status, does it retry differently, escalate, or halt? A retry loop against a
  containment boundary is itself an attack pattern; budgets bound it, but the
  intended behaviour needs deciding.
- **Whether the supervisor should ever refuse a well-formed, in-ceiling goal.**
  Currently no — it enforces structure only. Whether that is a gap or a correct
  division of labour is unresolved.
- **Container sandboxing.** First post-v0 milestone; cost not yet estimated.
- **Growth of the resolver set.** Every new resolver is new parsing in the
  security path. If the set grows past a handful, the review burden is the real
  cost of adding tools, and the "adding a tool is data" property quietly
  degrades toward "adding a tool is code".

---

## Appendix A — Cryptography

Every concept here is used somewhere above; nothing extra.

**Hash function (SHA-256).** Any input produces a fixed 32-byte fingerprint.
One-way, and flipping one input bit changes the whole output. Used four ways:
deriving identities, deriving PatternKeys, chaining the ledger, and binding a
signature to a request body.

**Public-key signatures (Ed25519).** (Josefsson & Liusvaara, 2017.) A keypair: a private key (32 bytes, never
leaves the agent) and a public key (32 bytes, published freely).
`sign(privkey, msg)` produces a 64-byte signature; `verify(pubkey, msg, sig)`
returns true or false. Nobody without the private key can produce a signature
that verifies. Ed25519 rather than RSA or ECDSA because it has no knobs — no
key size, no curve choice — and it is deterministic, so it cannot leak the key
through bad randomness the way ECDSA can.

**Bearer token vs capability token.** An OAuth access token or API key is a
*bearer* credential: whoever holds it has the authority. Steal it and you are
the agent. A capability token names a *subject* (an AgentID), and the holder
must additionally prove possession of the matching private key. Theft alone
buys nothing. This is why OAuth is not used here: it is a bearer scheme
designed around a human clicking "Allow", with the wrong lifetime, the wrong
granularity, and no per-action binding.

**Proof of possession (challenge–response).** Even a key-bound token can be
replayed by re-sending the same signed request. So the server issues a random
challenge, single-use, 30-second validity, and the agent signs the challenge
together with the request details. The resulting signature proves three things
at once: the agent holds the key, *this exact request* is what was authorised,
and it is not a replay.

**Canonicalisation (JCS).** (Rundgren et al., 2020.) `{"a":1,"b":2}` and `{"b":2,"a":1}` are
the same object but different *bytes*, and signatures are over bytes. Both
sides must agree on an exact serialisation — sorted keys, no whitespace,
defined number formatting — before hashing. Getting this wrong produces
signatures that fail across languages and libraries for no visible reason.

**Delegation chain.** A delegated token carries `parent_hash`, the hash of the
token it derives from. A verifier walks the chain to a root and checks at every
hop that the child's capability set is a subset of the parent's. Revoke a
parent and every descendant dies with it.

**Hash-chained ledger.** Entry *n* stores `SHA-256(entry_n ‖ h_{n-1})`. Alter
anything in the past and every subsequent hash breaks.

---

## References

Debenedetti, E., Shumailov, I., Fan, T., Hayes, J., Carlini, N., Fabian, D.,
Kern, C., Shi, C., Terzis, A., & Tramèr, F. (2025). *Defeating prompt
injections by design* (arXiv:2503.18813) [Preprint]. arXiv.
https://arxiv.org/abs/2503.18813

Debenedetti, E., Zhang, J., Balunović, M., Beurer-Kellner, L., Fischer, M., &
Tramèr, F. (2024). *AgentDojo: A dynamic environment to evaluate prompt
injection attacks and defenses for LLM agents* (arXiv:2406.13352) [Preprint].
arXiv. https://arxiv.org/abs/2406.13352

Dennis, J. B., & Van Horn, E. C. (1966). Programming semantics for
multiprogrammed computations. *Communications of the ACM, 9*(3), 143–155.
https://doi.org/10.1145/365230.365252

Fernandez, M. (2026). *Agent Control Protocol — ACP v1.30: Admission control
for agent actions* (arXiv:2603.18829) [Preprint]. arXiv.
https://arxiv.org/abs/2603.18829

Greenblatt, R., Shlegeris, B., Sachan, K., & Roger, F. (2024). *AI control:
Improving safety despite intentional subversion* (arXiv:2312.06942) [Preprint].
arXiv. https://arxiv.org/abs/2312.06942

Greshake, K., Abdelnabi, S., Mishra, S., Endres, C., Holz, T., & Fritz, M.
(2023). Not what you've signed up for: Compromising real-world LLM-integrated
applications with indirect prompt injection. In *Proceedings of the 16th ACM
Workshop on Artificial Intelligence and Security* (pp. 79–90). Association for
Computing Machinery. https://doi.org/10.1145/3605764.3623985

Haber, S., & Stornetta, W. S. (1991). How to time-stamp a digital document.
*Journal of Cryptology, 3*(2), 99–111. https://doi.org/10.1007/BF00196791

Hardy, N. (1988). The confused deputy: (Or why capabilities might have been
invented). *ACM SIGOPS Operating Systems Review, 22*(4), 36–38.
https://doi.org/10.1145/54289.871709

Josefsson, S., & Liusvaara, I. (2017). *Edwards-curve digital signature
algorithm (EdDSA)* (RFC 8032). Internet Engineering Task Force.
https://doi.org/10.17487/RFC8032

Miller, M. S. (2006). *Robust composition: Towards a unified approach to access
control and concurrency control* [Doctoral dissertation, Johns Hopkins
University]. JScholarship. https://jscholarship.library.jhu.edu/handle/1774.2/873

Rundgren, A., Jordan, B., & Erdtman, S. (2020). *JSON canonicalization scheme
(JCS)* (RFC 8785). Internet Engineering Task Force.
https://doi.org/10.17487/RFC8785

Saltzer, J. H., & Schroeder, M. D. (1975). The protection of information in
computer systems. *Proceedings of the IEEE, 63*(9), 1278–1308.
https://doi.org/10.1109/PROC.1975.9939

Schneider, F. B. (2000). Enforceable security policies. *ACM Transactions on
Information and System Security, 3*(1), 30–50.
https://doi.org/10.1145/353323.353382
