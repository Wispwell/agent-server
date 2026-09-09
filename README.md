# agent-server

A multi-agent system where the planner holds no operational capability and the
executors hold narrowly scoped, cryptographically bound authority that a
containment layer can revoke, rate-limit or deny mid-run.

The distinguishing claim is not "agents with permissions". It is that **no
component holding a language model is trusted, including the planner**, and the
system's safety properties are meant to hold anyway.

## The claim

An LLM that originates goals cannot be made trustworthy. So the property
claimed is not trust but **bounded authority**:

> The governor's effects on the world are confined to what the supervisor's
> rules admit, regardless of what the model decides to want.

That is checkable. "The governor is safe" is not.

## Trust boundary

| Trusted | Untrusted |
|---|---|
| containment server (admission, ledger, vault) | governor (frontier model) |
| supervisor (role catalog, budgets, lifecycle) | subagents |
| the human at the escalation queue | |

## Core invariant

```
Execute(action) => ValidIdentity(agent)
                 & ValidCapability(action in token.cap & resource in token.res)
                 & ValidDelegation(chain verified, depth <= max)
                 & Admissible(state, action)
```

Any predicate failing denies the action. Any *component* failing denies the
action — fail closed, always. There is no default-allow path.

## Two checkpoints

| | Supervisor (control plane) | Admission engine (data plane) |
|---|---|---|
| Question | May this goal become a subagent with these capabilities? | May this tool call execute right now? |
| State | Role catalog, budgets, agent graph | Tokens, rate counters, cooldowns, denial history |
| Fires at | Governor turn boundary | Every tool invocation |
| Stops | Runaway spawning, privilege creep | Injected / out-of-scope actions, floods |

Kept rigorously separate: conflating them destroys the ability to explain a
denial.

## Prior art

Most of the machinery here is inherited: object-capability security (Dennis &
Van Horn, 1966; Miller, 2006), least privilege and fail-safe defaults (Saltzer
& Schroeder, 1975), enforcement of trace properties by a reference monitor
(Schneider, 2000), tamper-evident hash chains (Haber & Stornetta, 1991), and
the indirect-prompt-injection threat class the whole design answers to
(Greshake et al., 2023). The capability/execution-token split, context-scoped
anomaly keying, and the deviation-collapse failure mode come from the Agent
Control Protocol draft (Fernandez, 2026), whose risk-scoring model is
deliberately not used.

The nearest adjacent work is CaMeL (Debenedetti et al., 2025), which keeps its
planner clean of untrusted data, and the AI control literature (Greenblatt et
al., 2024), whose trusted component is a weaker model rather than deterministic
code. §8.5 of `docs/design.md` positions this project against both.

**No research contribution is claimed** — this is an engineering synthesis.
§8 separates what is inherited from what is merely chosen, with full
references.

## Layout

```
src/agentserver/
  crypto/       M0  Ed25519 identity, JCS canonicalisation, capability + execution tokens
  ledger/       M0  append-only hash-chained audit log
  containment/  M1  admission engine, risk state, registry, escalation, secret vault
  tools/        M1  signed bindings, resource resolvers
  supervisor/   M2  the loop, observation, role catalog + behaviour trees, budgets,
                    contract, and governor.py — the planner, assembled from the
                    shared components below (UNTRUSTED, no callable tools)
  gateway/      M2  MCP proxy and transport, server-side credential injection
  subagent/     M2  behaviour-tree engine and runner, proof-of-possession client
  context/      M3  layered context windows and prompt/skill loading — shared
  providers/    M3  model clients (OpenRouter via the OpenAI SDK) — shared
evals/          M4  E1-E5 plus the counterfactual probe
scripts/demo.py M4  the injection demo
agents/         *.subagent.yaml source artifacts, compiled into the database
config.yaml     configuration: trust anchor, capabilities, roots, thresholds
docs/design.md  full design
```

## Milestones

- **M0 — trusted core.** Keypairs, sign/verify, canonicalisation, tokens, ledger. No LLM; fully unit-testable in isolation. This is the piece that must be right.
- **M1 — admission engine.** Rule set, PatternKey counters, cooldown, ET issue/consume, escalation queue, counterfactual probe. Driven by a scripted fake agent; still no LLM.
- **M2 — control plane.** Supervisor loop, role catalog, budgets, subagent runner, MCP gateway.
- **M3 — governor.** Frontier model in the loop, structured output contract, state digest injection, status normalisation.
- **M4 — evaluation.** Demo scenario, eval runs, ledger dumps, diagrams, writeup.

M0 and M1 are deliberately LLM-free so the trusted core is tested without two
hard things failing at once.

## Known weakest link

v0 ships **process isolation**, not containers: scrubbed environment, no
credentials in reachable state, gateway as the only configured route to tools.
That is honest containment against an injected model that follows its
instructions, and inadequate against one that deliberately probes for escape.
Container isolation is the first post-deadline milestone. The writeup says so
rather than overclaiming.

## Development

```sh
conda activate agent-server   # Python 3.13; never base
pip install -e '.[dev]'
pytest

agent-server keygen                       # operator signing key; prints a config line
agent-server bind tools read_file  --capability cap:fs.read  --field path
agent-server bind tools write_file --capability cap:fs.write --field path
agent-server compile agents/reporter.subagent.yaml
agent-server roles                        # what is installed

export OPENROUTER_API_KEY=...             # and set provider.model in config.yaml
agent-server run "summarise the q3 report"
agent-server ledger --tail 20             # check the summary against what ran
```

`prompts/` holds the operator-authored system instructions and rulesets that
become the trusted layers of an agent's context. The loader refuses a prompt
directory that sits inside any agent-writable root — a skill file is part of an
agent's system prompt, and an agent that could write there would be authoring
its own instructions.

**Configuration and authored artifacts are different things**, and the layout
enforces the distinction. `config.yaml` holds configuration: the trust anchor,
the capability vocabulary, roots, thresholds. A subagent is a *program* — a
capability set and a behaviour tree — so it is authored as an artifact and
**compiled** into the database, signed. Writing behaviour trees into a config
file would be coding in YAML under a configuration heading, and would move
validation from compile time to every startup.

The governor runs through **OpenRouter** using the OpenAI SDK (OpenRouter is
OpenAI-compatible and ships no SDK of its own). Copy `.env.example` to `.env`
and set `OPENROUTER_API_KEY`; the model slug lives in `config.yaml`, never in
code.

Structured output is best-effort on OpenRouter — support varies by model and by
the provider actually serving the request. Non-conforming governor output is a
normal case, handled as a schema rejection in `supervisor/contract.py` and
recorded in the ledger. Model output is never repaired to make it parse:
silently fixing it up is how an injected instruction gets laundered into a
valid-looking action.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

Apache-2.0 rather than MIT for the explicit patent grant: this is an access
control mechanism, and MIT's silence on patents is the clause that makes an
adopting organisation's legal review stall.
