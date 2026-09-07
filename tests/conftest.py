"""Shared fixtures for the containment tests."""

from __future__ import annotations

import pytest

from agentserver.containment.admission import AdmissionConfig, AdmissionEngine
from agentserver.containment.store import Store
from agentserver.crypto.keys import agent_id, generate_keypair, public_bytes
from agentserver.crypto.signing import b64u_encode
from agentserver.crypto.tokens import issue_capability_token
from agentserver.ledger.chain import Ledger
from agentserver.policy import Policy
from agentserver.tools.bindings import sign_binding, verify_binding

from .helpers import NOW


@pytest.fixture
def env(tmp_path):
    """A complete containment server with one bound tool and one agent."""
    (tmp_path / "workspace" / "reports").mkdir(parents=True)
    (tmp_path / "workspace" / "reports" / "q3.md").write_text("data")
    (tmp_path / "secret.txt").write_text("secret")

    operator, issuer, agent = generate_keypair(), generate_keypair(), generate_keypair()
    policy = Policy.from_dict({
        "operators": {agent_id(operator): b64u_encode(public_bytes(operator))},
        "capabilities": {
            "cap:fs.read": {"resolver": "path_under_root"},
            "cap:net.fetch": {"resolver": "url_host"},
        },
        "roots": {"workspace": str(tmp_path / "workspace")},
    })

    def bind(**kw):
        fields = {
            "server": "fs", "tool": "read_file", "capability": "cap:fs.read",
            "resolver": "path_under_root",
            "resolver_config": {"field": "path", "root": "workspace"},
            "schema_sha256": "ab" * 32, "requires_review": False,
        }
        fields.update(kw)
        return verify_binding(policy, sign_binding(operator, **fields))

    bindings = {b.key: b for b in [
        bind(),
        bind(server="web", tool="fetch", capability="cap:net.fetch",
             resolver="url_host", resolver_config={"field": "url"}),
    ]}

    store = Store(tmp_path / "state.db")
    ledger = Ledger(tmp_path / "ledger.jsonl")
    engine = AdmissionEngine(
        store, policy, ledger, issuer, bindings,
        config=AdmissionConfig(rate_limit_count=3, rate_limit_window=60, cooldown_denials=3),
    )
    engine.register_agent(agent_id(agent), b64u_encode(public_bytes(agent)), now=NOW)

    token = issue_capability_token(
        issuer, subject=agent_id(agent), capabilities=["cap:fs.read"],
        resource="workspace/reports/**", expires_at=NOW + 3600,
    )
    yield {
        "engine": engine, "store": store, "ledger": ledger, "policy": policy,
        "issuer": issuer, "agent": agent, "operator": operator, "token": token,
        "tmp": tmp_path, "bind": bind,
    }
    store.close()
