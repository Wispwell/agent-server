"""Request construction helpers shared by the containment tests."""

from __future__ import annotations

import json

from agentserver.containment.admission import ProofOfPossession, Request, ToolCall
from agentserver.crypto.keys import agent_id
from agentserver.crypto.signing import b64u_encode, pop_message, sign

NOW = 1_757_200_000

def request(env, path="reports/q3.md", *, key=None, now=NOW, server="fs", tool="read_file",
            token=None, args=None):
    engine, agent = env["engine"], key or env["agent"]
    call = ToolCall(server, tool, args if args is not None else {"path": path})
    challenge = engine.issue_challenge(now=now)
    body = json.dumps(call.action(), sort_keys=True).encode()
    sig = b64u_encode(sign(agent, pop_message(challenge, "POST", "/authorize", body)))
    return Request(
        call=call, token=token or env["token"],
        pop=ProofOfPossession(challenge, "POST", "/authorize", body, sig),
    )


def denial_count(env):
    return env["store"].one(
        "SELECT denial_count, cooldown_until FROM agents WHERE agent_id=?",
        (agent_id(env["agent"]),),
    )
