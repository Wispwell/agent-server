"""Subagent-side gateway client. M2. UNTRUSTED side.

Holds the subagent's private key and its capability token, and constructs a
proof of possession for every call. Holding the token is not sufficient to act:
the signature over challenge, method, path and body hash is what demonstrates
the caller holds the key, that this is the request that was authorised, and
that it is not a replay.

The private key is generated inside the subagent and never leaves it — the
supervisor learns only the public half. A key that crosses a process boundary
appears in argv, a file, or a log, and the identity guarantee everything else
rests on is only as good as that never happening.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from ..containment.admission import ProofOfPossession, Request, ToolCall
from ..crypto.signing import b64u_encode, pop_message, sign

__all__ = ["ToolClient"]

_PATH = "/acp/v1/authorize"


class ToolClient:
    def __init__(self, private_key, token: Mapping[str, Any], gateway, *, issue_challenge):
        self._key = private_key
        self.token = dict(token)
        self._gateway = gateway
        self._issue_challenge = issue_challenge

    def call(self, server: str, tool: str, args: Mapping[str, Any]) -> tuple[bool, Any]:
        call = ToolCall(server, tool, dict(args))
        body = json.dumps(call.action(), sort_keys=True).encode()
        challenge = self._issue_challenge()
        signature = b64u_encode(sign(self._key, pop_message(challenge, "POST", _PATH, body)))
        request = Request(
            call=call,
            token=self.token,
            pop=ProofOfPossession(challenge, "POST", _PATH, body, signature),
        )
        return self._gateway.call(request)
