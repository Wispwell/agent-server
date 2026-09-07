"""Subagent-side request signing. M2.

Every tool call carries proof of possession: sign challenge || method || path
|| sha256(body). Holding the token is not sufficient to act.

TODO(M2): challenge fetch, PoP signing, call gateway
"""
