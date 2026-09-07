"""Credential injection. M2.

Real API keys and secrets live here and on this side of the trust boundary
only. Subagents hold Execution Tokens; the gateway does the substitution.

TODO(M2): resolve capability -> credential, attach to outbound call
"""
