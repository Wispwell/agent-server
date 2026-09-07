"""Capability and Execution tokens. M0.

CapabilityToken — issued at `bound`, says what an agent may do, on what
resource, until when, and whether it may delegate. `exp` is mandatory: a token
without expiry is invalid by definition. `parent_hash` chains delegation.

ExecutionToken — issued per approved action. Single-use, short-lived, names
exactly this action on this resource at this moment. The ET, not the ledger, is
what actually gates state mutation.

TODO(M0): CapabilityToken, ExecutionToken, issue/verify, delegation subset check
"""
