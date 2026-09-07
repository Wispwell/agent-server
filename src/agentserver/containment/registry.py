"""Agent registry. M1.

Public keys, capability sets, agent state (active | restricted | suspended |
revoked), limits. Transition to revoked is one-way.

TODO(M1): register, lookup, revoke (with transitive revocation of descendants)
"""
