"""Ed25519 keypairs and agent identity. M0.

AgentID = base58(SHA-256(public_key))

A username is a claim; a key is a proof. Identity is demonstrated per request,
never asserted. Private keys never leave the agent that owns them.

TODO(M0): generate_keypair, derive_agent_id, load/store keypair
"""
