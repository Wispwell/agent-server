"""Sign and verify. M0.

Signature verification precedes all semantic validation — an object with an
invalid signature is rejected without its content being read.

TODO(M0): sign(privkey, msg), verify(pubkey, msg, sig)
TODO(M0): proof-of-possession over challenge || method || path || sha256(body)
"""
