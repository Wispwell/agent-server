"""Append-only hash-chained audit ledger. Milestone M0. Trusted.

    h_n = SHA-256(entry_n || h_{n-1})

Tamper-evident, not tamper-proof: it does not prevent editing the file, it
makes the edit undeniable. The ledger is also the entire empirical dataset for
the evals, which is why it exists in M0 rather than being retrofitted.
"""
