"""Model clients. M3.

One client implementation serving every agent in the system — the governor and
the model leaf of any subagent's behaviour tree — so provider quirks are
handled once.

Nothing in this package is trusted. Everything a provider returns is hostile
input, whichever agent asked for it, and is validated by the caller's schema
before it means anything.
"""
