"""Supervisor — the control plane. Milestone M2. Trusted.

The supervisor OWNS the loop. It invokes the model, receives output, validates,
decides, acts, and injects results into the next turn. The LLM is a subroutine
of a deterministic program, not a program that consults a deterministic helper
— a compromised governor could simply decline to call the latter.
"""
