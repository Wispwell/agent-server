"""Context assembly. M3. Shared by every agent in the system.

Both the governor and each subagent need the same thing: a prompt built from
operator-authored material plus whatever the run has accumulated. Building that
once, here, rather than separately in each, is what makes the trust rule
below enforceable in one place instead of remembered in several.

The layering in `window.py` is not organisational — the boundary between its
layers is the trust boundary.
"""
