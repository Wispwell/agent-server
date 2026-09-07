"""E4 — Boundary Activation Rate.

Fraction of decisions that were not APPROVED, over the whole run. Guards
against reporting a system that never fired as a system that works.

Deviation collapse (ACP paper section 17): enforcement correct, invariants
holding, and the boundary simply never reached because upstream stages removed
every signal that could trigger it. A competent governor plans safe tasks, so
without this we cannot distinguish "containment works" from "containment is a
no-op".

TODO(M4)
"""
