"""Secret storage. M1. Trusted — secrets never cross the boundary.

A subagent authorised to read a repo never receives a token; it receives an
Execution Token, and the gateway attaches the real credential on the way out.
This is what makes the system containment rather than governance.

TODO(M1): store/fetch credentials, never expose to untrusted callers
"""
