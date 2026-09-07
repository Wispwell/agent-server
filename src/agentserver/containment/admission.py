"""Admission engine. M1.

Explicit rules that plainly pass or fail. No risk score: the ACP paper's
RS = B(c) + F_res + F_ctx + F_hist + F_anom with thresholds at 40/70 is
invented constants dressed as specification, and is deliberately not used here.

    DENY      invalid signature, invalid proof-of-possession, expired token
    DENY      capability not in token, or resource outside token scope
    DENY      delegation chain invalid, or depth exceeded
    DENY      agent state in {suspended, revoked}, or cooldown active
    ESCALATE  capability flagged requires_review in the role catalog
    ESCALATE  rate on PatternKey over configured limit
    COOLDOWN  N denials within window W -> agent locked for duration D
    ALLOW     otherwise -> issue Execution Token

The bottom two rules are the stateful part — what a permission list cannot
express. A permission list can say "this agent may write files"; it cannot say
"this agent may not write its 40th file in ninety seconds".

TODO(M1): evaluate(request, state) -> Decision
"""
