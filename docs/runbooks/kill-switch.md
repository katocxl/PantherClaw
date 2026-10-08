# Runbook — Org kill switch (emergency stop)

**Status:** stub (implemented and exercised in M6).

**Engage (fast):** one eligible Responder + WebAuthn step-up + reason → `pclaw admin kill-switch engage --org <org> --reason "<text>"` or API. Effects: containment epoch incremented; every not-yet-dispatched permit becomes unusable; gateways receive the event (< 1 s p99) and refuse consequential dispatch; automations paused; target credentials revoked/rotated where supported; operations shows per-path confirmation (requested / confirmed / unsupported / failed / unknown).

**Honest limits:** requests already dispatched complete; routes not mediated by PantherClaw are unaffected (shown as residual exposure).

**Restore (deliberate):** two distinct eligible humans, each with step-up; restoration checklist (identity re-verification, connection health, residual grants and waiting approvals reviewed, narrow cohort first, post-restoration allow/deny verification). No automatic replay of blocked or expired actions.
