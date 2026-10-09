# ADR-0019 — Standards at the edges: AuthZEN endpoint and Shared Signals receiver

**Status:** Proposed (2026-10-09; founder decision pending). On acceptance, FEATURES.md gains PN-023 (M14) and PN-024 (M10).

**Context.** Buyers expect a new security layer to fit their existing stack. The October 2026 competitive review recommended OpenID AuthZEN for interoperable policy decisions and the OpenID Shared Signals Framework (CAEP/RISC) for revocation and risk signals. Some of its other recommendations conflict with accepted decisions and are rejected below.

**Decision (proposed).**
1. **AuthZEN evaluation endpoint (M14).** Third-party enforcement points (for example Envoy `ext_authz` or agent gateways) can ask PantherClaw for a decision through AuthZEN. Such routes skip permits and `BeginDispatch`, so they are labelled `PARTIAL` unless the target verifies PAP/1 action tokens (HR-024). An `ALLOW` for an action that consumes a budget or counter is recorded as dispatched with an unreported outcome, so its reservation is committed and never released early.
2. **Shared Signals receiver (M10).** PantherClaw accepts signed CAEP/RISC events from configured transmitters (the customer's identity provider). "User disabled", "sessions revoked" and "credential compromised" find the grants that person issued, approved or is represented in. PantherClaw suspends them only under a preauthorized playbook (F562); otherwise it opens a case (F800: no destructive automatic response by default).
3. **Not adopted from the review:**
   - an external policy engine as the primary decision maker: atomic budget reservations need the finalization transaction (ADR-0004 stands; OPA stays restrict-only);
   - generic proxies as the enforcement point: they cannot rebuild the outbound request from ActionIR (PN-003.2);
   - a portable bearer "authority envelope": it could not enforce cumulative budgets or sub-second revocation; PAP/1 action tokens are the portable artifact;
   - AI content classifiers in the decision path: later, only as fact providers under F366, never as authorization.

**Consequences.** PantherClaw can sit behind gateways customers already run and react to identity-provider events, while every decision still comes from the Authority. AuthZEN routes are honestly partial. The receiver adds an inbound endpoint and a new trust relationship (the transmitter), which the M10 brief threat-models.

**Alternatives.** No external decision API (customers must adopt our gateway everywhere); polling identity providers for user state (slow, provider-specific); automatic containment on every identity signal (violates F800).
