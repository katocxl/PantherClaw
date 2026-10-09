# ADR-0017 — Coding and DevOps agents first; v0.1.0 built around proven coverage

**Status:** Accepted (founder decision 2026-10-09)

**Context.** An October 2026 competitive review (14 vendors; vendor claims not independently verified) found per-tool authorization for MCP and API calls commoditising: identity, PAM, zero-trust and cloud vendors all ship policy gateways. The least contested capability is evidence that every route to an effect is mediated. In the plan, v0.1.0 followed M8, before the containment sandbox and coverage records (M9) and the adversarial range (M12). Until M9, a direct call that bypasses the gateway is only labelled `PARTIAL` (S11), so the preview would have looked like the commoditised category. The reference specification named support refunds as the first buying problem (§2).

**Decision.**
1. **First market:** coding and DevOps agents (Claude Code, the Claude Agent SDK, CI agents) with repository, MCP, HTTP and deployment access. The flagship demo is "three routes, three stops" ([PRODUCT.md](../PRODUCT.md) §6). Refunds stay as the engine's test harness (payments simulator) and become the second market.
2. **Delivery order:** M3 → M4 → M5 → M6 → M7 → M8 → M9 → M12 → **v0.1.0 preview** → M10 → M11 → M14 → M13 → **v1.0**. Milestone numbers stay as identifiers because hundreds of requirement, rule and threat rows cite them; `tools/traceability` holds the delivery order.
3. **M8 narrows to coding-agent integrations:** Go SDK and target verifier middleware, the core TypeScript and Python clients (the Agent SDK `canUseTool` callback needs them), the Claude Agent SDK integration, the GitHub App connector and organisation scan, `pclaw init`, merge review and the §43 coding-agent scenario.
4. **New M14 "Framework SDKs & business connectors"** takes the rest of the old M8: framework wrappers (PN-016.3), Stripe test mode (PN-017.2), Slack approvals (PN-017.3), the Postgres connector (PN-017.4) and data-scoping constraints (F101).
5. **M12 moves before the preview, whole.** Its scenarios attack capabilities built in M2–M9 (tokens, grants, budgets, approvals, gateway, egress), so it needs nothing from M10 or M11.

**Consequences.** The preview demonstrates enforced, evidenced coverage instead of a policy gateway. No `HR` or `T` row is due at M8, so moving its items costs no traceability; rules due at M9 and M12 (HR-024, HR-086, HR-120..122) now fall due before those of M10 and M11. Until M14, approvals use the API, the CLI and the M5 approval page (no Slack). Python and TypeScript developers get core clients in M8 but no framework wrappers until M14. The product is explained through seven components ([PRODUCT.md](../PRODUCT.md)); that grouping changes no behaviour.

**Alternatives.** Keep refunds first and the old order (the preview competes in the commoditised category); renumber milestones (breaks citations across FEATURES, HARDENING_RULES and THREAT_MODEL); split M12 into two parts (extra bookkeeping for no benefit).
