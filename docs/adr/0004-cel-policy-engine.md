# ADR-0004 — CEL rules with fixed Go composition; OPA restrict-only adapter

**Status:** Accepted (2026-10-08)

**Context.** The product needs readable, validated structured rules; precise composition semantics (prohibitions win, tightest limit wins, requirements combine, conflicts deny, missing evidence → CANNOT_AUTHORIZE); simulation and replay; bounded evaluation cost; and no customer-supplied code in the decision path.

**Decision.** Policies are structured rules (JSON/YAML) whose conditions are **CEL** expressions (cel-go), type-checked at publication against the action-definition schema, with custom `decimal`/`money` types and per-tenant cost budgets. The composition algorithm (the 10-step pipeline) is fixed Go code implementing the product invariants. CEL evaluation is fail-closed (error in FORBID → DENY; in REQUIRE/CONSTRAIN → CANNOT_AUTHORIZE). Grant constraints form a lattice (allowlists, ranges, prefixes, windows) so delegation subset checks are decidable. An optional external OPA adapter may only add restrictions.

**Consequences.** Microsecond evaluation; pure-function replay and simulation; one expression language for mappings, policies, triggers and detections. No formal policy analysis (unlike Cedar's SMT tooling): conflict detection is test- and sample-based and labeled as such.

**Alternatives.** OPA/Rego as the primary engine (flexible, harder to type-check; customer-written Rego is risky); Cedar (strong analysis, but obligations are not native and Go validation maturity was uncertain).
