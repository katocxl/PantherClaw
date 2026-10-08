# ADR-0003 — PostgreSQL as the single authoritative store, RLS FORCEd

**Status:** Accepted (2026-10-08)

**Context.** Correctness (budgets, approvals, idempotency) needs transactions; multi-tenancy needs isolation; a solo founder needs one system to operate.

**Decision.** PostgreSQL 17 is the only authoritative store (state, jobs via River, evidence ledger, replay store). pgx v5 + sqlc + goose; squawk lints migrations. Tenant isolation is enforced twice: typed `OrgID` in every repository method and **RLS ENABLE + FORCE** with `set_config('app.org_id', $1, true)` per transaction, composite `(org_id, id)` keys, org-scoped unique constraints, `RESET ALL` on pool release, `security_invoker` views, and roles `pc_migrator` / `pc_app` / `pc_audit_ro`.

**Consequences.** Strong consistency and simple operations; DB loss + fail-closed = outage (backups/PITR now, HA as an upgrade). Tests must run as `pc_app` (superusers bypass RLS). River tables are excluded from RLS and never carry secrets.

**Alternatives.** Separate stores for jobs (Redis/NATS) and evidence (object storage) — deferred until measurements justify them.
