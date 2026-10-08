# ADR-0006 — River jobs and Postgres state machines; no Temporal in MVP

**Status:** Accepted (2026-10-08)

**Decision.** Background work uses **River** (free tier) with transactional `InsertTx` as the outbox. Long-lived processes (approvals, reconciliation, automations) are explicit Postgres state machines advanced by jobs. Tenant schedules use our own `schedules` table (`next_fire_at` in UTC, `time/tzdata`, explicit DST rules) and a `SKIP LOCKED` dispatcher that enqueues unique `(schedule_id, fire_at)` jobs; River periodic jobs are used only for global maintenance. Expiry is enforced at use time; jobs only notify and clean up.

**Consequences.** One database, transactional consistency between state and jobs, no extra cluster. River is pre-1.0 (v0.49): pinned and upgraded deliberately. River Pro workflow features are not used.

**Alternatives.** Temporal (excellent durability, but a second cluster, and code-as-workflow does not fit declarative customer automations); DBOS (younger).
