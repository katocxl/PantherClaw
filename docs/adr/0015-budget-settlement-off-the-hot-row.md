# ADR-0015 — Keep budget settlement off the hot row

**Status:** Proposed (2026-10-08, from the M1.5 measurements; founder decision at G1)

**Context.** The M1.5 walking skeleton reserves and settles budgets on one row per budget (ARCHITECTURE §6.3). A conditional `UPDATE` locks that row until `COMMIT`, and `COMMIT` waits for the WAL flush. Every refund therefore puts **two** flushes behind the same row lock: the reservation in `Authorize` and the commit or release in `RecordExecution`. One budget's throughput is bounded by about `1 / (2 × flush latency)` whatever the CPU count. On the development laptop, where Docker Desktop's virtual disk flushes take about 0.9 ms (`pg_test_fsync`), that is 350–500 refunds per second at best. Flush-latency spikes then made calls queue past the gateway's 2 s timeout and collapse into `503`s at loads as low as 100 rps (`docs/perf/M1.5.md`).

The safety argument for moving work off the row is that settlement never makes the budget look *less* consumed:
- A commit moves an amount from `reserved` to `spent`, so `spent + reserved` is unchanged.
- A release lowers `reserved`.

Delaying either can only make the budget look **more** consumed than it is, which fails safe (no overspend). Only the reservation must be synchronous.

**Decision (proposed).**
1. **Asynchronous settlement.**
   - `RecordExecution` writes the outcome, the budget-ledger entry and a pending settlement row, and does not touch the budget row.
   - A River job settles pending rows per budget with one aggregated `UPDATE` (as the sweeper now does) and deletes them in the same transaction.
   - Hot-row flushes drop from two per refund to one, plus one per settlement batch.
   - Read paths that show "spent" use the budget row plus pending settlements.
2. **Fail fast on the hot row.** The finalization transaction sets `SET LOCAL lock_timeout` to about 100 ms. A budget lock that cannot be taken quickly yields `CANNOT_AUTHORIZE` (fail closed) instead of queueing towards the caller's timeout. This turns overload into fast, safe refusals rather than a cascade.
3. **Escrow slots, only when measured necessary.** A budget that must exceed one row's flush-bound rate is split into N slot rows that each hold a share of the limit. A reservation takes a random slot with headroom, and a rebalance job moves headroom between slots. This adds complexity, so it waits until a real workload needs it.

**Consequences.**
- One budget's peak rate roughly doubles with (1).
- (2) bounds Authorize latency under contention and removes the timeout cascade, at the cost of refusals during spikes.
- Settlement lag (seconds) appears in budget views.
- (3) is deferred.
- Hardware matters: NVMe flushes of about 0.1 ms move the single-row bound to about 5,000 refunds per second before any of this.

**Alternatives considered.**
- `synchronous_commit = off`: rejected. A crash could lose a committed reservation after its permit was dispatched, which means overspend.
- Advisory locks or an in-memory counter in front of the row: rejected. They are not crash-safe and not shared across replicas.
- Removing `FOR SHARE` on the containment row: it is not the bottleneck (the samples show no waits on it). `BeginDispatch` re-checks the epoch anyway.
