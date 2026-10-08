# Runbook — Backup and restore

**Status:** stub (completed and drilled in M13).

- **Local/self-hosted:** nightly `pg_dump --format=custom` of the PantherClaw database, encrypted with `age` to an offline recipient key, retained 14 days; WAL archiving for PITR when running on a VM.
- **Managed Postgres (upgrade):** provider PITR (≥ 7 days) + weekly logical export.
- **What must also be backed up:** KEK material (via the key provider, never alongside DB backups), gateway broker keys (or re-enroll gateways), offline roots (offline media, two copies).
- **Restore drill (quarterly from M13):** restore into an isolated environment → run `pclaw verify` over the ledger (chain + checkpoints) → run invariant suite against restored data → record RTO/RPO achieved in GATES_AND_REVIEW (G4 entry).
- After restore: containment epochs are incremented for all orgs (invalidates any in-flight permits from before the incident); gateways must re-sync containment snapshots before serving.
