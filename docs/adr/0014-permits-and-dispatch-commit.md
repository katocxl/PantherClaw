# ADR-0014 — Dispatch permits with a server-side commit point

**Status:** Accepted (2026-10-08)

**Decision.** An ALLOW returns a single-use Ed25519-signed permit (≈ 5 s TTL) carrying the org's containment epoch. Before sending any byte, the gateway calls `BeginDispatch`, which atomically moves the permit `ISSUED → DISPATCHING` only if it is unexpired (database clock) and the epoch is current. A stale `DISPATCHING` permit becomes `UNKNOWN` and enters reconciliation; only expired `ISSUED` permits release reservations. Gateways fail closed when their revocation-stream heartbeat is older than 2 s.

**Consequences.** Revocation and the kill switch take effect for every not-yet-dispatched action; crashes cannot cause double spending or silently lose evidence; one extra small RPC per dispatch.
