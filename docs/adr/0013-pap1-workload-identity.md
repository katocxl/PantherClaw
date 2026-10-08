# ADR-0013 — PAP/1 workload identity with DPoP-style proofs

**Status:** Accepted (2026-10-08)

**Decision.** Agents authenticate with an instance-held Ed25519 key, an Authority-issued 10-minute workload token bound to that key (`cnf.jkt`), and a per-request DPoP-style proof including a raw-body hash and a server-issued nonce. Attestation levels: L1 (enrollment + owner fingerprint confirmation), L2 (GitHub Actions OIDC matched by ids; Kubernetes projected service-account token + image digest), L3 later (SPIFFE/cloud identity). The specification is published under Apache-2.0 ([PAP-1.md](../protocol/PAP-1.md)).

**Consequences.** Stolen tokens are useless without the key; works for desktop, CI, containers and serverless without service-mesh infrastructure; SPIFFE can be added as an attestation source. Desktop keys in OS key stores are capped at L1 (same-user malware risk).

**Alternatives.** mTLS/SPIFFE everywhere (heavy for desktop and serverless agents); bearer API keys (no proof of possession).
