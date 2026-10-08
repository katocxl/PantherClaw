# Runbook — Key rotation

**Status:** stub (completed in M1 for envelope/signing keys, M6 for broker keys and internal CA, M7 for checkpoint keys).

| Key | Rotation | Procedure outline |
|---|---|---|
| Authority signing keys (receipts, permits, workload tokens) | 90 days, ≥ 7-day overlap | `pantherclaw-server keys rotate --purpose=<p>` → new key published in JWKS as `next` → promote to `active` → old key `verify-only` for 7 days → retire; ledger records each step |
| Envelope DEKs (per org/purpose) | yearly or on suspicion | create new DEK version; new writes use it; River job re-encrypts rows in batches; old version destroyed after verification |
| KEK (KeyProvider) | provider policy / on suspicion | rewrap all DEKs with new KEK; verify decrypt of samples; disable old KEK |
| Broker keys (gateway) | on gateway re-enrollment or suspicion | gateway generates new HPKE key → server re-seals credentials client-side via `pclaw seal` or ingest path → old blobs deleted |
| Internal CA intermediate | yearly | issue new intermediate; gateways renew certs (24 h) automatically; revoke old |
| Offline roots (licence, package) | only on compromise | follow compromise procedure: freeze promotions, publish revocation, re-sign with new root, ship root update in a signed release |

Compromise of any key: treat as incident ([incident-response.md](incident-response.md)), rotate immediately, record G4.
