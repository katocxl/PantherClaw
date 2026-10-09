# PantherClaw — Mandatory Hardening Rules

**Status:** binding design constraints (G0, 2026-10-08). Source: adversarial design review + engineering review of the architecture. A rule may only be relaxed through an ADR plus a recorded exception in [GATES_AND_REVIEW.md](GATES_AND_REVIEW.md).

**Traceability convention:** every rule `HR-###` is verified by at least one test whose name contains the ID (e.g. `TestHR001_BeginDispatchRejectsStaleEpoch`). CI's traceability check fails if an `MVP` rule scheduled for a completed milestone has no test. Threat IDs (`T-###`) refer to [THREAT_MODEL.md](THREAT_MODEL.md).

## Dispatch, permits and idempotency

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-001 | Gateway MUST call `BeginDispatch(permit_id, epoch)` before sending any byte to a target; transition `ISSUED→DISPATCHING` is a single conditional UPDATE using the **database clock** and the org's current **containment epoch**. | T-010, T-031 | M1.5/M6 |
| HR-002 | Every containment change (suspend, revoke, quarantine, kill switch) increments the org containment epoch in the same transaction. | T-031 | M6 |
| HR-003 | Sweepers release reservations only for expired `ISSUED` permits. Stale `DISPATCHING` becomes `UNKNOWN` → reconciliation; never auto-released. | T-024 | M1.5 |
| HR-004 | All state transitions are conditional `UPDATE … WHERE state=<expected>`; a 0-row result is a lost race handled explicitly (no double release, no double consume). | T-024 | M1 |
| HR-005 | A finalized `(org, run_id, action_id)` never yields a second permit; repeated calls return the stored decision. | T-012 | M4 |
| HR-006 | Same `(org, run_id, action_id)` with a different action hash ⇒ `DENY` (`ACTION_TAMPERED`) + security alert. `DENY`/expired are terminal; `CANNOT_AUTHORIZE` is retryable. | T-005, T-012 | M4 |
| HR-007 | Irreversible operations declare a semantic dedupe key; an open `UNKNOWN` or recent success on the key parks new requests in `RECONCILIATION`. | T-012 | M4/M7 |
| HR-008 | Target idempotency keys derive from the server-minted transaction id, never agent-supplied ids. | T-012 | M6 |
| HR-009 | Permits are single-use, TTL ≈ 5 s, carry the containment epoch, and are verified by the gateway before `BeginDispatch`. | T-010 | M1.5 |
| HR-010 | Gateway refuses to dispatch when its revocation/containment stream heartbeat is older than 2 s; on start it loads a full containment snapshot before serving. | T-031 | M6 |
| HR-011 | Consumed approvals are restored only when the gateway proves nothing was sent; otherwise the action is `UNKNOWN`. | T-005 | M6 |

## Never trust the gateway or the agent

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-020 | The Authority derives org from the gateway's mTLS certificate binding and rejects ActionIR whose org differs. | T-009 | M6 |
| HR-021 | The gateway forwards the workload token, proof and raw-body hash; the Authority re-verifies them itself. | T-009 | M6 |
| HR-022 | `run_id` is minted by the Authority and bound to instance, launcher, principal and grant; mismatches ⇒ `DENY`. | T-001 | M3 |
| HR-023 | Agent-supplied task text, reasons and summaries never change scope; they are stored and displayed as **untrusted**. | T-001, T-017 | M4 |
| HR-024 | Cooperative modes (SDK authorize, hooks) are labeled `PARTIAL`/`OBSERVE_ONLY` unless the target verifies PAP action tokens (shared replay store + body-hash check). | T-014 | M8/M9 |

## Approvals and human decisions

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-030 | Approval binding = hash of action hash, decision-basis digest, material-facts digest, grant revision, definition digest, run, agent instance, workload jkt, approver requirements, expiry, rendered-display hash (PAP/1 §8). | T-005, T-006 | M5 |
| HR-031 | Finalization re-runs the full pipeline and requires the same requirement class to be satisfied. | T-006 | M5 |
| HR-032 | Approvals are accepted only from authenticated human sessions; API keys and service accounts can never approve. | T-002 | M5 |
| HR-033 | High-consequence approvals require WebAuthn (UV) with `challenge = binding`; Slack/email only deep-link to the authenticated approval page. | T-006, T-026 | M5 |
| HR-034 | Approval text is rendered only from the tool package's per-operation template using canonical fields and system-of-record facts; agent text shown in a quarantined UNTRUSTED block; bidi controls stripped; mixed-script identifiers flagged. | T-026 | M5 |
| HR-035 | Two-person rules require two distinct users **and** distinct WebAuthn credentials, account-age and role-change cooldowns, and notification to org admins. | T-027 | M5 |
| HR-036 | Initiator/launcher/represented principal cannot satisfy an independent-approval requirement for their own action. | T-002 | M5 |
| HR-037 | Pending HOLDs per grant are capped; approvers see the variant history of the action; variant-shopping is a detection. | T-007 | M5/M10 |
| HR-038 | For high-consequence actions the permit carries the approver's WebAuthn assertion; customer-hosted gateways verify it against customer-pinned approver keys. | T-030 | M6 |
| HR-039 | Approval delivery failure never counts as approval; expiry is enforced at use time. | T-006 | M5 |

## Policy engine (CEL) and delegation

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-040 | Any CEL evaluation error in a FORBID rule ⇒ `DENY`; in REQUIRE/CONSTRAIN rules ⇒ `CANNOT_AUTHORIZE`. Never "no match". | T-018 | M4 |
| HR-041 | Material amounts use custom `decimal`/`money` CEL types; ordering operators on string-typed material fields are rejected at type-check. | T-018 | M4 |
| HR-042 | Optional fields require `has()` guards (enforced by the policy linter). | T-018 | M4 |
| HR-043 | Per-tenant CEL cost budget; exceeding it ⇒ `CANNOT_AUTHORIZE`. Comprehension sizes bounded. | T-023 | M4 |
| HR-044 | Policy rules are mutation-tested before publication (flipping each comparison must fail at least one test). | T-018 | M11 |
| HR-045 | Grant constraints are a lattice (allowlists, numeric ranges, prefixes, time windows) so child ⊆ parent is decidable at issuance. | T-008 | M4 |
| HR-046 | Every ancestor grant is evaluated at decision time; effective authority is the intersection even if issuance checks were wrong. | T-008 | M4 |
| HR-047 | Delegation depth and fan-out are capped; children cannot outlive parents; revocation cascades within one transaction. | T-008 | M4 |
| HR-048 | Shared budgets debit the child and all ancestors, locking rows in a fixed ancestor-first id order. | T-011 | M4 |
| HR-049 | Count-based limits use counter rows updated in the finalization transaction (no check-then-act in CEL). | T-011 | M4 |

## Tenancy and database

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-050 | Composite `(org_id, id)` primary and foreign keys; every unique constraint includes `org_id`. | T-003 | M1 |
| HR-051 | Tenant context set only by `set_config('app.org_id', $1, true)` at transaction start; plain `SET`/string-built SQL is lint-banned. | T-003 | M1 |
| HR-052 | Pool `AfterRelease` runs `RESET ALL`; RLS policies use `NULLIF(current_setting('app.org_id', true), '')::uuid` inside `(SELECT …)` so a missing setting matches nothing. | T-003 | M1 |
| HR-053 | RLS ENABLEd and FORCEd on every tenant table; views use `security_invoker = true`; no SECURITY DEFINER except one audited cross-org lister. | T-003 | M1 |
| HR-054 | Cross-org sweepers list `(org_id, id)` via the audited lister, then process each org in its own transaction with tenant context set. | T-003 | M1 |
| HR-055 | `pc_app` has no TRUNCATE, COPY, DDL or BYPASSRLS; UPDATE/DELETE revoked on evidence tables. Tests run as `pc_app`. | T-003, T-029 | M1 |
| HR-056 | Job args, LISTEN/NOTIFY payloads and logs carry IDs only — never secrets or payloads. | T-015 | M1 |
| HR-057 | Every app connection sets `statement_timeout`, `lock_timeout`, `idle_in_transaction_session_timeout`. | T-023 | M1 |

## Credentials and keys

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-060 | Target credentials are HPKE-sealed (X-Wing) to a broker key per tenant or per gateway deployment (KMS-wrapped); `info`/AAD binds `(org_id, connection_id, cred_version, allowed_hosts)`. | T-015, T-016 | M6 |
| HR-061 | Credentials are opened only in gateway memory at dispatch; never returned by any API, logged, or placed in job args. | T-015 | M6 |
| HR-062 | Envelope encryption AAD binds org, table, column and row id (ciphertext cannot be moved between rows). | T-016 | M1 |
| HR-063 | Licence-signing and package-signing root keys are generated and kept offline; CI never holds them. | T-034, T-036 | M1 |

## Gateway egress (confused deputy / SSRF)

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-070 | Never follow redirects (`CheckRedirect` returns `http.ErrUseLastResponse`). | T-021 | M1.5 |
| HR-071 | Check the **connected** IP in `net.Dialer.Control`: deny loopback, link-local, RFC1918, CGNAT (100.64/10), ULA, IPv4-mapped IPv6, 0.0.0.0/::, cloud metadata; decimal/octal/hex encodings covered by tests. | T-021 | M1.5 |
| HR-072 | Ignore `HTTP(S)_PROXY`/`NO_PROXY` env vars on egress transports. | T-021 | M1.5 |
| HR-073 | Host and SNI come only from the registered connection; path templates are percent-encoded; reject `..`, `%2f`, `@`, `#`, `?`, CR/LF in substitutions; re-parse the final URL and assert it matches the reviewed route. | T-021 | M6 |
| HR-074 | Egress uses a separate `http.Transport` with no client certificate (the gateway's mTLS identity never leaves on egress). | T-022 | M1.5 |
| HR-075 | Outbound requests are re-serialized from ActionIR + definition template; raw agent bytes are never forwarded. | T-020 | M1.5 |
| HR-076 | Responses are size- and decompression-ratio-capped and scanned for echoed injected secrets (redacted). | T-015 | M6 |
| HR-077 | Egress deny list enforced at connection registration and at dial; connections to PantherClaw's own hosts are forbidden; private targets only via customer-hosted gateways. | T-002, T-021 | M6 |
| HR-078 | Per-connection circuit breaker on `UNKNOWN` rate → connection quarantine + alert. | T-013 | M6 |
| HR-079 | Destinations are classified (public/internal) in ActionIR; disclosure-capable params carry size/entropy obligations. | T-017 | M6/M10 |

## MCP and connector runtime

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-080 | `Mcp-Method`/`Mcp-Name` headers must match the JSON-RPC body; JSON-RPC batches are rejected. | T-019 | M6 |
| HR-081 | Agents receive tool descriptions from the reviewed tool package, never live upstream text; drift between live and reviewed definitions quarantines the package. | T-025 | M6 |
| HR-082 | Server→client `elicitation`/`sampling` are blocked by default and policy-gated when enabled. | T-028 | M6 |
| HR-083 | Stateful MCP sessions (2025-11-25) are bound to the workload jkt and re-verified per POST; JSON-RPC ids are remapped per session. MCP list caches are forced private. | T-009 | M6 |
| HR-084 | Third-party MCP servers run only in customer-hosted gateways (never multi-tenant SaaS gateways in MVP). | T-015 | M6 |
| HR-085 | Each connector runs with its own uid and mount namespace, `hidepid=2`, seccomp/landlock (gVisor when available); its only network path is the gateway egress PEP, which injects credentials. | T-015 | M6/M9 |
| HR-086 | Routes through opaque MCP servers are capped at `PARTIAL` unless their egress is mediated. | T-014 | M9 |

## Identity protocol

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-090 | Verify token, `cnf`, and proof signature **before** inserting `jti`; replay store unique `(jkt, jti)`, time-partitioned. | T-032 | M3 |
| HR-091 | Server-issued DPoP nonces (≤ 5 min) remove reliance on client clocks; raw body hashed before parsing. | T-032 | M3 |
| HR-092 | Desktop workloads (`pclaw mcp proxy`) capped at L1, stdio only (never a localhost HTTP listener); same jkt from a new network ⇒ alert. | T-033 | M3/M6 |
| HR-093 | GitHub OIDC attestation matches `repository_id`, `repository_owner_id` and the workflow (`workflow_ref` for ordinary jobs, `job_workflow_ref` for reusable workflows, on a protected branch or tag), requires `ref_protected`, checks `aud = pantherclaw:<org>`, and rejects `pull_request` runs (from forks or the same repository) and `pull_request_target`. | T-035 | M3 |
| HR-094 | Owner confirms the key fingerprint in ADMISSION unless an L2 auto-admission policy matches pinned claims. | T-004 | M3 |
| HR-095 | Algorithms are pinned per key; `none`, HMAC on asymmetric keys and unlisted algorithms are rejected (go-jose allowlists). | T-032 | M2 |

## Canonicalization and input

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-100 | Strict JSON (`encoding/json/v2`): duplicate keys, invalid UTF-8 and unknown fields rejected; depth/size limits enforced. | T-020 | M4 |
| HR-101 | No JSON numbers in material params (decimal strings only). | T-020 | M4 |
| HR-102 | Mixed-script/confusable identifiers and bidi controls are rejected, not normalized; target-meaningful bytes are never normalized. | T-020, T-026 | M4 |
| HR-103 | Ambiguous targets, missing material fields, unsupported units ⇒ `CANNOT_AUTHORIZE` (no defaults). | T-020 | M4 |
| HR-104 | protovalidate at every API edge plus domain validation; explicit request DTOs (no mass assignment). | T-037 | M1 |

## Evidence and kill switch

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-110 | Receipts are written unchained inside their business transaction; a single per-org chainer (advisory lock) links rows older than `pg_snapshot_xmin`. | T-029 | M1.5 |
| HR-111 | Signed Merkle checkpoints per window; `pclaw verify` checks consistency proofs; a global root (all orgs) is anchored to Rekor v2 with an RFC 3161 timestamp. | T-029 | M7 |
| HR-112 | Receipts reconcile against target-side logs where available to detect effects without receipts. | T-029 | M7 |
| HR-113 | Kill switch engage: one eligible responder + step-up; restore: two people + step-up; engage also pauses automations and revokes target creds where supported. | T-031 | M6 |

## Sandbox, red team and packages

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-120 | Red-team runs are server-enforced to simulator-only environments; receipts carry `simulated: true`. | T-038 | M12 |
| HR-121 | Sandbox closure probes run from a trusted sidecar plus an external canary, require positive and negative controls, and ENFORCED promotion expires. | T-039 | M9 |
| HR-122 | Sandbox networks block IPv6, ICMP and DNS egress; Docker ≥ 26 required (CVE-2024-29018). | T-039 | M9 |
| HR-123 | Tool packages are signed by the offline package root with TUF-style expiring metadata; per-org version pins only move forward (anti-rollback). | T-036 | M4 |
| HR-124 | Package mappings are reviewed as code (a wrong mapping is a total bypass) and covered by golden tests. | T-036 | M4 |

## Supply chain and CI

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-130 | No `pull_request_target`; `persist-credentials: false`; `permissions: {}` default with per-job grants; all actions pinned by full SHA (repo policy enforced). | T-040 | M0 |
| HR-131 | Release job runs harden-runner in block mode, publishes via OIDC trusted publishing only, and attests every artifact. | T-040 | M0 |
| HR-132 | Dependencies pass govulncheck/OSV/dependency-review gates and a 7-day release cooldown; Trivy is not used (March 2026 compromise). | T-040 | M0 |
