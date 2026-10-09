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

## Federated identity, runs and discovery (ADR-0018, G0 M3)

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-140 | Trusted-issuer entries pin the issuer, the key source, the audience `pantherclaw:<org>`, the allowed algorithms and at least one immutable claim binding a token to one agent (never a name alone); an entry without one is rejected. Only preset kinds can be configured, and rules built into a preset run in code that configuration cannot disable. | T-044 | M3 |
| HR-141 | Adding or widening an issuer entry (including turning on auto-admission) is a protected change: a new revision that takes effect only when a human holding `identity.issuer.activate` activates it, shown with what it widens and audited. Narrowing or disabling takes effect at once. | T-044 | M3 |
| HR-142 | Issuer keys are fetched, and Kubernetes TokenReview is called, only over TLS through the egress-guarded client; key documents are size-capped and cached at most 15 minutes, and an unknown `kid` triggers at most one refetch per minute per issuer. Private destinations are allowed only by operator configuration, never by tenant input. | T-045 | M3 |
| HR-143 | Attestation tokens are single use (keyed on `jti`, or on the token's SHA-256 when it has none), must carry exactly `aud = pantherclaw:<org>`, must expire at most 1 hour after issue, and confer L2 only until they expire; a workload token never outlives the attestation behind its level. | T-046 | M3 |
| HR-144 | Kubernetes attestation: TokenReview with audience `pantherclaw:<org>` must authenticate the token as the pinned namespace, service-account name and service-account UID and return the bound pod's name and UID, and that pod must still exist; the image digest comes only from trusted cluster state for that pod UID (or signed evidence bound to it), never from the workload. | T-047 | M3 |
| HR-145 | A subject token at `StartRun` is accepted only from an OIDC provider configured for subject tokens, as a signed JWT with an allowed algorithm (opaque tokens rejected), with `aud` naming PantherClaw, unexpired, `iat` at most 5 minutes old, never seen before (`jti` or token SHA-256), and `(iss, sub)` linked to an active user of the org. | T-048 | M3 |
| HR-146 | A run's represented principal is the launcher itself, a user proven by a subject token (HR-145), or for a child run its parent's principal; a principal named by the launcher is refused. A subject token never creates, widens or substitutes for a grant. | T-048, T-001 | M3 |
| HR-147 | Authority never moves between instances: runs (and, from M4, grants) bind to instance and agent ids, never names; a new enrollment, attestation, ownership transfer or reused name starts with no runs; a re-attestation whose binding claims differ from the instance's is refused. | T-004, T-049 | M3 |
| HR-148 | Unknown workloads hold no authority: requests from keys that are not admitted instances are refused (`CANNOT_AUTHORIZE`) and become discoveries deduplicated by key thumbprint, rate-limited per gateway and capped per org; observed attributes are stored and shown as untrusted. | T-050 | M3 |

## Browser sessions, WebAuthn and notifications (G0 M5 part 1)

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-150 | A browser session is issued only by a verified sign-in, as a 256-bit secret in the `__Host-pc_session` cookie (`Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`) stored only as its SHA-256. Each request checks org, user and session state, 30 minutes idle and 12 hours absolute by the database clock. The secret rotates at sign-in, at step-up and after a role change; a rotated secret presented after a 60-second grace ends the session. A user has at most 10 sessions. | T-051, T-037 | M5 |
| HR-151 | A state-changing request authenticated by a session cookie requires `Sec-Fetch-Site: same-origin` (or, without Fetch Metadata, an `Origin` equal to the public origin), the `PC-CSRF: 1` header and a JSON content type; `GET` never changes state. Pages use `html/template`, no inline script or style, a CSP with `script-src 'self'`, `frame-ancestors 'none'` and required Trusted Types, and `Cache-Control: no-store`; no CORS headers are sent. | T-051, T-037 | M5 |
| HR-152 | Browser sign-in uses a single-use `state`, PKCE S256, `nonce`, the RFC 9207 `iss` check and a binding cookie that must come back from the same browser; when `max_age` is requested, `auth_time` must be present and recent. The return path is chosen from a fixed list and stored server-side, never read from the callback. Only active members of the org get a session. | T-051, T-037 | M5 |
| HR-153 | WebAuthn ceremonies accept only the configured RP ID and exactly the public origin, require user verification (UV flag checked), allow ES256, EdDSA and RS256 with keys of at least 2,048 bits, and use a challenge that is bound to one browser session and user, valid 5 minutes and consumed by a conditional update. A credential id exists at most once per org. | T-052 | M5 |
| HR-154 | A signature counter that does not increase (other than 0 stored and 0 received) refuses the assertion and suspends the credential, with an audit event and a notice; a credential's backup-eligible flag cannot change after registration. | T-052 | M5 |
| HR-155 | Adding or removing a WebAuthn credential needs a provider sign-in at most 5 minutes old or a step-up with another active credential at most 5 minutes old; every change is audited and emailed to the user. Administrators can remove another user's credential but never register one. | T-052 | M5 |
| HR-156 | Step-up is recorded on one browser session and expires after 5 minutes; it never carries over to another session, a CLI token, an API key or a service account. Only users can hold browser sessions or WebAuthn credentials. | T-052, T-002 | M5 |
| HR-157 | Notification destinations: webhook URLs are `https` without credentials, never PantherClaw's own host, and are called only through the egress client (connected address checked, no redirects, no proxy variables); private ranges only by operator configuration. Slack URLs must be on `hooks.slack.com`. Email goes only to org users' provider addresses. Webhook secrets and Slack URLs are encrypted per row (HR-062), shown once, and never returned or logged. | T-053, T-021 | M5 |
| HR-158 | Notification content is rendered only from a fixed per-type template over ids, canonical names and counts: no agent text, no free text, no secrets. Channel messages contain no approve or deny action, only a deep link to the authenticated page, and dynamic text is escaped for each channel (Slack link syntax, mail headers). | T-054, T-026 | M5 |
| HR-159 | Deliveries are River jobs carrying ids only, retried at most 8 times (about 27 hours), stopped at notification expiry, capped at 1,000 pending per channel, and signed per Standard Webhooks for webhook channels. A delivery's outcome changes only delivery and channel health; no other module reads delivery state, and a channel never receives an approval. | T-054, T-006 | M5 |

## Grants and facts (G0 M4 part 2)

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-160 | Facts are accepted only from the provider registered for that fact name, authenticated as that provider; values a workload sends are never facts. A fact's observation time may be neither later than the database clock nor earlier than the provider's maximum lag allows, and an older observation never replaces a newer one. A required fact that is missing or older than its maximum age ⇒ `CANNOT_AUTHORIZE`. | T-055 | M4 |
| HR-161 | Workload credentials never issue, widen or change grants or guardrails. Guardrail changes need a person holding `guardrails.manage`. Root grants are issued only by a person holding `grant.issue` for the agent's team, unless G0 M4 decision 7 extends issuance to audited service accounts. A workload can only delegate a subset of its own run's grant to a child run, and only when that grant allows delegation and depth remains. | T-001, T-008 | M4 |

## Approvals, waitlist and wait handles (G0 M5 part 2)

| ID | Rule | Threats | MS |
|---|---|---|---|
| HR-170 | An approver or step-up subject is eligible only while they are an enabled user holding `approval.respond` through the requirement's role (G0 M5 part 2 decision 2) on the agent's scope path. Eligibility is checked when they respond and again inside the finalization that consumes the approval. Removing their role, disabling them, or removing or suspending their credential voids their unconsumed responses. The run's launcher and represented principal, and those of every ancestor run, never count toward an approval; an `independent` requirement also excludes the agent's owners and the grant's issuer (decision 3). A step-up is satisfied only by the person the requirement names. One response counts toward one requirement. | T-002, T-027, T-061 | M5 |
| HR-171 | An approval request is created only by the finalization that records a hold, and its binding is fixed then. A request whose binding no longer matches the current evaluation is superseded, never updated. An approved request is consumed by a conditional update inside the finalization that issues the permit: at most once, before its deadline and its consume-by time, by the database clock. A decline, an expiry or a narrower proposal ends the transaction as `DENY`. No hold is recorded while containment refuses the action. | T-005, T-006 | M5 |
| HR-172 | Declining, requesting evidence and proposing a narrower action grant nothing and need a human session. A narrower proposal keeps the operation, target, account and destinations, and moves only material parameters toward narrower values; the agent must submit it as a new action, with its own decision and approval. Evidence and notes from workloads or requesters are untrusted and size-capped. They are shown only in the untrusted block, never sent in notifications, and never change a binding; only facts from registered providers do. | T-063, T-026 | M5 |
| HR-173 | Approval requests and waitlist entries are routed only to currently eligible deciders, recomputed at every notification. Reminders and escalation steps notify more eligible deciders at wider scopes but never make anyone eligible, and all of them happen before the deadline. Having no eligible decider, or failing deliveries, is recorded as routing health and reported to the org's admins; the hold still resolves to `DENY` at its deadline. | T-061, T-006, T-054 | M5 |
| HR-174 | A wait handle names a transaction and is served only to a workload authenticated by PAP/1 as that transaction's run and instance. Waiting is read-only: it returns states, codes and times, never approver identities, notes or rendered content. A long-poll lasts at most 30 seconds and a stream at most 5 minutes, and concurrent waits are capped per instance and per server. Waiting never extends a deadline or dispatches anything; the agent resubmits the identical action. | T-060, T-023, T-005 | M5 |
| HR-175 | A batch approval covers only `ACTION_HOLD` entries that share an operation and definition digest, whose definition is reversible, whose requirement is one approver without step-up or `independent`, and whose value is at or below the org's batch ceiling. A batch has at most 25 entries and one WebAuthn assertion, whose challenge is the hash of exactly those entries' sorted bindings. Each entry keeps its own response, audit event and consumption. | T-062, T-007 | M5 |
| HR-176 | Access requests and restorations never change authority by themselves. An access request is resolved only by dismissal, or by a grant revision made through the grant API by a person allowed to issue that grant, with its issuance checks and audit. A restoration takes effect only when an eligible person other than the requester approves it with a WebAuthn assertion bound to the restoration. No approval widens a grant, a guardrail or a policy, and nothing approves "all similar" actions. | T-001, T-002, T-063 | M5 |
| HR-177 | A waitlist entry's kind, subject, priority and deadline come only from PantherClaw's own records, never from agent input. At most one entry per subject is open. Every transition is a conditional update. Deadlines are enforced at use by the database clock, and an entry past its deadline resolves to "not done" (denied, not admitted, not restored, not activated, unchanged). The exception is a `RECONCILIATION` entry, which stays open and escalates until it is resolved. | T-007, T-061 | M5 |
