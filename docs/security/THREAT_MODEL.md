# PantherClaw — Threat Model (SG02)

**Version:** 1.0 · **Date:** 2026-10-08 · **Method:** asset/boundary analysis + STRIDE per trust boundary + product abuse cases · **Owner:** founder (security owner) · **Review:** at every milestone G0, after material change (G4), and at least quarterly.

Mitigation references: `HR-###` = [HARDENING_RULES.md](HARDENING_RULES.md), `SB-x` = section of [SECURITY_BASELINES.md](SECURITY_BASELINES.md). Each abuse case `T-###` has negative tests named `TestT###_…` or covered by the referenced `HR` tests.

## 1. Scope

In scope: `pantherclaw-server` (api + worker), `pantherclaw-gateway`, `pclaw`, `pclaw-admin`, SDKs, Claude Code integration, PostgreSQL schema, build/release pipeline, public repository. Out of scope: customer agents' internal logic, customer IdPs, target systems' own security (we model them as possibly compromised, A11).

## 2. Assets

| Asset | C | I | A | Notes |
|---|---|---|---|---|
| Grants, envelopes, delegation lineage | M | **H** | H | Integrity = authority correctness |
| Policies, tool packages / action definitions | M | **H** | H | A wrong mapping is a total bypass |
| Approvals and their bindings | M | **H** | M | Forgery = unauthorized consequential action |
| Budgets, counters, ledgers | M | **H** | H | Overspend = financial loss |
| Sealed target credentials, broker keys | **H** | H | H | Theft = bypass of every control |
| KEKs/DEKs | **H** | H | H | |
| Signing keys: receipts, permits, workload tokens, internal CA | **H** | **H** | H | |
| Offline roots: licence signing, package signing | **H** | **H** | M | Never online |
| Evidence ledger, receipts, checkpoints | M | **H** | M | Customer audit/forensics |
| Restricted payload captures | **H** | H | L | Off by default |
| Sessions, WebAuthn credentials, API keys, service-account keys | **H** | H | M | |
| Tenant configuration & membership | M | H | H | |
| Release artifacts & signing identity (GitHub OIDC) | L | **H** | M | Supply chain |
| CI secrets (subscription token for AI review) | H | M | L | |
| Source IP (enterprise code, curated content) | H | M | L | See [IP_PROTECTION.md](../IP_PROTECTION.md) |

## 3. Trust boundaries

| ID | Boundary | Untrusted side → trusted side | Primary controls |
|---|---|---|---|
| TB1 | Agent ↔ Gateway | Agent/SDK/MCP client → gateway | PAP/1 token + DPoP + nonces (HR-090..095), strict input (HR-100..104) |
| TB2 | Gateway ↔ Target | Gateway → external API/MCP | Egress guards (HR-070..079), re-serialization, sealed creds |
| TB3 | Gateway ↔ Authority | Gateway → server | mTLS with org binding, server re-verification (HR-020..021) |
| TB4 | Clients ↔ Server | Browser/CLI/API clients → server | OIDC, sessions, WebAuthn, service auth, protovalidate (SB-2) |
| TB5 | Server ↔ PostgreSQL | App → DB | Roles, RLS FORCE, set_config, timeouts (HR-050..057) |
| TB6 | Server/Gateway ↔ KMS | App → key provider | KeyProvider port, least-privilege key roles (SB-3) |
| TB7 | Tenant ↔ Tenant | Org A → Org B data | RLS, composite keys, typed OrgID, negative tests |
| TB8 | Integrations ↔ Server | IdP, Slack, SIEM, webhooks | Signature verification, deep-link approvals only (HR-033) |
| TB9 | Third-party MCP code ↔ Connector runtime | Connector process → gateway | Isolation, customer-hosted only (HR-084..086) |
| TB10 | CI/CD ↔ Repo/Registries | Workflows, deps → artifacts | Pinned actions, OIDC publishing, attestations (HR-130..132) |
| TB11 | Tool output/content ↔ Agent | External text → agent reasoning | Outside our enforcement; constrained by grants, sequences, detections |
| TB12 | Public repo ↔ Private enterprise repo | Public → private | No private code/secrets in public repo; extension interfaces |

## 4. Attack surfaces

Connect APIs (gRPC/JSON) · MCP endpoint (Streamable HTTP, two spec versions) · HTTP proxy routes · SDK endpoint (authorize/wait) · enrollment & admission · OIDC callback, device flow, browser sign-in and account pages · WebAuthn ceremonies · notification destinations (outbound webhooks, Slack, SMTP) · inbound webhooks · Slack interactions · SIEM/webhook export · search & graph queries · evidence export/packs · tool-package import · licence-key ingestion · CLI local key store · connector runtime · compose/Helm configuration · GitHub workflows · dependency installation · model-facing tool descriptions.

## 5. Adversaries

| ID | Adversary | Capabilities assumed |
|---|---|---|
| A1 | Compromised / prompt-injected agent | Arbitrary requests with its own valid identity; can read its own env/files; may run shell tools |
| A2 | Malicious content author | Plants instructions in data the agent reads (tickets, docs, web pages) |
| A3 | Malicious/compromised MCP server or tool | Controls tool descriptions, responses, timing; may change behavior (rug pull) |
| A4 | Holder of stolen workload credentials | Has tokens, maybe the private key |
| A5 | Malicious insider developer (customer) | Valid user; wants to self-grant or self-approve |
| A6 | Phished/coerced approver | Legit approver tricked by misleading request |
| A7 | Malicious customer admin / SaaS operator insider | High privileges in tenant or infrastructure, DB access |
| A8 | Cross-tenant attacker | Valid tenant account elsewhere on the same deployment |
| A9 | Network attacker | On-path or off-path; DNS manipulation |
| A10 | Supply-chain attacker | Compromises a dependency, action, or build step |
| A11 | Compromised target | Returns forged acceptance/effects, hangs, redirects |
| A12 | Code thief / licence violator | Copies public code, removes licence checks |

## 6. STRIDE by boundary (summary)

| Boundary | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| TB1 | token theft/replay → DPoP, nonces | body/params tampering → body hash, re-serialization | agent denies action → signed receipts | secrets in params → classification, redaction | oversized/deep input, long-polls → limits | self-authorization → grants, HR-001..011 |
| TB2 | target spoofing → TLS, pinned hosts | response forgery → independent verifiers | — | creds leaked via redirect → HR-070 | slow targets → circuit breaker | SSRF → HR-071..077 |
| TB3 | rogue gateway → mTLS + re-verification | permit reuse → BeginDispatch | — | — | Authority down → fail closed | gateway asserting org → HR-020 |
| TB4 | account takeover → OIDC + WebAuthn | CSRF, mass assignment → SB-2, HR-104 | admin denies change → audit ledger | IDOR → authz on every call | API abuse → rate limits | role escalation → RBAC + SoD |
| TB5 | — | evidence edits → revoked UPDATE/DELETE | — | cross-tenant read → RLS | lock storms → timeouts | BYPASSRLS → role design |
| TB7 | — | — | — | search/graph inference → permission-safe queries | noisy neighbor → quotas | FK oracle → composite keys |
| TB9 | — | — | — | /proc/environ creds → isolation, egress injection | resource exhaustion → cgroups | sandbox escape → seccomp/landlock/gVisor |
| TB10 | — | malicious dep/action → pins, cooldown, scans | — | secret exfil from CI → minimal secrets, harden-runner | — | release hijack → environment gate + OIDC |

## 7. Product abuse cases

| ID | Abuse case | Adv. | Entry | Consequence | Mitigations | MS |
|---|---|---|---|---|---|---|
| T-001 | Agent enlarges its own scope via task text or self-issued grant | A1 | TB1 | Unauthorized effects | Grants from trusted sources only; HR-022, HR-023, HR-161; no agent grant issuance | M4 |
| T-002 | Self-approval: agent uses a PantherClaw API key / connection to PantherClaw; developer approves own action | A1, A5 | TB4, TB2 | Bypass of human gate | HR-032, HR-036, HR-077; `pclaw scan` flags `pck_` keys; secret scanning pattern | M5 |
| T-003 | Tenant escape (RLS gaps, pooled connection leaks, FK/unique existence oracles, sweeper context) | A8 | TB5/TB7 | Data leak / cross-tenant actions | HR-050..057; cross-tenant suite per table | M1 |
| T-004 | Rogue instance admitted under a real agent's name | A4, A1 | Enrollment | Inherited authority | HR-094; no name-based inheritance (F034) | M3 |
| T-005 | Approval replay / theft by a sibling run producing the same hash | A1 | TB1 | Unapproved execution | HR-030 (binds run, instance, jkt), HR-005/006, HR-011 | M5 |
| T-006 | TOCTOU: material change after approval (amount, payee, facts) | A1, A11 | TB1 | Approved ≠ executed | HR-030, HR-031, HR-039 | M5 |
| T-007 | HOLD flooding / variant-shopping to fatigue approvers | A1 | TB1 | Rubber-stamped approval | HR-037; detection PN-006 | M5/M10 |
| T-008 | Delegation escape: child broader than parent, outliving parent, surviving revocation | A1 | TB1 | Authority expansion | HR-045..047 | M4 |
| T-009 | Compromised/malicious gateway asserts another org's identity | A7, A9 | TB3 | Cross-tenant authorization | HR-020, HR-021, HR-083 | M6 |
| T-010 | Permit reuse or use after revocation | A1, A7 | TB3 | Unauthorized dispatch | HR-001, HR-002, HR-009 | M6 |
| T-011 | Concurrent budget overspend; split requests; children escaping shared limits | A1 | TB1 | Financial loss | HR-048, HR-049; 1,000-goroutine race test | M4 |
| T-012 | Retry evasion with fresh action ids; duplicate irreversible effects | A1, A11 | TB1 | Double payment | HR-005..008 | M4/M6 |
| T-013 | Induced UNKNOWN outcomes to stall budgets/dependent work | A11, A3 | TB2 | Availability loss | HR-078; capped UNKNOWN reservations + escalation | M6 |
| T-014 | Equivalent-route bypass (direct API, SSH, browser, cooperative SDK path skipped) | A1 | outside TB1 | Uncontrolled effect | Credential custody; coverage states; HR-024, HR-086; sandbox (PN-008) | M9 |
| T-015 | Credential theft (connector `/proc/environ`, logs, job args, responses) | A3, A1 | TB9, TB2 | Total bypass | HR-056, HR-060, HR-061, HR-076, HR-084, HR-085 | M6 |
| T-016 | Ciphertext swap between rows/tenants (sealed blobs, envelope data) | A7 | TB5 | Wrong/privileged creds used | HR-060, HR-062 | M1/M6 |
| T-017 | Prompt-injected exfiltration through allowed channels | A2→A1 | TB11 | Data disclosure | Sequence rules (read→disclosure hold), HR-079, detections; **residual** | M10 |
| T-018 | CEL fail-open (error swallowing, string comparison of amounts) | A1 | Policy | Prohibition skipped | HR-040..044 | M4 |
| T-019 | MCP header/body mismatch, batch smuggling | A1 | TB1 | Authorize X, execute Y | HR-080 | M6 |
| T-020 | Parser differentials (duplicate keys, numbers, Unicode) | A1 | TB1/TB2 | Authorize X, target sees Y | HR-075, HR-100..103 | M4 |
| T-021 | SSRF / DNS rebinding / redirect credential leak / metadata access | A1, A8, A11 | TB2 | Infra compromise, cred leak | HR-070..073, HR-077 | M1.5/M6 |
| T-022 | Gateway mTLS identity presented to an attacker-chosen host | A1, A11 | TB2 | Control-plane impersonation | HR-074 | M1.5 |
| T-023 | DoS: CEL cost, oversized/deep input, counter cardinality, long-poll exhaustion, lock storms | A1, A8 | TB1/TB4 | Outage | HR-043, HR-057, HR-100; connection caps; rate limits | M4/M6 |
| T-024 | Reservation leak or double release after crash | A11 | — | Budget drift | HR-003, HR-004 | M1.5 |
| T-025 | Tool poisoning / rug pull (descriptions or behavior change) | A3 | TB9/TB2 | Agent manipulated; meaning drift | HR-081, HR-123; drift detection | M6/M10 |
| T-026 | Approval UI spoofing (confusables, bidi, agent-written text) | A1, A2 | TB4 | Phished approver | HR-033, HR-034, HR-102 | M5 |
| T-027 | Sock-puppet second approver | A5, A7 | TB4 | Two-person rule defeated | HR-035; residual if IdP admin colludes | M5 |
| T-028 | MCP elicitation/sampling phishing users or injecting prompts | A3 | TB2→TB1 | Secret disclosure | HR-082 | M6 |
| T-029 | Evidence tampering; insider re-signing a rewritten chain | A7 | TB5 | Lost accountability | HR-055, HR-110..112 | M7 |
| T-030 | SaaS operator forges approvals in the DB | A7 | TB5 | Unapproved execution | HR-038 | M6 |
| T-031 | Revocation/kill-switch bypass (stale gateway) or abuse (DoS engage, silent lift) | A1, A7 | TB3 | Uncontained agent / outage | HR-002, HR-010, HR-113 | M6 |
| T-032 | Token/proof replay, alg confusion, token substitution | A4, A9 | TB1 | Impersonation | HR-090, HR-091, HR-095 | M2/M3 |
| T-033 | Local workload key theft from desktop key store | A1, malware | Host | Impersonation from elsewhere | HR-092; hardware keys preferred | M3 |
| T-034 | Licence-key forgery or check removal | A12 | Code | Revenue loss | Offline Ed25519 root (HR-063); legal (BSL) | M1 |
| T-035 | GitHub OIDC mis-binding (name reuse, forks, same-repository pull-request runs, `pull_request_target`) | A4 | Attestation | Impersonation | HR-093 | M3 |
| T-036 | Package signing compromise, rollback to bad mapping, malicious mapping | A10, A7 | Packages | Total bypass | HR-063, HR-123, HR-124 | M4 |
| T-037 | API attacks: IDOR, mass assignment, injection, CSRF, OIDC mix-up, session fixation | A5, A8, A9 | TB4 | Unauthorized changes | SB-2, HR-104; authz on every call; sqlc parameterization | M2/M5 |
| T-038 | Red-team scenario run against live targets | A5 | Range | Real damage | HR-120 | M12 |
| T-039 | Sandbox escape / DNS exfil / forged probe results | A1 | Sandbox | False ENFORCED claim | HR-121, HR-122 | M9 |
| T-040 | CI/supply-chain compromise (deps, actions, release hijack) | A10 | TB10 | Malicious release | HR-130..132 | M0 |
| T-041 | Log injection / sensitive data in logs or traces | A1 | Logging | Leak, forged audit lines | SB-4 redaction types, JSON encoding, field caps | M1 |
| T-042 | Permission-unsafe search/graph/count inference | A5, A8 | TB4/TB7 | Hidden record disclosure | Permission filters before aggregation; tests (F300, F320) | M10 |
| T-043 | Customer admin abuses platform admin to read payloads or approve | A7 | TB4 | Privacy breach | Admin ≠ approver ≠ evidence reader (F583); audited restricted access | M2/M5 |
| T-044 | Trusted-issuer mis-scoping: an entry bound by names or broad claims (any repository of an owner, any namespace), or silently widened, lets unintended workloads attest as an agent | A5, A7 | Attestation configuration | Impersonation, rogue admission | HR-140, HR-141 | M3 |
| T-045 | Issuer key source abuse: a tenant-supplied issuer or key URL used for SSRF, a poisoned or stale key cache, unknown-`kid` refetch amplification | A8, A9 | Attestation | Internal network access, forged attestation, outage | HR-142, HR-071 | M3 |
| T-046 | Attestation token replay or cross-org use (a token copied from CI logs, or minted for another org's audience, enrolls a rogue instance) | A4 | Enrollment | Rogue instance at L2 | HR-143, HR-093 | M3 |
| T-047 | Kubernetes mis-binding and digest spoofing: a service account deleted and recreated with the same name, another namespace, a deleted pod's token, a swapped image, or a workload reporting a trusted image digest it does not run | A4, A5 | Attestation | Impersonation; a false `attested` release | HR-144 | M3 |
| T-048 | Represented-principal spoofing: a launcher names a user it does not act for; a subject token from an unconfigured provider, for another audience, stale or replayed; a subject token used to gain authority | A5, A4 | TB4 | Actions attributed to, and authorized for, the wrong person | HR-145, HR-146 | M3 |
| T-049 | Authority hopping: a new instance, a re-attestation, an ownership transfer or a reused agent name inherits another instance's runs or grants | A4, A1 | Enrollment | Inherited authority | HR-147, HR-022 | M3 |
| T-050 | Discovery flooding or poisoning: random keys fill the unclaimed queue, or forged observed attributes lead an owner to admit a rogue key | A1, A8 | TB1 | Owner fatigue, rogue admission, storage exhaustion | HR-148, HR-094 | M3 |
| T-051 | Browser session takeover: a session cookie planted before sign-in (fixation), a login started by an attacker completing in the victim's browser (login CSRF), cross-site requests riding the cookie, a redirect after sign-in to another site, a framed page, or a stolen cookie that outlives sign-out, user disable or a role change | A5, A8, A9 | TB4 | Actions in another person's name | HR-150, HR-151, HR-152 | M5 |
| T-052 | Rogue or cloned WebAuthn credential: an attacker holding a stolen session registers their own key or removes the victim's, a cloned authenticator, an assertion relayed from a phishing origin or replayed from another session, a step-up reused by another session or a non-human credential | A5, A6, A9 | TB4 | Forged step-up, and in part 2 forged approvals | HR-153, HR-154, HR-155, HR-156 | M5 |
| T-053 | Notification channel abuse: a tenant-chosen webhook or Slack URL used to reach private networks, cloud metadata or PantherClaw itself (SSRF, DNS rebinding, redirects), mail header injection or mail to strangers, channel secrets leaked through the API or logs | A5, A8 | TB8 | Internal network access, secret disclosure, spam | HR-157, HR-070..072, HR-077, HR-062 | M5 |
| T-054 | Notification spoofing and fatigue: forged or replayed webhooks, a Slack message whose text forges a link, a message that looks like it can approve, delivery floods that exhaust queues, a delivery failure or acknowledgement read as a decision | A1, A2, A6 | TB8 | Phished approver, missed alerts, outage | HR-158, HR-159, HR-039 | M5 |
| T-055 | Forged or stale facts: an agent, a gateway or an unregistered source supplies a fact (charge refundable, branch protected, backup verified), or an old observation is presented as current | A1, A5 | Fact providers | A prohibition or requirement skipped on false evidence | HR-160 | M4 |
| T-060 | Wait-channel abuse: a workload polls or streams another run's wait handle to learn its decisions, uses waits to learn who approves, or opens thousands of long-polls and streams to exhaust the server | A1, A4 | TB1 | Information leak, outage | HR-174, HR-030 | M5 |
| T-061 | Approval routing and escalation abuse: requests routed to ineligible or attacker-controlled people, escalation that widens who may decide, a role self-granted or an account created just before approving, a person approving their own run's action, a failed delivery or a missed deadline treated as consent | A5, A7 | TB4, TB8 | Unapproved or rubber-stamped execution | HR-170, HR-173, HR-177, HR-035 | M5 |
| T-062 | Batch-review smuggling: a high-value, irreversible or different action slipped into a batch so that one assertion approves it, or a batch assertion reused for other entries | A1, A6 | TB4 | Unapproved execution | HR-175 | M5 |
| T-063 | Decision-path misuse: a narrower proposal or evidence used to change what was approved, agent-written evidence that steers the approver, an access request or restoration that creates authority without governed review, an approval used to widen a grant | A1, A2, A5 | TB1, TB4 | Authority expansion, phished approver | HR-172, HR-176, HR-034 | M5 |

## 8. Residual risks (accepted, owner: founder, reviewed quarterly)

| ID | Risk | Why accepted | Compensating controls |
|---|---|---|---|
| R-01 | Gateway is in the TCB for routes it mediates | Inherent to a PEP | Minimal gateway, no DB access, signed releases, customer-hosted option |
| R-02 | Revocation latency bounded (< 1 s), in-flight requests complete | Physical limit | Short permits, epochs, heartbeat fail-closed |
| R-03 | Cooperative modes and opaque MCP routes are PARTIAL | Agent controls its own process | Honest labeling, sandbox, credential custody |
| R-04 | In-grant misuse by prompt-injected agents | Authority is legitimately granted | Narrow grants, sequences, approvals, detections |
| R-05 | Exfiltration via allowed channels | Data must flow for work | Destination classes, size/entropy obligations, detections |
| R-06 | Targets without query APIs cannot be reconciled automatically | Provider limitation | UNKNOWN visible, owned reconciliation queue |
| R-07 | Single Postgres + fail-closed ⇒ DB loss is an outage | Correctness over availability | Backups/PITR (upgrade: HA) |
| R-08 | Customer IdP admin can defeat SoD (sock puppets) | Identity is customer-owned | Distinct WebAuthn creds, cooldowns, admin notices |
| R-09 | Go cannot reliably zeroize secrets | Runtime limitation | Short-lived plaintext, no swap/core dumps in images |
| R-10 | Ledger proves integrity, not completeness | Inherent | Target-log reconciliation, external anchoring |
| R-11 | Solo founder: no independent human reviewer | Team size | EX-001 compensating controls ([GATES_AND_REVIEW.md](GATES_AND_REVIEW.md)) |
| R-12 | Public source can be copied | Business choice | BSL, private enterprise repo, signed roots, detection |
| R-13 | Device-code phishing: a person can be talked into confirming a code someone else started, giving that CLI their session | Device flow is the only browserless CLI login (ADR-0016) | Confirmation page shows device name, address and time with an explicit warning; same-origin POST; 10-minute codes, 5 attempts; each session is tied to the requesting device key, audited (`authn.login`) and revocable (logout, user disable) |
| R-14 | A local attacker who copies `credentials.json` gets the CLI session (the device key is in the same file) | Founder decision 4 (ADR-0016): private file now, OS keychain later | Mode 0600 in the user profile; 15-minute access tokens; 8-hour absolute sessions; refresh rotation with reuse detection; immediate server-side revocation |
| R-15 | The Kubernetes reviewer credential (TokenReview and pod reads) is a bearer token in a file; the server reads the file again every minute, so a replaced token is used up to a minute later (until 2026-10-09 a rotated token needed a restart) | M3 keeps cluster access in operator configuration (founder decision 3) | Least-privilege RBAC from the workload-identity runbook (TokenReview plus `get` on pods in pinned namespaces); short-lived reviewer tokens, rotated without a restart; any failed cluster call refuses the attestation (fail closed) |
| R-16 | Before verification, an attestation's audience picks which org's nonce and replay store a request uses | Enrollment without an enrollment token must find the org from the attestation (PAP-1 §3.2) | The verified audience must name the same org (HR-143); the proof is checked against that org's live nonces; a mismatch only costs one refused request |

## 9. Change log

| Date | Change | Gate |
|---|---|---|
| 2026-10-08 | v1.0 created from product spec, adversarial review and engineering review | G0 (M0) |
| 2026-10-08 | M2: TB4 implemented for the CLI and services (OIDC relying party with PKCE, nonce and RFC 9207; server-mediated device flow; `private_key_jwt`; `pck_` API keys; per-request revocation checks). T-032, T-037, T-043 tested for their M2 parts. Residual risks R-13 (device-code phishing) and R-14 (CLI credentials file) accepted. TB8 gains the customer IdP as an OIDC provider (HTTPS only, discovered endpoints checked). | G0 (M2), ADR-0016 |
| 2026-10-09 | M3 brief: ADR-0018 constraints become T-044..T-050 (issuer mis-scoping, key-source abuse, attestation replay, Kubernetes mis-binding, represented-principal spoofing, authority hopping, discovery flooding) with HR-140..148. New attack surfaces: trusted-issuer configuration, the workload enrollment and token endpoints, subject tokens at `StartRun`, gateway reports of unknown workloads. TB1 gains attestation by customer CI and cluster issuers; TB8 gains the OIDC provider as a source of subject tokens | G0 (M3), ADR-0018 |
| 2026-10-09 | M4 part 2 brief: T-055 (forged or stale facts) with HR-160; T-001 also mitigated by HR-161 (workloads never issue or widen grants). New attack surfaces: grant issuance and delegation, guardrail changes, fact providers pushing facts. TB1 gains delegation by workloads, which can only narrow | G0 (M4 part 2) |
| 2026-10-09 | M5 part 1 brief: browser sessions, CSRF defences, WebAuthn and notifications become T-051..T-054 (session takeover, rogue or cloned credentials, channel abuse, notification spoofing and fatigue) with HR-150..159. New attack surfaces: browser sign-in and the account page, notification destinations. TB4 gains browser sessions and WebAuthn; TB8 gains outbound notification channels, which never carry an approval | G0 (M5 part 1) |
| 2026-10-09 | M5 part 1 implemented: browser sign-in and sessions (TB4), CSRF defences, WebAuthn registration and session step-up, notification channels (TB8: outbound log, SMTP, Slack and signed webhooks through the egress client). T-051..T-054 tested with HR-150..159; T-037 tested for its M5 part; groundwork tests for HR-039 (delivery never authorizes). No residual risk added | G1 (M5 part 1) |
| 2026-10-09 | R-15 narrowed: the server reads the Kubernetes reviewer token file again every minute, so a rotated token needs no restart (`TestHR144_ReviewerTokenRotationNeedsNoRestart`) | M3 follow-up (EX-004) |
| 2026-10-09 | M5 part 2 brief: approvals, transaction-bound step-up, the approval page and the Agent Waitlist become T-060..T-063 (wait-channel abuse, routing and escalation abuse, batch-review smuggling, decision-path misuse) with HR-170..177; T-002, T-005, T-006, T-007, T-026 and T-027 are planned in full. New attack surfaces: the approval page and its WebAuthn binding ceremony, decline, evidence and narrower proposals, wait handles (long-poll and SSE), access requests, agent restorations, batch review. TB1 gains wait handles and evidence from workloads; TB4 gains approvals; TB8 gains approval routing, which never carries an approval | G0 (M5 part 2) |
