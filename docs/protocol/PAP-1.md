<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Joshua Kato -->

# PantherClaw Authority Protocol — PAP/1

**Status:** Draft 1 (2026-10-08; §3.3 and §5 revised 2026-10-09) · **License:** Apache-2.0 (this directory) · **Normative language:** MUST, MUST NOT, SHOULD, MAY per RFC 2119/8174.

PAP/1 defines how an AI agent workload proves *who it is*, how a run is bound to *whose authority* it uses, how a requested action is expressed *exactly*, and how authorization, dispatch and evidence are represented so that any party can verify them. It is open so that SDKs, gateways and target-side verifiers interoperate.

## 1. Roles

| Role | Description |
|---|---|
| **Workload** | One running agent instance (process/container/job). Holds a private key. |
| **Owner** | Human accountable for an agent; issues enrollment tokens and confirms key fingerprints. |
| **Launcher** | Human or service that starts a run. |
| **Represented principal** | The human/service whose authority the run uses. MAY differ from the launcher. |
| **Gateway (PEP)** | Enforcement point that mediates actions. |
| **Authority (PDP + finalizer)** | PantherClaw Transaction Authority: decides and finalizes. |
| **Target** | System where the effect happens. In *target-enforced mode* it verifies action tokens. |
| **Verifier** | Any party checking receipts offline. |

## 2. Cryptographic profile

| Use | Algorithm |
|---|---|
| Signatures (tokens, proofs, receipts, permits, checkpoints) | Ed25519 (JWS `alg: "EdDSA"`, `crv: "Ed25519"`). Receipts MAY carry an additional ML-DSA-65 signature (§9.4). |
| Hash | SHA-256, encoded base64url without padding unless stated. |
| Key thumbprint | RFC 7638 JWK thumbprint (SHA-256) = `jkt`. |
| Canonical JSON | RFC 8785 (JCS). |
| Sealed credentials | HPKE (RFC 9180) KEM `MLKEM768-X25519` (X-Wing), KDF HKDF-SHA256, AEAD AES-256-GCM. |
| Transport | TLS 1.3. Gateway↔Authority: mutual TLS. |

Implementations MUST pin algorithms per key (`kid`) and MUST reject `alg: none`, HMAC algorithms on asymmetric keys, and any algorithm not listed for that key.

## 3. Workload identity

### 3.1 Key generation
The workload MUST generate an Ed25519 key pair locally. The private key MUST NOT leave the workload. Implementations SHOULD use non-exportable hardware-backed storage (TPM, Secure Enclave) when available.

### 3.2 Enrollment
1. The Owner requests an **enrollment token** for `(org, agent, environment)`. Properties: random 256-bit secret, single use, TTL ≤ 15 minutes, stored by the Authority only as SHA-256.
2. The workload sends `EnrollWorkload{enrollment_token, public_jwk, attestation?, declared_release?}` signed with its private key (proof of possession over a server-provided challenge).
3. The Authority creates an **agent instance** in state `PENDING_ADMISSION` and an `ADMISSION` waitlist entry showing the key fingerprint. The Owner MUST confirm the fingerprint (or an attestation policy auto-admits L2+ instances that match pinned claims).
4. On admission the instance becomes usable; until then requests are `CANNOT_AUTHORIZE` (or observed only in monitor mode).

### 3.3 Attestation levels
| Level | Evidence | Notes |
|---|---|---|
| L1 | Enrollment token + Owner fingerprint confirmation | Desktop workloads (`pclaw mcp proxy`) are capped at L1. |
| L2 | Workload token from a **trusted issuer** configured for the org. Presets: GitHub Actions OIDC token; Kubernetes projected service-account token (validated via TokenReview) + image digest | Every issuer entry MUST pin the issuer, key source, audience (`pantherclaw:<org_id>`), allowed algorithms and at least one immutable claim binding the token to one agent; an entry without one MUST be rejected. Rules built into a preset MUST NOT be disabled by configuration. GitHub: MUST match `repository_id` and `repository_owner_id`; MUST require `ref_protected` to be `true` (the triggering ref is a protected branch or tag); MUST reject tokens whose `event_name` is `pull_request` (from forks or the same repository) or `pull_request_target`, because those runs execute code not yet reviewed into a protected ref. The workflow binding depends on the job type, and each issuer entry declares which it accepts: an ordinary workflow job binds on `workflow_ref` (workflow path and ref); a job that calls a reusable workflow binds on `job_workflow_ref` (the called workflow's path and ref, which MUST itself be a protected branch or tag of its repository). An entry MAY also pin `workflow_sha` or `job_workflow_sha` to one exact revision. Kubernetes: the projected token MUST carry the entry's audience and be validated through TokenReview, which MUST return the bound pod's name and UID; the entry pins the cluster, namespace and service account. The image digest MUST come from trusted cluster state for that pod UID (the API server's `status.containerStatuses[].imageID`) or from signed evidence bound to that pod, such as a verified image signature or admission attestation; a digest the workload supplies itself is only `declared`. Each attestation token is single use (`jti`). Further presets (GitLab CI, cloud workload identity, SPIFFE JWT-SVID, Microsoft Entra Agent ID) are future. |
| L3 | SPIFFE X.509 SVID / cloud instance identity | Future. |

Release identity (code hash, image digest) is recorded as `declared` unless supplied by L2+ attestation, then `attested`. A value the workload reports about itself is always `declared`, whatever its attestation level.

### 3.4 Workload token
Issued by the Authority after admission; JWS compact, header `{"alg":"EdDSA","kid":"<authority key id>","typ":"pap-wt+jwt"}`:

```json
{
  "iss": "https://<authority>",
  "sub": "pc:org/<org_id>/agent/<agent_id>/inst/<instance_id>",
  "aud": "pantherclaw-gateway",
  "iat": 1791457200, "nbf": 1791457200, "exp": 1791457800,
  "jti": "<uuidv7>",
  "cnf": {"jkt": "<RFC 7638 thumbprint of workload key>"},
  "pap": {"v": 1, "org": "<org_id>", "env": "<env_id>", "att_lvl": 1, "release": {"state": "declared", "digest": "sha256:…"}}
}
```

TTL MUST be ≤ 10 minutes. Refresh requires a fresh request proof.

## 4. Request proof (DPoP profile)

Every request from a workload MUST carry `Authorization: PAP <workload token>` and `PAP-Proof: <JWS>` signed with the workload key. Header `{"alg":"EdDSA","typ":"pap-proof+jwt","jwk":{…public key…}}`; claims:

| Claim | Meaning |
|---|---|
| `htm`, `htu` | HTTP method and target URI (scheme, host, path; no query/fragment) |
| `iat` | Issued-at (seconds) |
| `jti` | Unique id (≥ 128 bits) |
| `ath` | base64url(SHA-256(workload token)) |
| `bh` | base64url(SHA-256(raw request body bytes)) — computed **before** any parsing |
| `nonce` | Most recent server-issued nonce (`PAP-Nonce` response header) |

Verification order (MUST): (1) verify workload token signature, `iss`, `aud`, `exp/nbf`; (2) verify proof signature with the embedded `jwk`; (3) check `jkt(jwk) == cnf.jkt`; (4) check `htm/htu/ath/bh`; (5) check `nonce` is current (server-issued, ≤ 5 min); (6) **then** insert `(jkt, jti)` into the replay store (unique, retained ≥ nonce lifetime + 60 s). Failure at any step: HTTP 401 with `PAP-Error` code (§12) and, where applicable, a fresh `PAP-Nonce`.

## 5. Runs

A **run** is created by the Authority (never by the workload) via `StartRun{agent_id, instance_id?, launcher, represented_principal, grant_id | task template, task_ref}` called by an authenticated launcher (human session, service account, or automation identity). The Authority returns a server-minted `run_id` bound to: instance (or instance set), launcher, represented principal and grant. Workloads reference `run_id`; any mismatch with the bound instance ⇒ `DENY` (tamper).

**Represented principal from the customer's identity provider.** When the launcher is not the represented principal (for example a service that starts a run for a signed-in user), `StartRun` MAY carry `subject_token` and `subject_token_type` with RFC 8693 semantics, issued to that user by an OIDC provider configured for the org: either an OIDC ID token or an access token that is a signed JWT (RFC 9068 profile) carrying `iss`, `sub`, `aud`, `exp` and `iat`. Opaque access tokens MUST be rejected; PAP/1 defines no introspection path. The launcher is the actor. The Authority MUST verify the signature, issuer, audience (MUST name the Authority), expiry and freshness (`iat` ≤ 5 minutes old), MUST reject a replayed token (keyed on `jti`, or on the token's SHA-256 when it has none), and MUST link `(iss, sub)` to a user of the org. The run records the provider identity and the actor chain. A subject token proves who is represented; it MUST NOT create, widen or substitute for a grant.

## 6. ActionIR v1 — the canonical action

ActionIR is produced by the gateway (or SDK, for cooperative mode) from a raw tool call using an **ACTIVE, signed tool package**. Schema (all fields required unless marked optional):

```json
{
  "v": 1,
  "org": "<org_id>", "env": "<env_id>",
  "run_id": "<server-minted>", "action_id": "<uuidv7, stable across retries of the same logical action>",
  "agent_instance": "<instance_id>",
  "operation": "payments.refund.create",
  "definition": {"package": "pc.mock-payments", "version": "1.0.0", "digest": "sha256:…"},
  "channel": "mcp | http | sdk | hook",
  "route": "<route_id>",
  "target": {"type": "payments.charge", "id": "ch_3Px…", "account": "acct_…"},
  "params": {"amount": {"value": "85.00", "currency": "USD"}, "reason": "duplicate"},
  "destinations": [{"kind": "external", "id": "…"}],
  "dedupe_key": "refund:order_714"
}
```

Rules (MUST):
- **Strict parsing:** reject duplicate object keys, invalid UTF-8, unknown fields, nesting depth > 16, strings > 8 KiB (material) / 64 KiB (other), total > 1 MiB.
- **No JSON numbers in material parameters.** Amounts are decimal strings matching `^-?(0|[1-9][0-9]{0,17})(\.[0-9]{1,8})?$`; currencies are ISO-4217 uppercase.
- **Identifiers** (target ids, accounts, recipients): reject mixed-script/confusable strings and bidi controls; never case-fold or Unicode-normalize bytes that are meaningful to the target (git refs, file paths, object keys).
- **No defaults:** an ambiguous target, missing material field or unsupported unit ⇒ `CANNOT_AUTHORIZE` (never a silent default).
- **Canonical hash:** `action_hash = SHA-256(JCS(ActionIR))`.
- **Dedupe key:** irreversible operations declare a semantic dedupe key in the tool package; an open `UNKNOWN` or recent success on the same key parks a new request in `RECONCILIATION`.

## 7. Authorization exchange

### 7.1 Authorize
`Authorize{action: ActionIR, workload_token, proof, body_hash}` from gateway to Authority over mTLS. The Authority MUST re-verify §4 itself and MUST derive the org from the gateway certificate binding (reject mismatch). Response:

```json
{
  "decision": "ALLOW | ALLOW_WITH_OBLIGATIONS | REQUIRE_APPROVAL | REQUIRE_STEP_UP | DENY | CANNOT_AUTHORIZE",
  "transaction_id": "<uuidv7>",
  "action_hash": "…",
  "reasons": [{"code": "GRANT_AMOUNT_EXCEEDED", "check": "authority", "detail": "…", "decisive": true}],
  "obligations": [{"kind": "field_filter", "timing": "before_execution", "spec": {…}}],
  "wait": {"handle": "…", "retry_after_s": 5, "expires_at": "…"},
  "permit": "<JWS, only for ALLOW / ALLOW_WITH_OBLIGATIONS>",
  "receipt_ref": "…"
}
```

Idempotency: `(org, run_id, action_id)` is unique. Same triple + same hash ⇒ the stored decision is returned. Same triple + different hash ⇒ `DENY` with code `ACTION_TAMPERED` and a security alert. `DENY` and expired decisions are terminal for that triple; `CANNOT_AUTHORIZE` MAY be retried.

### 7.2 Dispatch permit
JWS, `typ: "pap-permit+jwt"`, TTL ≈ 5 s:

```json
{"iss": "…", "aud": "gw:<gateway_id>", "jti": "<permit_id>", "iat": …, "exp": …,
 "pap": {"v": 1, "org": "…", "txn": "<transaction_id>", "act": "<action_hash>",
         "epoch": 42, "approval": {"binding": "…", "assertion": "<WebAuthn assertion, high-consequence only>"}}}
```

### 7.3 BeginDispatch (commit point)
Before sending any byte to the target the gateway MUST call `BeginDispatch{permit_id, epoch}`. The Authority atomically transitions the permit `ISSUED → DISPATCHING` only if not expired (database clock) and `epoch` equals the org's current containment epoch. Any failure ⇒ the gateway MUST NOT dispatch. A permit that was `DISPATCHING` without a recorded outcome becomes `UNKNOWN` (never released automatically).

### 7.4 RecordExecution
`RecordExecution{permit_id, outcome: accepted|failed|unknown, target_response_digest, timings}` → execution receipt. The target-facing idempotency key (where the target supports one) MUST be derived from `transaction_id`, never from agent-supplied ids.

## 8. Holds, waiting and approvals

- `REQUIRE_APPROVAL` / `REQUIRE_STEP_UP` return `wait.handle`. SDKs MAY long-poll `Wait{handle}` or subscribe via SSE; MCP clients receive a structured pending result (or the tasks extension when negotiated).
- When the requirement is satisfied the workload **resubmits the same `run_id` + `action_id` with an identical action hash**. The Authority re-runs the full pipeline and finalizes only if the same requirement class is now satisfied.
- **Approval binding:**
  `binding = SHA-256(JCS({action_hash, decision_basis_digest, material_facts_digest, grant_revision, definition_digest, run_id, agent_instance, jkt, approver_requirements, expires_at, display_hash}))`
  where `display_hash` is the SHA-256 of the approval text rendered from the tool package's approval template (agent-supplied text is excluded and shown separately as untrusted).
- High-consequence approvals MUST be WebAuthn assertions with `challenge = binding` (user verification required). Approvals are accepted only from human sessions — never from API keys or service accounts. Two-person rules require two distinct users **and** distinct WebAuthn credentials.

## 9. Receipts and evidence

### 9.1 Decision receipt
Signed JWS (`typ: "pap-decision+jwt"`) containing: transaction id, action hash, decision, reasons, checklist, obligations, versions (decision-basis digest, grant revision, definition digest), facts digest, identity summary (instance, att_lvl, launcher, principal), timestamps, `simulated` flag.

### 9.2 Execution receipt
Effective action hash, permit id, gateway id, access mode (target-enforced, narrow temporary, PantherClaw-held, constrained runtime, agent-held), attempts, dispatch time, outcome, target response digest, `simulated` flag.

### 9.3 Effect receipt
Verifier identity and authority, verification level (transport/acceptance · follow-up state · domain effect · downstream consequence), expected vs observed effect, result state (§ARCHITECTURE 6.2), basis, limitations, timestamps.

### 9.4 Signatures and chaining
Receipts are Ed25519-signed; the format reserves `sigs[]` for an additional ML-DSA-65 signature. Receipts are linked into a per-org hash chain (`entry_hash = SHA-256(prev_hash ‖ JCS(entry))`) and summarized in signed Merkle checkpoints. A global root over all orgs MAY be anchored in a public transparency log.

## 10. Target-enforced mode (action tokens)

For targets that run PantherClaw verifier middleware, the gateway attaches `PAP-Action: <JWS>`:

```json
{"iss": "…", "aud": "<target id>", "jti": "<single use>", "iat": …, "exp": "≤ 60 s",
 "pap": {"v": 1, "txn": "…", "act": "<action_hash>", "bh": "<SHA-256 of the exact outbound body>",
         "op": "payments.refund.create", "target": {"type": "…", "id": "…"}}}
```

The verifier MUST check signature (JWKS), `aud`, expiry, `bh` against the received body, single use of `jti` in a **shared** replay store, and that the requested operation/target match. Only then may the route be counted as `ENFORCED` for cooperative (SDK) modes.

## 11. Keys and discovery

- JWKS: `GET /.well-known/pantherclaw/jwks.json` (Authority signing keys, with `use`, `alg`, `kid`).
- Rotation every 90 days with ≥ 7-day overlap; revoked keys published in `/.well-known/pantherclaw/revoked-keys.json`.
- Tool packages and licence keys are signed by separate offline roots (not in the JWKS).

## 12. Error codes (`PAP-Error`)

`invalid_token`, `token_expired`, `invalid_proof`, `proof_replay`, `use_nonce`, `key_mismatch`, `body_hash_mismatch`, `instance_not_admitted`, `attestation_insufficient`, `run_mismatch`, `action_tampered`, `unknown_route`, `definition_inactive`, `ambiguous_input`, `rate_limited`, `authority_unavailable` (→ `CANNOT_AUTHORIZE`).

## 13. Versioning

`pap.v` is a major version. Additive fields are allowed within v1; consumers MUST ignore unknown *claims* in tokens but MUST reject unknown *fields* in ActionIR. Breaking changes require PAP/2.

## 14. Security considerations (summary)

Replay is prevented by `(jkt, jti)` uniqueness, server nonces and single-use permits/tokens; token theft without the private key is useless; agents never receive target credentials; the gateway re-serializes outbound requests from ActionIR so parser differentials cannot smuggle unauthorized effects; the Authority never trusts gateway assertions about org or identity; cooperative modes are labeled honestly. See `docs/security/THREAT_MODEL.md` and `docs/security/HARDENING_RULES.md` in the PantherClaw repository.
