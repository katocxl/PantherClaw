### G0 — M4 follow-up: org package-signing keys (Team edition) — 2026-10-09

This brief is written before implementation (G0). It plans the follow-up that [G0 M4](M4.md) decision 2 left open: "org admins register an org package-signing key; activation is a separate, audited step. Built as a follow-up (Team edition)." The architecture decision is [ADR-0020](../adr/0020-org-package-signing-keys.md).

**Purpose:** let a Team org describe its own internal tools as tool packages (F361, F372) without PantherClaw signing them. The org keeps a signing key offline, registers its public half, signs targets metadata for its packages, and imports them. They then go through the same review and activation as PantherClaw's packages, and they can never change what a PantherClaw operation means.

**Scope:**
- `internal/definitions/trust`: org keys (kid `org-packages-` plus the key's thumbprint), strict parsing of their public JWK, signing and verification with them, and the reserved `pc.` namespace.
- `internal/definitions/app`: register, revoke and list keys; the importer routes org-signed targets to the org's own keys, with anti-rollback per key; activation refuses versions of a key revoked as compromised; the edition check.
- Migration `00026_package_keys.sql` (M4's reserved range): `package_signing_keys` (one row per key, with its anti-rollback state), and `package_versions.signing_key_id`. The Postgres store implements the `Keys` port and the operation rule.
- `PackageService` gains `RegisterSigningKey`, `RevokeSigningKey` and `ListSigningKeys`; `PackageVersion` gains the signing key's kid. New permission `package.key.manage` on the Org Admin role.
- `pclaw package-key create|register|revoke|list` and `pclaw package sign` (keys are generated and used on the customer's machine, encrypted with a passphrase; never sent to the server).

**Out of scope:** customer-authored definitions through an API instead of package files (F361's guided authoring), package tests as a publication gate (M11), a review diff for capability-widening updates (F373), more than one person to register a key (decision 3 below), and hardware-backed signing keys.

**Threat slice:** the new T-056 (org key abuse), T-036 (package signing compromise, rollback, malicious mapping), and T-003 for the new table.

**Hardening rules in scope:** the new HR-162; HR-123, amended to name org keys as the second kind of signer; HR-124 (an org's mappings are still the org's reviewed code); HR-002 (a compromised key raises the containment epoch); HR-004 (every state change is conditional); HR-050..057 for the new table.

**Product requirements:** F361 (signing and import of customer-defined packages), F372, F395 (separate review and activation).

**Security constraints and design decisions:**
1. **Two kinds of signer, never mixed.** The importer reads the kid of the targets document only to choose a key set: an `org-packages-` kid is verified against that org's active keys alone; anything else against the package roots alone. A forged kid therefore cannot borrow the other set.
2. **Anti-rollback per key.** Each key keeps the highest targets version it was accepted with, beside the package root's per-org state. A key rotation starts a new sequence; the old key's metadata no longer verifies once it is revoked.
3. **Namespace.** An org key never signs a name starting with `pc.` (refused when signing and again when importing). Within an org, an operation is defined by packages of one kind of signer only; retired versions do not count. Imports into an org are serialized (one advisory lock per org), so two concurrent imports cannot both pass this check.
4. **Separation of duties.** Org Admin holds `package.key.manage` and `package.import`; Policy Publisher holds `package.activate`; no default role holds both `package.key.manage` and `package.activate`. Because service accounts may hold Org Admin, `package.key.manage` is not a human-only catalog permission: the use case lets only a person register a key, while revoking (which only removes trust) is open to any holder of the permission.
5. **Revocation.** A key moves `ACTIVE → REVOKED` once, with a reason. `ROTATED` keeps its versions. `COMPROMISED`, in one transaction: the containment epoch first (design decision 8 of part 2), then `ACTIVE`/`STALE` versions to `QUARANTINED` and `UNCLASSIFIED`/`DRAFT`/`REVIEWED` versions to `RETIRED`, each audited. A quarantined version may go back to review, but activation of any version signed by a compromised key is refused.
6. **Edition.** Registering a key and importing an org-signed package need Team or above (the grace period counts). Everything else works on any edition, so a lapsed licence never stops active packages.
7. **Limits.** At most 5 active keys per org; a key name is 1–64 letters, digits, spaces, dots, dashes or underscores; a JWK with any member beyond the public Ed25519 fields (a private `d`, for example) is refused.

**Founder decisions** (asked in the Claude Code session on 2026-10-09; each answered with the recommended option):
1. **What revoking a key does to what it signed.** *Answer:* the reason decides. `ROTATED` keeps its packages; `COMPROMISED` quarantines or retires every version it signed and raises the containment epoch.
2. **Namespace.** *Answer:* reserve both: `pc.` names only from PantherClaw's root, and an org package may not define an operation that a PantherClaw package defines in that org (and the reverse).
3. **Who registers a key.** *Answer:* one person with the new `package.key.manage` permission on Org Admin, audited. Activation stays with Policy Publisher.
4. **Edition.** *Answer:* registering keys and importing org-signed packages need Team or above; active org packages keep deciding after a licence lapses, and keys can still be listed and revoked.

**Tests to write first:**
- `TestHR162_*`: org keys sign and verify only their org's packages; a kid must be derived from its key; strict JWK parsing; per-key anti-rollback independent of the root's; registration is human, Team, limited to 5 active keys, and never re-registers a revoked kid; a lapsed licence blocks only new keys and imports; a rotated key's versions keep working; the role catalog keeps keys and activation apart.
- `TestT056_*`: unregistered, revoked and other orgs' keys are untrusted; org packages never redefine PantherClaw operations (both directions); a compromised key withdraws its versions, raises the epoch, and its versions cannot be activated again.
- The generated table check (`TestHR053_EveryTenantTableIsIsolated`) covers the new table; store integration tests for cross-org isolation, the conditional updates and the per-org lock; RPC tests for permissions, editions and IDOR.

**Delivery plan (stacked pull requests):** 1 this brief, ADR-0020, HR-162, T-056, the trust and application layers on in-memory fakes, and the permission · 2 migration `00026` and the Postgres store · 3 the `PackageService` RPCs and server wiring · 4 the `pclaw` commands.

**Decision:** APPROVED — Joshua Kato, 2026-10-09 (decision 2 at G0 M4; the four follow-up decisions above, recommended option on each)

---

### Status — 2026-10-09

**Delivered** as four stacked pull requests: #113 (brief, ADR-0020, HR-162, T-056, trust and use cases), #116 (migration `00026`, Postgres store), #118 (`PackageService` RPCs, server wiring) and the `pclaw` commands. `task check`, `task test:integration` and `task trace` through M4 pass on each.

**How an org uses it** (Team edition and above):

```bash
pclaw package-key create --name release --out-dir ~/keys --passphrase-file ~/keys/pp
pclaw package-key register --name "release 2026" --public-key-file ~/keys/release.pub.json
pclaw package sign --key ~/keys/release.key --passphrase-file ~/keys/pp --version 1 --expires-days 180 --out targets.jws package.yaml
pclaw package import --name acme.payments --version 1.0.0 --targets-file targets.jws --file package.yaml
```

A Policy Publisher then activates the version (`pclaw package transition … --to active`, from #103). After a rotation, revoke the old key with `--reason rotated`; after a leak, with `--reason compromised`.

**Deviations:**
1. `package.key.manage` is not in the human-only catalog (design decision 4): the Org Admin role may be bound to service accounts, and a human-only permission would make the whole role unbindable for them. The use case refuses a non-person registering a key instead, and `TestHR162_RegisteringAKeyNeedsAPersonTeamAndAValidKey` and the RPC test cover it.
2. The command group is `pclaw package-key …`, not `pclaw package key …`, because `pclaw` commands are at most two words.
3. Signing tools share `trust.TargetOf`; `pclaw-admin keygen` refuses the new `org-packages` key purpose, which only `pclaw` creates.

**Still open:** a review diff for capability-widening package updates (F373) and package tests as a publication gate (M11).
