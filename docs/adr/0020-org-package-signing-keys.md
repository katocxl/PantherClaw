# ADR-0020 — Org package-signing keys for customer-written packages

**Status:** Accepted (2026-10-09; G0 M4 decision 2, with the follow-up decisions recorded in the [G0 M4 follow-up brief](../g0/M4-org-package-keys.md))

**Context.** Every tool package gives operations their meaning, and a wrong mapping is a total bypass (HR-124). Until now only packages listed in targets metadata signed by PantherClaw's offline package root could be imported (HR-123). Customers on the Team edition need to describe their own internal tools as packages (F361, F372), and PantherClaw cannot review and sign every customer's package. The founder chose, at G0 M4 (decision 2), that org admins register an org package-signing public key and that activating a package signed with it stays a separate, audited step. The alternatives were an online PantherClaw signing key, or unsigned packages activated by two people.

**Decision.**
1. **A second kind of signer, scoped to one org.** An org registers Ed25519 public keys (kid `org-packages-<thumbprint>`, never confused with a `packages-root-` kid). Targets metadata signed with one is verified only against that org's registered, unrevoked keys, so it imports into that org and no other. The metadata format, expiry and the exact-bytes match are the package root's (HR-123); anti-rollback state is kept per key.
2. **PantherClaw's meanings stay PantherClaw's.** Names starting with `pc.` are accepted only from a package root. Within an org, an operation is defined by packages of one kind of signer only: an org package cannot redefine an operation a PantherClaw package defines, and the reverse (retired versions do not count).
3. **People decide.** Registering a key needs `package.key.manage` (Org Admin) and a person; it is audited, at most five keys are active, and a revoked key can never be registered again. Importing never activates; a Policy Publisher activates each version (no default role does both).
4. **Revocation by reason.** `ROTATED` stops new imports and keeps what the key signed. `COMPROMISED` also raises the containment epoch, quarantines the versions that decide, retires the ones not yet active, and refuses to activate any version that key signed again.
5. **Edition.** Registering keys and importing org-signed packages need Team or above. When a licence lapses, active org packages keep deciding (no outage); keys can still be listed and revoked.

HR-123 names org keys as the second kind of signer; HR-162 holds the rules above; T-056 is the threat.

**Consequences.**
- The org's private key is the org's responsibility: PantherClaw never sees or stores it. `pclaw` generates keys locally, encrypted with a passphrase, and signs offline.
- An org admin and a Policy Publisher together can give operations new meanings in their own org. That is the purpose of the feature; activation is audited and cannot touch PantherClaw's operations.
- A key compromise is contained with one call: permits already issued fail at `BeginDispatch`, and the key's versions stop deciding.
- `package_versions` records which key signed each version, so revocation and audit can find them.

**Alternatives considered.**
- An online PantherClaw key that signs whatever an org uploads: rejected. It would sign anything an org admin sends, so it adds no review, and an online signing key is a target (HR-063 keeps signing keys offline).
- Unsigned packages activated by two people: rejected. Nothing would bind the activated bytes to what the org's release process produced, and it needs two people even in small teams.
- Letting org keys sign any name: rejected. One stolen key could replace the meaning of a reviewed PantherClaw operation such as a refund.
