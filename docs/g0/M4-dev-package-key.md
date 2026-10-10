### G0 — M4 follow-up: a development package key — 2026-10-10

This brief is written before implementation (G0). It closes the gap that [G0 M4](M4.md) decision 3 left: "`dev seed` creates a throwaway development package key, trusted only with the development gateway on loopback". Part 2 delivered only half of it: `dev seed` signs the reference packages with a key it generates, uses once and never stores, so no server trusts any development key and a developer cannot import a package through `PackageService` locally. The founder chose to build the rest on 2026-10-10.

**What changed since decision 3.** M6 removed the development gateway token (G0 M6 design decision 20), so "trusted only with the development gateway" has no meaning any more. Decision 20 already gives the replacement: "the development package key is trusted only when the server's API and gateway listeners are both on loopback".

**Purpose:** after `dev seed`, a developer signs a package with the development key and imports it through `pclaw package import` (`PackageService`), exactly as an operator does with the offline root, against a local server only. No production configuration can ever trust that key.

**Options.**

1. **(A, recommended) A development package key, trusted only by an all-loopback server.** `dev seed` creates the key once and keeps it in `deploy/dev/secrets`. A new optional setting names its public half; a server with that setting refuses to start unless every listener and its public URL are on loopback. Details below.
2. **(B) `dev seed` registers an ordinary org package-signing key (ADR-0020).** No new trust root, but it does not work for this purpose:
   - org keys may not sign `pc.` names, and both reference packages are `pc.mock-payments` and `pc.shell` (HR-162);
   - an org package may not define an operation a PantherClaw package already defines in that org, so no package touching the refund or shell operations could be imported;
   - org-signed imports need Team edition, and no licence verifies in development (the licence `roots.json` is empty), so it would need a development bypass of the edition check: a second trust switch.
3. **(C) Option A, and only binaries built with a `devkey` build tag can load the key.** Release binaries could not trust it even with a wrong configuration. But every `go run`, `task build` and test that needs it takes `-tags devkey`, the commands in BUILD_GUIDE §4 change, and the binaries we test differ from the ones we ship.

**Design of option A.**

1. **Where the key lives.** `deploy/dev/secrets/package-dev.key` (PKCS#8 PEM, unencrypted, mode 0600) and its public JWKS `deploy/dev/secrets/package-dev.pub.json`, the `<name>.key` / `<name>.pub.json` pair `pclaw package-key create` and `pclaw-admin keygen` already use. `deploy/dev/secrets/` is git-ignored. `dev seed` creates the pair on its first run, reuses it afterwards, never overwrites it, and refuses a pair whose halves do not match. It signs the reference packages with it instead of a throwaway key.
2. **A kid that can never be a root.** The key has its own purpose, `packages-dev`, and kid `packages-dev-<thumbprint>`. `trust.ParseRoots` accepts only `packages-root-` kids derived from their keys, so the development key can never be added to the embedded `roots.json` or passed to `pclaw-admin packages verify --roots`. Imports signed with it are audited with that kid, so they are recognisable.
3. **What makes the server trust it.** One new setting, `dev.package_key_file`, names the public JWKS (empty by default; set in `deploy/dev/server.example.json`). `dev seed` finds the private half beside it. When the setting is present, configuration validation refuses to start the server (and `dev seed`) unless all of these hold:
   - `http.addr` is loopback, `http.plaintext_behind_proxy` is false and `http.trusted_proxies` is empty;
   - the host of `auth.public_url` is loopback (127.0.0.0/8, ::1 or `localhost`);
   - `gateway_api` is absent, or its `addr`, every one of its `hostnames` and its `url` are loopback;
   - `auth.api_key_env` is not `live`.
   When it starts, the server trusts the embedded package roots plus the development key, and logs a warning naming the key. Nothing else changes: the importer routes a `packages-dev-` kid to the root set, anti-rollback stays per org, and the gateway never verifies package signatures (G0 M6 decision 19).
4. **How a production configuration can never trust it.** The setting is off unless named; any non-loopback listener, a declared proxy, a non-loopback public URL or `live` API keys turn a configuration that names it into a start-up error rather than a silent downgrade; and the kid can never become a package root.
5. **Signing for developers.** `pclaw-admin packages sign --key deploy/dev/secrets/package-dev.key --version N …` accepts a `packages-dev` key (and says it is one). `pclaw-admin keygen` refuses the purpose; only `dev seed` makes development keys. Each `dev seed` creates a new org, whose reference packages use targets version 1, so a developer signs from version 2.

**Hardening rule (new, M4's range):** HR-163, "The development package key (kid `packages-dev-`, made by `dev seed`) is trusted only by a server whose API and gateway listeners, gateway hostnames and public URL are all on loopback, with no declared proxy and without `live` API keys; a configuration that names it otherwise refuses to start. It is never a package root." No new threat: T-036 (package signing compromise) covers it.

**Tests to write first:**
- `TestHR163_DevPackageKeyOnlyOnLoopback`: each production condition (non-loopback API, proxy flag, trusted proxies, public URL, gateway address, hostname or URL, `live` keys) refuses the setting; the development example configuration passes.
- `TestHR163_DevKeyIsNeverAPackageRoot`: `ParseRoots` refuses a `packages-dev-` kid; a development-signed document does not verify against the embedded roots; the development key signs `pc.` names, and org-kid routing is unchanged.
- `TestHR163_ProductionConfigsDoNotTrustTheDevKey`: without the setting, the server's package roots are exactly the embedded ones, even when the key files exist.
- Integration: `dev seed` with the development configuration creates the pair, imports the reference packages under the development kid and reuses the pair on a second run; a package signed with `pclaw-admin packages sign` and the development key imports through `PackageService` on a server built from that configuration, and the same call on a server without the setting is `PACKAGE_UNTRUSTED`.

**Delivery:** one pull request: this brief, HR-163, the code and tests, and BUILD_GUIDE §4.

**Decision:** pending (asked in the Claude Code session on 2026-10-10).
