# ADR-0018 — Federated workload identity and represented principals from the customer's identity provider

**Status:** Accepted (founder decision 2026-10-09). The M3 G0 brief turns the constraints below into `HR` rules and threat rows.

**Context.** Enterprises already issue identities to workloads (GitHub Actions, GitLab CI, Kubernetes, cloud workload identity, SPIFFE) and, increasingly, to agents themselves (Microsoft Entra Agent ID, Okta). PAP/1 L2 named GitHub Actions and Kubernetes only, each as its own code path, and SPIFFE was "Later". A run's represented principal could only be named by the launcher. A product that needs its own agent directory competes with identity platforms instead of building on them.

**Decision.**
1. **L2 attestation accepts workload tokens from configured trusted issuers.** Each issuer entry pins the issuer URL, the key source, the expected audience (`pantherclaw:<org>`), the allowed algorithms and the immutable claims that bind a token to one agent (for GitHub: `repository_id`, `repository_owner_id`, and `job_workflow_ref` including a protected branch or tag ref). Presets are code and carry extra rules that configuration cannot disable: GitHub rejects `pull_request` runs, from forks or the same repository, and `pull_request_target`, because they execute code not yet reviewed into the protected ref (HR-093); Kubernetes uses TokenReview plus the image digest. M3 ships the GitHub Actions and Kubernetes presets. GitLab CI, cloud workload identity, SPIFFE JWT-SVIDs and Entra Agent ID follow as presets (PN-002.3, now `Next`). L3 keeps hardware and infrastructure attestation (SPIFFE X.509 SVIDs, cloud instance identity documents).
2. **`StartRun` may prove the represented principal with an RFC 8693 subject token.** A service account that starts a run for a signed-in user passes that user's token from one of the org's configured OIDC providers as `subject_token`: an ID token, or an access token that is a signed JWT (RFC 9068); opaque access tokens are rejected because PAP/1 defines no introspection; the authenticated launcher is the actor. The Authority checks issuer, signature, audience, expiry and freshness, links `(iss, sub)` to an org user as in ADR-0016, and records the identity-provider identity and the actor chain on the run. PantherClaw never mints human identity. The token proves who is represented; it grants nothing (invariant 1), and the task grant still decides.
3. **Constraints for the M3 brief:**
   - names alone never bind: an issuer entry without pinned immutable binding claims is rejected;
   - issuer keys are fetched only over TLS through the egress-guarded client, with a bounded cache lifetime;
   - each attestation token is single use (replay store on `jti`);
   - a new attestation never moves authority from one instance to another (F033, F034);
   - subject tokens must name PantherClaw as audience and be at most 5 minutes old;
   - adding or widening an issuer entry is a protected change (F582).

**Consequences.** A new CI system or identity platform becomes a preset plus tests, not a new attestation path. Issuer misconfiguration is the new risk; it is handled by validation, protected changes and preset rules that cannot be switched off. Agents that must run on pull requests (for example review bots) cannot be admitted automatically through the GitHub preset; the M3 brief decides their admission path. PAP/1 §3.3 and §5 change before any implementation exists (M3 has not started).

**Alternatives.** Bespoke code per platform (slower; each one a separate review); SPIFFE everywhere (heavy for desktop and serverless agents, ADR-0013); trusting a principal the launcher names (breaks invariant 4 for service launchers); a full token-exchange service that issues downstream tokens (unnecessary: connectors already mint narrow provider-native tokens, such as GitHub App installation tokens).
