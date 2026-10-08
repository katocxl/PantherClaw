## What and why

<!-- One paragraph. Link the milestone G0 brief. -->

**Requirement IDs:** <!-- F### / PN-### / HR-### / T-### -->

## Security checklist (G1)

- [ ] Tests written first for security-relevant behavior, including negative/abuse cases (named `TestHR###_…` / `TestT###_…` where applicable)
- [ ] Tenancy: every new query is tenant-scoped (typed `OrgID` + RLS); new tables have cross-tenant tests
- [ ] Inputs validated at the edge (protovalidate) and in the domain; failures are fail-closed (`DENY` / `CANNOT_AUTHORIZE`)
- [ ] No secrets, tokens or payloads in logs, errors, job args or receipts
- [ ] Outbound HTTP uses `internal/platform/httpx` clients (no redirects, dial-time IP checks)
- [ ] No new dependency — or a justification row was added to `docs/security/DEPENDENCY_POLICY.md`
- [ ] Threat model / hardening rules / ADRs updated if trust boundaries, identity, data flows or dependencies changed
- [ ] `task check` passes locally

## Reviews

- [ ] Claude review (ai-review) addressed
- [ ] CodeRabbit review addressed (disagreements recorded below)
- [ ] Founder G1 after ≥ 1 h cooling-off: comment `G1: approved <sha>`

<!-- Disagreements between reviewers and their adjudication: -->
