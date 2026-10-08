# PantherClaw — Security Findings Process (SG14)

**Open vulnerabilities are never recorded in this public file.** They live in private GitHub Security Advisories (Security tab) until fixed and disclosed. This file records the process and **closed** findings only.

## Process

1. **Intake:** CI scanners, AI reviewers, fuzzing, red-team range, external reports (SECURITY.md), self-review.
2. **Triage (≤ 7 days):** severity (CVSS v4 + product impact on invariants), affected versions, threat ID (`T-###`), hardening rule (`HR-###`), owner.
3. **Track:** private advisory (security-relevant) or issue (non-sensitive quality finding).
4. **Fix:** test reproducing the finding first; fix; both AI reviewers re-run; G1.
5. **Verify:** the reproducing test passes on the fixed revision; evidence linked.
6. **Close & disclose:** publish advisory/CVE where appropriate; add a row below.

A finding is never closed because a model proposed a fix — only when the verifying test passes on a merged revision.

## Closed findings

| ID | Date closed | Severity | Component | Summary | Fix revision | Verifying test |
|---|---|---|---|---|---|---|
| — | — | — | — | No findings closed yet. | — | — |

## Design-review findings incorporated before code (2026-10-08)

Pre-implementation adversarial and engineering reviews produced design changes (not vulnerabilities in code). They are recorded as binding rules HR-001…HR-132 in [HARDENING_RULES.md](HARDENING_RULES.md).
