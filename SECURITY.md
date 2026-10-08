# Security policy

PantherClaw is a security product. We treat vulnerabilities in it as the highest-priority work.

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a suspected vulnerability.**

Report privately through GitHub: **[Report a vulnerability](https://github.com/katocxl/pantherclaw/security/advisories/new)** (Security tab → *Report a vulnerability*). Include:

- affected component (server, gateway, CLI, SDK, protocol) and version or commit;
- impact and attacker preconditions;
- reproduction steps or proof of concept (use simulators/synthetic data only);
- any suggested fix.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | within 3 business days |
| Initial assessment (severity, scope) | within 7 days |
| Fix for critical issues | within 7 days of confirmation |
| Fix for high issues | within 30 days |
| Coordinated disclosure | after a fix is released, or 90 days, whichever comes first (by agreement) |

We credit reporters in the advisory unless you prefer otherwise.

## Scope

In scope: everything in this repository and official release artifacts (binaries, container images, SDK packages). Especially welcome: authorization bypasses, tenant-isolation failures, approval replay/forgery, budget races, credential exposure, equivalent-route bypasses, evidence-ledger tampering, SSRF via the gateway, supply-chain weaknesses in our build/release pipeline.

Out of scope: findings that require a compromised host running the gateway (the gateway is in the trusted computing base — see `docs/security/THREAT_MODEL.md`), denial of service by volumetric flooding, social engineering, and issues in third-party services.

## Safe harbor

Good-faith research that respects this policy, avoids privacy violations and data destruction, and only targets your own deployments or simulators will not be pursued legally by the project owner.

## Supported versions

Pre-1.0: only the latest release receives fixes. Official builds are verifiable: `gh attestation verify <artifact> --repo katocxl/pantherclaw`.
