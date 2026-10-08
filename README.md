# PantherClaw

**AI Agent Identity & Runtime Authorization Firewall** — an *agent transaction firewall*.

> Give an agent useful authority. Make every consequential action explainable. Stop that authority when it is no longer appropriate.

PantherClaw sits between AI agents and the systems they act on. Every consequential action is tied to a **verified agent workload**, a **represented principal** and a **task-specific grant**; it is decided by a deterministic policy engine (allow · constrain · hold for approval · deny · cannot authorize); it is executed **exactly as authorized** with credentials the agent never sees; and decision, execution and effect are recorded as **signed, hash-chained evidence**.

> **Status: pre-alpha — under active construction.** Milestone **M0 (bootstrap)** is complete. Follow progress in [docs/BUILD_GUIDE.md](docs/BUILD_GUIDE.md). Nothing here is production-ready yet.

## What it does

| Pillar | In one line |
|---|---|
| Inventory, discovery & lifecycle | Find every agent (including shadow MCP configs), give it an owner, track it from discovered to retired |
| Identity & Authority Protocol (PAP/1) | Proof-of-possession workload identity, launcher vs represented principal, server-minted runs |
| Authorization | Task grants with non-expanding delegation, CEL policies, exact decisions with explanations |
| Non-bypassable transaction boundary | Gateway re-serializes exactly what was authorized, injects sealed credentials, fails closed |
| Agent Waitlist | One queue for everything awaiting a security decision — admission, access requests, holds, tool reviews, restoration, reconciliation |
| Agent controls | Concurrency-safe budgets, counters, sequences, constraints |
| Containment | Scoped suspension and revocation with per-path verification; asymmetric org kill switch |
| Monitoring, threat detection, investigation | Attention-ranked operations, MITRE ATLAS / OWASP Agentic mapped detections, evidence-first cases, OCSF export |
| Breach radius | Observed vs effective vs credential/bypass reach |
| Proof | Signed decision/execution/effect receipts, Merkle checkpoints, transparency-log anchoring, offline verification |
| Coverage & adversarial sandbox | Honest coverage states, egress-locked containment sandbox, red-team range |

Full list: [docs/FEATURES.md](docs/FEATURES.md).

## Integrations (MVP)

- **MCP gateway** — point any MCP client (Claude, Cursor, VS Code…) at PantherClaw.
- **Python SDK** (LangChain/LangGraph, OpenAI Agents SDK, CrewAI) · **TypeScript SDK** (Vercel AI SDK, MCP TS) · **Go SDK**.
- **Claude Code / Claude Agent SDK** hooks.

## Documentation

| Document | Purpose |
|---|---|
| [docs/BUILD_GUIDE.md](docs/BUILD_GUIDE.md) | How PantherClaw is built: rules, milestones, tests |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, flows, data, deployment |
| [docs/protocol/PAP-1.md](docs/protocol/PAP-1.md) | PantherClaw Authority Protocol (Apache-2.0) |
| [docs/security/](docs/security/) | Threat model, hardening rules, baselines, gates |
| [docs/FEATURES.md](docs/FEATURES.md) | Product features by pillar and edition |
| [docs/reference/](docs/reference/) | Full product specification (F001–F802) |

## Development

```bash
task setup    # git hooks + pinned tools
task check    # format, headers, lint, tests, workflow lint, secret scan
```

No global installs needed beyond Go and Docker: every tool is pinned under `tools/pins/` and runs via `go tool` (`go tool -modfile=tools/pins/task/go.mod task check` works without Task installed). See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Report vulnerabilities privately: [Security advisories](https://github.com/katocxl/pantherclaw/security/advisories/new). See [SECURITY.md](SECURITY.md).

## License

- Core (server, gateway, CLI, simulators): **Business Source License 1.1** — free for development, testing and evaluation, and for production use governing up to **5 agents in one organization**; not for hosted/competing offerings. Each version converts to Apache-2.0 four years after release. See [LICENSE](LICENSE) and [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md).
- SDKs, protocol specification and Claude Code integration: **Apache-2.0** (see [NOTICE](NOTICE)).
- PantherClaw™ is a trademark of Joshua Kato — see [TRADEMARKS.md](TRADEMARKS.md).
