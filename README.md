# PantherClaw

**The agent transaction firewall.**

PantherClaw gives every AI agent a verified identity, only the access its current task needs, and a firewall it cannot route around, with evidence your auditors can check. It answers one question for every consequential action: can this agent run do this, for this task, through this route, right now, and can we prove the boundary held?

> **Status: pre-alpha.** Under active development; not ready for production use. Everything below is planned.

## What's inside

| Component | What it does |
|---|---|
| **Agent Identity** | Finds every agent, gives it an owner, and verifies which workload is acting and for whom, using the identities you already have (your IdP, GitHub Actions, Kubernetes) |
| **Task Access** | Just enough access for one task, for a limited time, with exact human approvals |
| **Policy & Limits** | Org rules, budgets and sequence limits that hold across parallel agents and sub-agents |
| **Agent Firewall** | A gateway for MCP and API calls plus a containment sandbox, with per-route proof that there is no way around it |
| **Credential Custody** | Agents never hold your keys; credentials are used only for authorized actions |
| **Detect & Respond** | Spot misuse, see the blast radius, stop a run, an agent or the whole org in under a second |
| **Proof** | Signed decision, execution and effect receipts you can verify offline, plus a red-team range for your own policies |

Details: [docs/PRODUCT.md](docs/PRODUCT.md).

## Integrations

Planned (not yet released), coding agents first: Claude Code and the Claude Agent SDK, MCP clients, GitHub, and Go, Python and TypeScript SDKs. See the milestones in [docs/BUILD_GUIDE.md](docs/BUILD_GUIDE.md).

## Development

```bash
task setup    # git hooks + pinned tools
task check    # format, headers, lint, tests, workflow lint, secret scan
```

You need Go and Docker. Task is optional: every tool, Task included, is pinned under `tools/pins/`, so without a global Task run `go tool -modfile=tools/pins/task/go.mod task <name>`. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Report vulnerabilities privately: [Security advisories](https://github.com/katocxl/pantherclaw/security/advisories/new). See [SECURITY.md](SECURITY.md).

## License

- Core (server, gateway, CLI, simulators): **Business Source License 1.1** — free for development, testing and evaluation, and for production use governing up to **5 agents in one organization**; not for hosted/competing offerings. Each version converts to Apache-2.0 four years after release. See [LICENSE](LICENSE) and [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md).
- SDKs, protocol specification and Claude Code integration: **Apache-2.0** (see [NOTICE](NOTICE)).
- PantherClaw™ is a trademark of Joshua Kato — see [TRADEMARKS.md](TRADEMARKS.md).
