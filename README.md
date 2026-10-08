# PantherClaw

**Runtime authorization for AI agents.**

PantherClaw sits between AI agents and the systems they act on, so that every consequential action an agent takes is authorized, controlled and accounted for.

> **Status: pre-alpha.** Under active development; not ready for production use.

## Integrations

Planned (not yet released): MCP clients, Claude Code, and Python, TypeScript and Go SDKs. See the milestones in [docs/BUILD_GUIDE.md](docs/BUILD_GUIDE.md).

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
