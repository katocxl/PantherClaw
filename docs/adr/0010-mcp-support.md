# ADR-0010 — MCP support for spec 2026-07-28 and 2025-11-25

**Status:** Accepted (2026-10-08)

**Decision.** The gateway uses the official MCP Go SDK (v1.8+) and supports **2026-07-28** (stateless Streamable HTTP, `server/discover`, required `Mcp-Method`/`Mcp-Name` headers, tasks as the `io.modelcontextprotocol/tasks` extension) and **2025-11-25** (stateful sessions) for existing clients. Hardening: header/body consistency, batch rejection, sessions bound to the workload key, reviewed tool descriptions only, elicitation/sampling gated, private caching. The tasks extension (for HOLD and long-running approvals) is implemented by PantherClaw where the SDK lacks it. Off-the-shelf stdio clients use `pclaw mcp proxy`.

**Consequences.** Broad client compatibility; a small amount of extension code owned by us; spec churn tracked per release.
