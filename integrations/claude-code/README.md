# PantherClaw for Claude Code & the Claude Agent SDK (Apache-2.0)

**Status:** planned for milestone **M6** (hook) and **M8** (Agent SDK), see [docs/BUILD_GUIDE.md](../../docs/BUILD_GUIDE.md).

- **Claude Code plugin:** a `PreToolUse` hook that sends each tool call (Bash **and** PowerShell, file edits, MCP tools, web fetches) to the PantherClaw gateway for a decision, with Windows path normalization (case, 8.3 short names, `\\?\` prefixes, alternate data streams, `/c/` vs `C:\`).
- **Claude Agent SDK:** a `canUseTool` callback with the same semantics.
- **Honest coverage:** hooks are cooperative — PantherClaw labels these routes **PARTIAL** unless the credentials the agent would use are held by PantherClaw (credential custody) or the agent runs in the containment sandbox.
