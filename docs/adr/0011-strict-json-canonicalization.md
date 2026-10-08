# ADR-0011 — encoding/json/v2 + RFC 8785 for ActionIR

**Status:** Accepted (2026-10-08)

**Decision.** Core packages use `encoding/json/v2` and `encoding/json/jsontext` (GA in Go 1.27); v1 `encoding/json` is banned there by depguard (v1 semantics accept duplicate keys). The ActionIR canonical form uses `jsontext.Value.Canonicalize()` (RFC 8785). Material numbers are decimal strings (JCS numbers are IEEE-754 doubles). Unknown fields are rejected; depth and size limits are enforced.

**Consequences.** Parser-differential attacks are closed on our side; outbound requests are re-serialized from ActionIR, so targets see exactly what was authorized.
