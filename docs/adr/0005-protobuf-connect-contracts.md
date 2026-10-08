# ADR-0005 — Protobuf + buf + connect-go v2 as the single contract

**Status:** Accepted (2026-10-08)

**Decision.** All APIs are defined in `proto/pantherclaw/v1`. `buf lint` and `buf breaking` gate PRs. connect-go **v2** (`connectrpc.com/connect/v2`, released 2026-10-07) serves gRPC, gRPC-Web and Connect JSON from one handler. protovalidate rules enforce input constraints at the edge (domain validation still runs). OpenAPI is generated for documentation and Schemathesis. SDKs use Connect JSON over plain HTTP POST.

**Consequences.** One source of truth for server, gateway, SDKs and the future UI; breaking-change detection is automatic. connect-go v2 is new: it is pinned, its changelog is tracked, and interceptors live behind `internal/platform/rpc` (authn-go is not v2-ready; we write our own authentication interceptor).

**Alternatives.** OpenAPI-first REST (two contract systems alongside the gateway's internal RPC); gRPC only (poor ergonomics for Python/TypeScript agents).
