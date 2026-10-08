# PantherClaw Python SDK (Apache-2.0)

**Status:** planned for milestone **M8** (see [docs/BUILD_GUIDE.md](../../docs/BUILD_GUIDE.md)).

Will provide: PAP/1 workload identity (enrollment, Ed25519 key in the OS key store, DPoP-style proofs), `authorize` / `execute` / `wait` APIs (sync + async), HOLD wait handles, and wrappers for LangChain/LangGraph, the OpenAI Agents SDK and CrewAI (Python 3.13). Managed with `uv` (`uv.lock` with hashes, `exclude-newer = "7 days"`), linted with ruff, type-checked with `mypy --strict`, tested with pytest, published to PyPI via trusted publishing with attestations.
