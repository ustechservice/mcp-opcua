# mcp-opcua: agent instructions

Read `docs/SPEC.md` and `docs/adr/` before changing behavior. The spec is the source of truth; propose an ADR before deviating.

## Rules
- **Safety first:** the policy layer runs before any OPC UA I/O. Never add a code path that writes without passing through `policy/`.
- Writes stay disabled by default. Tests must cover every rejection path.
- Python 3.11+, async throughout, type hints everywhere (mypy strict).
- Tooling: `uv` for environments, `ruff` for lint and format, `pytest` for tests.
- Every source file carries the SPDX header (`python scripts/commitguard.py --fix-headers`).
- Never commit secrets, certificates, captures from real plants, or customer data.
- Examples and tests run against the bundled simulator only; never document connecting to production equipment with writes enabled.

## Commands
```bash
uv sync
uv run ruff check . && uv run ruff format --check .
uv run mypy src
uv run pytest
python scripts/commitguard.py --all
docker compose up        # simulator + server
```

## Commits
Small, focused commits with imperative messages. One feature per PR.
