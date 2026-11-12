# mcp-opcua: First Version Spec

## Problem
LLM agents are being connected to industrial systems with no safety layer. Existing OPC UA bridges expose raw read/write access. One hallucinated write to a PLC tag can stop a line, damage equipment, or hurt someone.

## Goal
An MCP server that lets AI agents **observe** OPC UA systems freely and **act** only through explicit, auditable, bounded controls. It should be safe enough that an OT engineer would let it near a plant network.

## Non-goals (first version)
- Historian, alarms & conditions, methods/calls, PubSub
- Multi-server federation
- A GUI

## Users
- **OT and controls engineers** exploring AI-assisted troubleshooting
- **IT/OT architects** evaluating agent access to the plant floor
- **Researchers and students** who need a realistic, safe sandbox

## Tools exposed over MCP
| Tool | Mode | Description |
|---|---|---|
| `browse` | read | Browse the address space from a node; depth-limited; returns NodeId, BrowseName, NodeClass, DataType |
| `read` | read | Read one or more node values with status code, source and server timestamps, and engineering units |
| `read_history` | stretch | Not in the first version |
| `subscribe` / `poll_subscription` | read | Monitored items with sampling interval; bounded buffer |
| `describe_node` | read | Attributes plus EU range and description, so the agent understands the tag before using it |
| `write` | **gated** | Disabled by default. See Write safety |

## Write safety (core differentiator)
1. **Off by default.** `writes.enabled: false`.
2. **Allowlist.** Only NodeIds or glob patterns listed in config can be written. Everything else is rejected before any network I/O.
3. **Constraints per tag:** type, min/max, allowed enum values, max rate of change, and a minimum interval between writes.
4. **Two-phase commit.** `write` returns a dry-run plan (current value → proposed value, constraint checks) and a `confirmation_token` valid for N seconds. Only `write(confirm=token)` executes it.
5. **Human-in-the-loop option.** `writes.require_human: true` means confirmation must come from an out-of-band approver (CLI prompt or webhook), not from the agent.
6. **Read-back verification.** After a write, read the value back and report a mismatch.
7. **Kill switch.** A file or env flag disables all writes immediately without a restart.

## Audit
- Every tool call is appended to JSONL: timestamp, client, tool, args, result status, latency.
- Writes also log before and after values and who confirmed.
- Optional hash chain (each record holds the previous record's SHA-256) so tampering is detectable.

## Security
- OPC UA security modes: None (sim only, with a warning), Sign, SignAndEncrypt; policy Basic256Sha256 or newer.
- Auth: anonymous (sim only), username/password from env, X.509 client certificate.
- No secrets in config files; env or file references only.
- Server certificate trust store; reject unknown certificates by default.
- Config validated with Pydantic at startup; fail closed.

## Architecture
```
MCP client (Claude, etc.)
   │ stdio / streamable HTTP
mcp_opcua.server (FastMCP)
   ├── policy/      allowlist, constraints, tokens, kill switch
   ├── audit/       JSONL writer and hash chain
   ├── opcua/       async client wrapper (asyncua), connection pool, reconnect
   └── config/      Pydantic models, YAML loader
```

## Demo / simulator
- `docker compose up` starts an asyncua simulation of a **bottling line** (conveyor speed, fill level, temperature, reject count, line state) plus the MCP server in read-only mode.
- `examples/claude_desktop_config.json` and a GIF of an agent diagnosing a "fill level drift" scenario.

## Stack
Python 3.11+, `asyncua`, official MCP Python SDK, Pydantic v2, uv, ruff, mypy (strict), pytest + pytest-asyncio, mkdocs-material.

## Done for the first version
- [ ] All read tools working against the simulator, with integration tests in CI (simulator in a service container)
- [ ] Write path: allowlist, constraints, two-phase confirm, read-back, kill switch; unit tests per rule, plus property tests for range checks
- [ ] Audit JSONL with hash chain and a verify command (`mcp-opcua audit verify`)
- [ ] `docker compose up` demo works on a clean machine in under 2 minutes
- [ ] README with GIF, threat model (`docs/THREAT_MODEL.md`), docs site
- [ ] Release v0.1.0 on PyPI via trusted publishing
- [ ] commitguard and CI green

## Later
Modbus/S7 adapters via a shared `mcp-ot-core`; unit conversion; IEC 62443 security-level mapping; Grafana dashboard of agent activity; signed audit exports.
