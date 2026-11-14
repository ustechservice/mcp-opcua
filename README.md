# mcp-opcua

**A safe-by-default MCP server that lets AI agents read industrial OPC UA systems, and write only through explicit, bounded, audited controls.**

> 🚧 Under active development. See the [first-version spec](docs/SPEC.md).

## Why
AI agents are getting connected to the plant floor. A raw OPC UA bridge lets one hallucinated write stop a production line. mcp-opcua gives agents full visibility and only gated control:

- 🔒 **Writes off by default**: allowlist, per-tag constraints, two-phase confirmation, optional human approval, read-back verification, kill switch
- 🧾 **Full audit trail**: hash-chained JSONL of every call
- 🏭 **Try it in 60 seconds**: `docker compose up` starts a simulated bottling line

## Quickstart (simulator)
```bash
uv sync
uv run mcp-opcua sim &                                    # bottling line on opc.tcp://localhost:4840
uv run mcp-opcua serve --config examples/config.sim.yaml  # MCP over stdio, read-only
```
Or `docker compose up` for the simulator plus the server over streamable HTTP on `127.0.0.1:8000/mcp`.
For Claude Desktop, see [`examples/claude_desktop_config.json`](examples/claude_desktop_config.json).

### Tools
| Tool | Mode |
|---|---|
| `browse`, `read`, `describe_node`, `subscribe`, `poll_subscription`, `unsubscribe` | read |
| `write` | **gated**: off by default; two-phase (`write(node_id, value)` returns a plan + token, `write(confirm=token)` executes) |

### Writes
Writes stay off unless you set `writes.enabled: true` and list every writable tag. Each write is checked
against the allowlist, type, min/max, allowed values, max step and min interval **before** any OPC UA I/O,
then re-checked against a fresh read at confirm time and verified by read-back afterwards.
See [`examples/config.sim-writes.yaml`](examples/config.sim-writes.yaml) and [ADR 0001](docs/adr/0001-safety-model.md).

- Human approval: `writes.require_human: true`, then `mcp-opcua approve <token> --config ...`
- Kill switch: create the `kill_switch_file` or set `MCP_OPCUA_KILL=1`. Takes effect on the next call, no restart.
- Audit: every call goes to hash-chained JSONL; check it with `mcp-opcua audit verify audit.jsonl`.

> Only point this at production equipment with a reviewed allowlist, `require_human: true`, and
> `SignAndEncrypt`. The examples target the bundled simulator only.

## License
Dual-licensed under [AGPL-3.0](LICENSE) or a [commercial license](COMMERCIAL.md) from USTechService Corporation.
Contributions require agreeing to the [CLA](CLA.md).
