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

- Allowlist: `pattern` is an exact, canonical NodeId (`ns=2;s=X`, not `ns=02;s=X`). Set `glob: true`
  on a rule to use fnmatch wildcards. A node matching two rules is rejected. Steps (`max_rate_of_change`)
  need `min_interval_s >= 1`.
- Human approval: `writes.require_human: true`. The operator runs `mcp-opcua approve --config ...` to list
  pending writes, then `mcp-opcua approve <id> --config ...` in a terminal to review and approve one. The
  approval is bound to that exact node and value; the agent never sees the approval id.
  **Limit:** approvals are not signed. Anyone who can write to `approvals_dir` can approve, so this
  is not a boundary against an agent that has a shell on the host. It protects against an agent that
  only reaches the server through MCP. Signed approvals are planned.
- Relative paths in the config (`kill_switch_file`, `approvals_dir`, `audit.path`, certs) resolve
  against the config file's directory (`~` is expanded). `kill_switch_file` is required when writes are
  enabled, and the server logs its resolved path at startup. Stepped tags need `min_interval_s >= 1`.
- HTTP: streamable HTTP has no auth in v0.1. DNS-rebinding protection is always on (add Host values
  with `--allowed-host`), and the server refuses to serve writes on a non-loopback address.
- Kill switch: create the `kill_switch_file` or set `MCP_OPCUA_KILL=1`. Takes effect on the next call, no restart.
- Audit: every call goes to hash-chained JSONL; check it with `mcp-opcua audit verify audit.jsonl`.

> Only point this at production equipment with a reviewed allowlist, `require_human: true`, and
> `SignAndEncrypt`. The examples target the bundled simulator only.

## License
Dual-licensed under [AGPL-3.0](LICENSE) or a [commercial license](COMMERCIAL.md) from USTechService Corporation.
Contributions require agreeing to the [CLA](CLA.md).
