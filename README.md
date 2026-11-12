# mcp-opcua

**A safe-by-default MCP server that lets AI agents read industrial OPC UA systems, and write only through explicit, bounded, audited controls.**

> 🚧 Under active development. See the [first-version spec](docs/SPEC.md).

## Why
AI agents are getting connected to the plant floor. A raw OPC UA bridge lets one hallucinated write stop a production line. mcp-opcua gives agents full visibility and only gated control:

- 🔒 **Writes off by default**: allowlist, per-tag constraints, two-phase confirmation, optional human approval, read-back verification, kill switch
- 🧾 **Full audit trail**: hash-chained JSONL of every call
- 🏭 **Try it in 60 seconds**: `docker compose up` starts a simulated bottling line

## License
Dual-licensed under [AGPL-3.0](LICENSE) or a [commercial license](COMMERCIAL.md) from USTechService Corporation.
Contributions require agreeing to the [CLA](CLA.md).
