# Threat model

Scope: mcp-opcua v0.1, tested against the bundled simulator only. It has not been run against real
equipment. This page says what the server is designed to stop, and what it does not stop.

## What we protect

1. **The process.** No write reaches the OPC UA server unless an operator allowed that tag and value range in advance.
2. **The record.** What the agent asked for and what was written can be reconstructed afterwards.
3. **Credentials.** OPC UA passwords and keys stay out of config files and out of the model's context.

## Who we assume the attacker is

| Actor | Can do | In scope |
|---|---|---|
| The model itself (hallucination) | Call any MCP tool with any arguments | Yes |
| Prompt injection (text in tag names, descriptions, documents the agent reads) | Steer the model into calling tools | Yes |
| A web page in the operator's browser | Send HTTP requests to `127.0.0.1` | Yes (DNS rebinding) |
| A network attacker between the server and the PLC | Read or alter OPC UA traffic | Yes, when `SignAndEncrypt` is used |
| An agent or user with a shell on the host | Read and write local files | **No** (see limits) |
| Someone with access to the PLC or the OPC UA server | Anything | No |

## Controls

| Threat | Control |
|---|---|
| Hallucinated or injected write to any tag | Writes are off by default. When on, only allowlisted NodeIds are writable. Checked before any OPC UA I/O. |
| Write of a dangerous value to an allowed tag | Per-tag type, min/max, allowed values, max step and min interval. Re-checked against a fresh read at confirm time. |
| Model confirms its own bad plan | Two-phase write with a token that expires (30 s by default). With `require_human: true` the approval happens in a terminal, is bound to the exact node and value, and the agent never sees the approval id. |
| Write silently fails or is overridden by the PLC | Read-back after every write; a mismatch is reported. |
| Runaway agent | Kill switch (file or `MCP_OPCUA_KILL=1`), effective on the next call, no restart. |
| Ambiguous allowlist (two rules match, non-canonical NodeId) | Rejected. Config fails closed at startup. |
| Browser-based attack on the HTTP transport | DNS-rebinding protection always on; writes are refused on a non-loopback bind address. |
| Eavesdropping or tampering on the OPC UA link | `SignAndEncrypt` is the default; `None` or anonymous needs `allow_insecure: true`. A server certificate file is required when security is on. |
| Disputed history | Hash-chained JSONL audit of every call; `mcp-opcua audit verify` detects edited, removed or reordered records. |

## Known limits

- **Host access defeats it.** Approvals are not signed and the kill switch is a file. An agent with a
  shell on the same host can approve its own write or remove the kill-switch file. Run the server
  under a different user than any agent that has a shell.
- **The audit chain is unkeyed and local.** It detects edits inside the file. It does not detect
  someone who rewrites the whole file, or who cuts records off the end. Ship the log to a system the
  host cannot rewrite if you need that.
- **HTTP has no authentication in v0.1.** Any local process can call the server. Use stdio, or keep
  HTTP on loopback and read-only.
- **Reads are not restricted.** An agent can browse and read every node the OPC UA account can see.
  Limit that with the OPC UA account's own permissions.
- **Constraints are per tag.** The server does not know that two individually valid writes are unsafe
  together. Interlocks belong in the PLC, not here.
- **Injected text still reaches the model.** Tag names and descriptions are returned as data. The
  write gate limits the damage; it does not stop the model from being misled.
- **Not a safety system.** This is not SIL-rated and must never be the only barrier in front of a
  hazard.

## Before pointing it at real equipment

Reviewed allowlist with tight ranges, `require_human: true`, `SignAndEncrypt` with a pinned server
certificate, a least-privilege OPC UA account, the server on its own OS user, and the audit log
shipped off the host.
