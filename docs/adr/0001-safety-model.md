# ADR 0001: Safety model for writes

**Status:** Accepted

## Context
Agents can be prompt-injected or can hallucinate. Any write path reachable by the model alone is a safety and security hazard in OT.

## Decision
Writes are disabled by default and gated by four layers: an allowlist, per-tag constraints, a two-phase confirmation token (with an optional human approver), and read-back verification. A kill switch overrides everything. Policy is evaluated **before** any OPC UA network call.

## Consequences
- Agent write workflows are slower (two calls), which is intended.
- Operators have to curate an allowlist; the docs ship example policies.
- The safety layer is testable in isolation with no OPC UA server.
