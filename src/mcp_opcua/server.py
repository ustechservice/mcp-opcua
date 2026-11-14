# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Copyright (c) 2026 USTechService Corporation
"""MCP tool surface. Reads go straight to OPC UA; writes go through WritePolicy first."""

from __future__ import annotations

import math
import time
from collections.abc import Awaitable, Callable
from typing import Any

from mcp.server.mcpserver import MCPServer

from mcp_opcua.audit import AuditLog
from mcp_opcua.config import Config
from mcp_opcua.opcua_client import OpcUaClient
from mcp_opcua.policy import PolicyError, WritePolicy

MAX_READ_NODES = 100
MAX_POLL_ITEMS = 1000


def _values_match(a: Any, b: Any) -> bool:
    if isinstance(a, float) or isinstance(b, float):
        try:
            return math.isclose(float(a), float(b), rel_tol=1e-6, abs_tol=1e-9)
        except (TypeError, ValueError):
            return False
    return bool(a == b)


class Service:
    """Tool implementations, separate from MCP wiring so they are testable directly."""

    def __init__(self, cfg: Config, ua: OpcUaClient, audit: AuditLog, policy: WritePolicy) -> None:
        self.cfg, self.ua, self.audit, self.policy = cfg, ua, audit, policy

    async def _audited(
        self, tool: str, args: dict[str, Any], fn: Callable[[], Awaitable[dict[str, Any]]]
    ) -> dict[str, Any]:
        t0 = time.perf_counter()
        try:
            result = await fn()
            status = result.get("status", "ok")
            extra = {k: result[k] for k in ("before", "after", "confirmed_by") if k in result}
            return result
        except PolicyError as e:
            status, extra = f"rejected:{e.code}", {}
            return {"status": "rejected", "code": e.code, "error": str(e)}
        except (ValueError, RuntimeError) as e:
            status, extra = "error", {}
            return {"status": "error", "error": str(e)}
        finally:
            self.audit.append(
                client="mcp",
                tool=tool,
                args=args,
                status=status,
                latency_ms=round((time.perf_counter() - t0) * 1000, 2),
                **extra,
            )

    async def browse(self, node_id: str, depth: int) -> dict[str, Any]:
        async def run() -> dict[str, Any]:
            d = min(max(depth, 1), self.cfg.browse_max_depth)
            nodes = await self.ua.browse(node_id, d, self.cfg.browse_max_nodes)
            return {
                "nodes": nodes,
                "truncated": len(nodes) >= self.cfg.browse_max_nodes,
                "depth": d,
            }

        return await self._audited("browse", {"node_id": node_id, "depth": depth}, run)

    async def read(self, node_ids: list[str]) -> dict[str, Any]:
        async def run() -> dict[str, Any]:
            if not node_ids or len(node_ids) > MAX_READ_NODES:
                raise ValueError(f"node_ids must contain 1..{MAX_READ_NODES} items")
            return {"values": await self.ua.read(node_ids)}

        return await self._audited("read", {"node_ids": node_ids}, run)

    async def describe_node(self, node_id: str) -> dict[str, Any]:
        async def run() -> dict[str, Any]:
            return await self.ua.describe(node_id)

        return await self._audited("describe_node", {"node_id": node_id}, run)

    async def subscribe(self, node_ids: list[str], sampling_ms: int) -> dict[str, Any]:
        async def run() -> dict[str, Any]:
            if not node_ids or len(node_ids) > MAX_READ_NODES:
                raise ValueError(f"node_ids must contain 1..{MAX_READ_NODES} items")
            return {"subscription_id": await self.ua.subscribe(node_ids, sampling_ms)}

        return await self._audited(
            "subscribe", {"node_ids": node_ids, "sampling_ms": sampling_ms}, run
        )

    async def poll_subscription(self, subscription_id: int, max_items: int) -> dict[str, Any]:
        async def run() -> dict[str, Any]:
            return self.ua.poll(subscription_id, min(max(max_items, 1), MAX_POLL_ITEMS))

        return await self._audited("poll_subscription", {"subscription_id": subscription_id}, run)

    async def unsubscribe(self, subscription_id: int) -> dict[str, Any]:
        async def run() -> dict[str, Any]:
            await self.ua.unsubscribe(subscription_id)
            return {"status": "ok"}

        return await self._audited("unsubscribe", {"subscription_id": subscription_id}, run)

    async def write(self, node_id: str | None, value: Any, confirm: str | None) -> dict[str, Any]:
        args = {"node_id": node_id, "value": value, "confirm": bool(confirm)}
        if confirm:
            return await self._audited("write", args, lambda: self._execute(confirm))
        return await self._audited("write", args, lambda: self._plan(node_id, value))

    async def _plan(self, node_id: str | None, value: Any) -> dict[str, Any]:
        if not node_id:
            raise ValueError("node_id is required to plan a write")
        # Cheap gates first so a disabled/unlisted tag never touches the network.
        self.policy.gate()
        self.policy.rule_for(node_id)
        current = await self.ua.read_value(node_id)
        p = self.policy.plan(node_id, value, current)
        return {
            "status": "planned",
            "node_id": p.node_id,
            "current": p.current,
            "proposed": p.proposed,
            "checks_passed": list(p.checks),
            "confirmation_token": p.token,
            "expires_in_s": self.cfg.writes.token_ttl_s,
            "requires_human": self.cfg.writes.require_human,
            "next": "call write(confirm=<token>)"
            + (
                " after a human runs `mcp-opcua approve <token>`"
                if self.cfg.writes.require_human
                else ""
            ),
        }

    async def _execute(self, token: str) -> dict[str, Any]:
        p = self.policy.redeem(token)
        # Re-validate against a fresh read: the plant may have moved since the plan.
        before = await self.ua.read_value(p.node_id)
        self.policy.check(p.node_id, p.proposed, before)
        await self.ua.write(p.node_id, p.proposed)
        self.policy.record_write(p.node_id)
        after = await self.ua.read_value(p.node_id)
        ok = _values_match(after, p.proposed)
        return {
            "status": "written" if ok else "readback_mismatch",
            "node_id": p.node_id,
            "before": before,
            "after": after,
            "requested": p.proposed,
            "confirmed_by": "human" if self.cfg.writes.require_human else "agent",
        }


def build_server(svc: Service) -> MCPServer:
    mcp = MCPServer(
        name="mcp-opcua",
        instructions=(
            "Read-only by default. Use describe_node before acting on a tag. "
            "Writes are two-phase: write(node_id, value) returns a plan and a token; "
            "write(confirm=token) executes it. Rejections include a machine-readable code."
        ),
    )

    @mcp.tool(description="Browse the address space from a node (default: Objects folder).")
    async def browse(node_id: str = "i=85", depth: int = 1) -> dict[str, Any]:
        return await svc.browse(node_id, depth)

    @mcp.tool(description="Read values with status, timestamps and engineering units.")
    async def read(node_ids: list[str]) -> dict[str, Any]:
        return await svc.read(node_ids)

    @mcp.tool(description="Attributes, EU range, units and description of one node.")
    async def describe_node(node_id: str) -> dict[str, Any]:
        return await svc.describe_node(node_id)

    @mcp.tool(description="Create a monitored-item subscription. Returns subscription_id.")
    async def subscribe(node_ids: list[str], sampling_ms: int = 1000) -> dict[str, Any]:
        return await svc.subscribe(node_ids, sampling_ms)

    @mcp.tool(description="Drain buffered changes from a subscription.")
    async def poll_subscription(subscription_id: int, max_items: int = 100) -> dict[str, Any]:
        return await svc.poll_subscription(subscription_id, max_items)

    @mcp.tool(description="Delete a subscription.")
    async def unsubscribe(subscription_id: int) -> dict[str, Any]:
        return await svc.unsubscribe(subscription_id)

    @mcp.tool(
        description=(
            "GATED. Phase 1: write(node_id, value) returns a dry-run plan and confirmation_token. "
            "Phase 2: write(confirm=token) executes. Disabled unless the operator enabled it."
        )
    )
    async def write(
        node_id: str | None = None,
        value: bool | int | float | str | None = None,
        confirm: str | None = None,
    ) -> dict[str, Any]:
        return await svc.write(node_id, value, confirm)

    return mcp
