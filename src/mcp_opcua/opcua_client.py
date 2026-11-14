# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Copyright (c) 2026 USTechService Corporation
"""Thin async wrapper over asyncua. Knows nothing about policy; server.py enforces it first."""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from asyncua import ua
from asyncua.client.client import Client
from asyncua.common.node import Node
from asyncua.ua.uaerrors import UaError

from mcp_opcua.config import ConnectionConfig, SecurityMode, SubscriptionConfig

log = logging.getLogger(__name__)


def _jsonable(v: Any) -> Any:
    if isinstance(v, bool | int | float | str) or v is None:
        return v
    if isinstance(v, list | tuple):
        return [_jsonable(x) for x in v]
    return str(v)


def _dv(node_id: str, dv: ua.DataValue) -> dict[str, Any]:
    return {
        "node_id": node_id,
        "value": _jsonable(dv.Value.Value if dv.Value is not None else None),
        "status": dv.StatusCode.name if dv.StatusCode else "Good",
        "source_timestamp": dv.SourceTimestamp.isoformat() if dv.SourceTimestamp else None,
        "server_timestamp": dv.ServerTimestamp.isoformat() if dv.ServerTimestamp else None,
    }


@dataclass
class _Sub:
    handler: _BufferHandler
    sub: Any
    node_ids: list[str]


@dataclass
class _BufferHandler:
    buf: deque[dict[str, Any]]
    dropped: int = 0

    def datachange_notification(self, node: Node, val: Any, data: Any) -> None:
        if len(self.buf) == self.buf.maxlen:
            self.dropped += 1
        dv = data.monitored_item.Value
        self.buf.append(_dv(node.nodeid.to_string(), dv))


@dataclass
class OpcUaClient:
    cfg: ConnectionConfig
    sub_cfg: SubscriptionConfig
    _client: Client | None = None
    _subs: dict[int, _Sub] = field(default_factory=dict)
    _next_sub: int = 1

    async def connect(self) -> None:
        c = Client(self.cfg.endpoint, timeout=self.cfg.timeout_s, auto_reconnect=True)
        if self.cfg.security_mode is SecurityMode.NONE:
            log.warning("security_mode=None: traffic is unauthenticated and unencrypted (sim only)")
        else:
            a = self.cfg.auth
            cert = str(a.client_cert_file) if a.client_cert_file else None
            key = str(a.client_key_file) if a.client_key_file else None
            if not (cert and key):
                raise ValueError("Sign/SignAndEncrypt requires a client certificate and key")
            await c.set_security_string(
                f"{self.cfg.security_policy},{self.cfg.security_mode.value},{cert},{key},"
                f"{self.cfg.server_cert_file}"
            )
        if self.cfg.auth.kind == "username":
            user, pw = self.cfg.auth.credentials()
            c.set_user(user)
            c.set_password(pw)
        await c.connect()
        self._client = c

    async def close(self) -> None:
        if self._client:
            await self._client.disconnect()
            self._client = None

    @property
    def client(self) -> Client:
        if self._client is None:
            raise RuntimeError("not connected")
        return self._client

    def node(self, node_id: str) -> Node:
        try:
            return self.client.get_node(node_id)
        except Exception as e:  # asyncua raises several types for bad NodeId strings
            raise ValueError(f"invalid NodeId {node_id!r}: {e}") from e

    # -- reads -----------------------------------------------------------------
    async def browse(self, node_id: str, depth: int, max_nodes: int) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        frontier: list[tuple[Node, int]] = [(self.node(node_id), 0)]
        while frontier and len(out) < max_nodes:
            n, d = frontier.pop(0)
            for child in await n.get_children():
                if len(out) >= max_nodes:
                    break
                nc = await child.read_node_class()
                entry: dict[str, Any] = {
                    "node_id": child.nodeid.to_string(),
                    "browse_name": (await child.read_browse_name()).to_string(),
                    "node_class": nc.name,
                    "depth": d + 1,
                }
                if nc == ua.NodeClass.Variable:
                    entry["data_type"] = (await child.read_data_type_as_variant_type()).name
                out.append(entry)
                if d + 1 < depth:
                    frontier.append((child, d + 1))
        return out

    async def read(self, node_ids: list[str]) -> list[dict[str, Any]]:
        results = []
        for nid in node_ids:
            dv = await self.node(nid).read_data_value()
            r = _dv(nid, dv)
            r["engineering_units"] = await self._eu(self.node(nid))
            results.append(r)
        return results

    async def read_value(self, node_id: str) -> Any:
        return _jsonable(await self.node(node_id).read_value())

    async def _prop(self, n: Node, name: str) -> Any:
        try:
            return await (await n.get_child(f"0:{name}")).read_value()
        except UaError:
            return None

    async def _eu(self, n: Node) -> str | None:
        eu = await self._prop(n, "EngineeringUnits")
        return eu.DisplayName.Text if eu is not None else None

    async def describe(self, node_id: str) -> dict[str, Any]:
        n = self.node(node_id)
        nc = await n.read_node_class()
        desc = await n.read_description()
        out: dict[str, Any] = {
            "node_id": node_id,
            "browse_name": (await n.read_browse_name()).to_string(),
            "display_name": (await n.read_display_name()).Text,
            "description": desc.Text if desc else None,
            "node_class": nc.name,
        }
        if nc == ua.NodeClass.Variable:
            out["data_type"] = (await n.read_data_type_as_variant_type()).name
            out["engineering_units"] = await self._eu(n)
            rng = await self._prop(n, "EURange")
            out["eu_range"] = {"low": rng.Low, "high": rng.High} if rng is not None else None
            out["access_level"] = sorted(a.name for a in await n.get_access_level())
        return out

    # -- writes (only called by server.py after policy passes) ----------------
    async def write(self, node_id: str, value: Any) -> None:
        n = self.node(node_id)
        vtype = await n.read_data_type_as_variant_type()
        await n.write_value(ua.DataValue(ua.Variant(value, vtype)))

    # -- subscriptions ---------------------------------------------------------
    async def subscribe(self, node_ids: list[str], sampling_ms: int) -> int:
        if len(self._subs) >= self.sub_cfg.max_subscriptions:
            raise ValueError(f"subscription limit ({self.sub_cfg.max_subscriptions}) reached")
        sampling_ms = max(sampling_ms, self.sub_cfg.min_sampling_ms)
        handler = _BufferHandler(deque(maxlen=self.sub_cfg.max_buffer))
        sub = await self.client.create_subscription(sampling_ms, handler)
        await sub.subscribe_data_change([self.node(n) for n in node_ids])
        sid = self._next_sub
        self._next_sub += 1
        self._subs[sid] = _Sub(handler, sub, node_ids)
        return sid

    def poll(self, sub_id: int, max_items: int) -> dict[str, Any]:
        s = self._subs.get(sub_id)
        if s is None:
            raise ValueError(f"unknown subscription {sub_id}")
        items: list[dict[str, Any]] = []
        while s.handler.buf and len(items) < max_items:
            items.append(s.handler.buf.popleft())
        dropped, s.handler.dropped = s.handler.dropped, 0
        return {"items": items, "dropped": dropped, "remaining": len(s.handler.buf)}

    async def unsubscribe(self, sub_id: int) -> None:
        s = self._subs.pop(sub_id, None)
        if s is None:
            raise ValueError(f"unknown subscription {sub_id}")
        await asyncio.shield(s.sub.delete())
