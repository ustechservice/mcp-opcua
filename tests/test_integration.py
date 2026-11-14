# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Copyright (c) 2026 USTechService Corporation
"""End to end against the bundled simulator (in-process, random port)."""

from __future__ import annotations

import socket
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from mcp_opcua.audit import AuditLog, verify
from mcp_opcua.config import Config
from mcp_opcua.opcua_client import OpcUaClient
from mcp_opcua.policy import WritePolicy
from mcp_opcua.server import Service, build_server
from mcp_opcua.sim import build

pytestmark = pytest.mark.integration


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture
async def endpoint() -> AsyncIterator[str]:
    url = f"opc.tcp://127.0.0.1:{_free_port()}/bottling/"
    line = await build(url)
    async with line.server:
        yield url


async def _svc(endpoint: str, tmp_path: Path, writes: dict[str, Any] | None = None) -> Service:
    cfg = Config.model_validate(
        {
            "connection": {"endpoint": endpoint, "security_mode": "None", "allow_insecure": True},
            "writes": {
                "approvals_dir": str(tmp_path / "ap"),
                "kill_switch_file": str(tmp_path / "K"),
                **(writes or {}),
            },
            "audit": {"path": str(tmp_path / "audit.jsonl")},
        }
    )
    ua = OpcUaClient(cfg.connection, cfg.subscriptions)
    await ua.connect()
    return Service(cfg, ua, AuditLog(cfg.audit.path), WritePolicy(cfg.writes))


SPEED = "ns=2;s=ConveyorSpeed"
WRITES = {
    "enabled": True,
    "tags": [{"pattern": SPEED, "type": "float", "min": 0, "max": 2.5, "max_rate_of_change": 0.5}],
}


async def test_read_tools(endpoint: str, tmp_path: Path) -> None:
    svc = await _svc(endpoint, tmp_path)
    try:
        objs = await svc.browse("i=85", 2)
        names = {n["browse_name"] for n in objs["nodes"]}
        assert "2:BottlingLine" in names and "2:FillLevel" in names

        r = await svc.read(["ns=2;s=FillLevel", "ns=2;s=LineState", "ns=2;s=RejectCount"])
        fill, state, rejects = r["values"]
        assert rejects["engineering_units"] is None  # tag without EU property must not crash
        assert fill["status"] == "Good" and fill["engineering_units"] == "mL"
        assert fill["server_timestamp"] and state["value"] == "Running"

        d = await svc.describe_node("ns=2;s=FillLevel")
        assert d["eu_range"] == {"low": 480.0, "high": 520.0}
        assert d["data_type"] == "Double" and "fill volume" in d["description"]

        bad = await svc.read(["ns=2;s=DoesNotExist"])
        assert bad["status"] == "error" or bad["values"][0]["status"] != "Good"
    finally:
        await svc.ua.close()
    assert verify(tmp_path / "audit.jsonl")[0]


async def test_subscription(endpoint: str, tmp_path: Path) -> None:
    svc = await _svc(endpoint, tmp_path)
    try:
        sid = (await svc.subscribe(["ns=2;s=ConveyorSpeed"], 100))["subscription_id"]
        await svc.ua.client.get_node(SPEED).write_value(1.5)  # simulate the plant moving
        import asyncio

        for _ in range(30):
            got = await svc.poll_subscription(sid, 10)
            if any(i["value"] == 1.5 for i in got["items"]):
                break
            await asyncio.sleep(0.1)
        else:
            pytest.fail("no data change received")
        assert (await svc.unsubscribe(sid))["status"] == "ok"
        assert (await svc.poll_subscription(sid, 10))["status"] == "error"
    finally:
        await svc.ua.close()


async def test_write_disabled_by_default(endpoint: str, tmp_path: Path) -> None:
    svc = await _svc(endpoint, tmp_path)
    try:
        r = await svc.write(SPEED, 1.3, None)
        assert r == {"status": "rejected", "code": "writes_disabled", "error": r["error"]}
        assert await svc.ua.read_value(SPEED) == 1.2
    finally:
        await svc.ua.close()


async def test_two_phase_write_with_readback(endpoint: str, tmp_path: Path) -> None:
    svc = await _svc(endpoint, tmp_path, WRITES)
    try:
        plan = await svc.write(SPEED, 1.5, None)
        assert plan["status"] == "planned" and plan["current"] == 1.2
        assert await svc.ua.read_value(SPEED) == 1.2  # plan did not write

        done = await svc.write(None, None, plan["confirmation_token"])
        assert done["status"] == "written" and done["before"] == 1.2 and done["after"] == 1.5

        again = await svc.write(None, None, plan["confirmation_token"])
        assert again["code"] == "bad_token"

        for node, value, want in [
            ("ns=2;s=FillTarget", 500.0, "not_allowlisted"),
            (SPEED, 2.4, "rate_of_change"),
            (SPEED, 9.0, "above_max"),
        ]:
            assert (await svc.write(node, value, None))["code"] == want
    finally:
        await svc.ua.close()
    recs = (tmp_path / "audit.jsonl").read_text().splitlines()
    assert any('"before":1.2' in r and '"after":1.5' in r for r in recs)
    assert verify(tmp_path / "audit.jsonl")[0]


async def test_confirm_revalidates_against_fresh_value(endpoint: str, tmp_path: Path) -> None:
    svc = await _svc(endpoint, tmp_path, WRITES)
    try:
        plan = await svc.write(SPEED, 1.6, None)  # step 0.4 from 1.2: ok
        await svc.ua.client.get_node(SPEED).write_value(0.5)  # plant moved; step now 1.1
        r = await svc.write(None, None, plan["confirmation_token"])
        assert r["code"] == "rate_of_change"
        assert await svc.ua.read_value(SPEED) == 0.5
    finally:
        await svc.ua.close()


async def test_kill_switch_blocks_confirm(endpoint: str, tmp_path: Path) -> None:
    svc = await _svc(endpoint, tmp_path, WRITES)
    try:
        plan = await svc.write(SPEED, 1.3, None)
        (tmp_path / "K").touch()
        r = await svc.write(None, None, plan["confirmation_token"])
        assert r["code"] == "kill_switch" and await svc.ua.read_value(SPEED) == 1.2
    finally:
        await svc.ua.close()


async def test_mcp_tools_registered(endpoint: str, tmp_path: Path) -> None:
    svc = await _svc(endpoint, tmp_path)
    try:
        names = {t.name for t in await build_server(svc).list_tools()}
        assert names == {
            "browse",
            "read",
            "describe_node",
            "subscribe",
            "poll_subscription",
            "unsubscribe",
            "write",
        }
    finally:
        await svc.ua.close()
