# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Copyright (c) 2026 USTechService Corporation
"""Simulated bottling line (asyncua server). For demos and tests only, never production."""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass
from typing import Any

from asyncua import ua
from asyncua.server.server import Server
from asyncua.ua.attribute_ids import AttributeIds

log = logging.getLogger(__name__)
NS_URI = "urn:mcp-opcua:sim:bottling"


@dataclass
class Line:
    server: Server
    ns: int
    nodes: dict[str, Any]


async def _var(
    parent: Any,
    ns: int,
    name: str,
    value: Any,
    vtype: ua.VariantType,
    unit: str | None,
    rng: tuple[float, float] | None,
    desc: str,
    writable: bool,
) -> Any:
    v = await parent.add_variable(
        ua.NodeId.from_string(f"ns={ns};s={name}"), f"{ns}:{name}", ua.Variant(value, vtype)
    )
    await v.write_attribute(
        AttributeIds.Description, ua.DataValue(ua.Variant(ua.LocalizedText(desc)))
    )
    if unit:
        eu = ua.EUInformation()
        eu.DisplayName = ua.LocalizedText(unit)
        await v.add_property(0, "EngineeringUnits", eu)
    if rng:
        r = ua.Range()
        r.Low, r.High = rng
        await v.add_property(0, "EURange", r)
    if writable:
        await v.set_writable()
    return v


async def build(endpoint: str) -> Line:
    server = Server()
    await server.init()
    server.set_endpoint(endpoint)
    server.set_server_name("mcp-opcua bottling line simulator")
    server.set_security_policy([ua.SecurityPolicyType.NoSecurity])
    ns = await server.register_namespace(NS_URI)
    line = await server.nodes.objects.add_object(
        ua.NodeId.from_string(f"ns={ns};s=BottlingLine"), f"{ns}:BottlingLine"
    )
    F, D, I32, S = (
        ua.VariantType.Float,
        ua.VariantType.Double,
        ua.VariantType.Int32,
        ua.VariantType.String,
    )
    nodes = {
        "ConveyorSpeed": await _var(
            line,
            ns,
            "ConveyorSpeed",
            1.2,
            D,
            "m/s",
            (0.0, 2.5),
            "Main conveyor belt speed setpoint",
            True,
        ),
        "FillLevel": await _var(
            line,
            ns,
            "FillLevel",
            500.0,
            D,
            "mL",
            (480.0, 520.0),
            "Measured fill volume of the last bottle",
            False,
        ),
        "FillTarget": await _var(
            line, ns, "FillTarget", 500.0, D, "mL", (480.0, 520.0), "Filler volume setpoint", True
        ),
        "Temperature": await _var(
            line,
            ns,
            "Temperature",
            4.0,
            F,
            "°C",
            (2.0, 8.0),
            "Product temperature at the filler",
            False,
        ),
        "RejectCount": await _var(
            line,
            ns,
            "RejectCount",
            0,
            I32,
            None,
            None,
            "Bottles rejected by inspection since shift start",
            False,
        ),
        "LineState": await _var(
            line, ns, "LineState", "Running", S, None, None, "Running | Stopped | Fault", True
        ),
    }
    return Line(server, ns, nodes)


async def step(line: Line, t: int) -> None:
    n = line.nodes
    target = await n["FillTarget"].read_value()
    running = await n["LineState"].read_value() == "Running"
    # Scenario: the filler slowly drifts high after t=60 ("fill level drift" demo).
    drift = max(0, t - 60) * 0.05
    level = target + drift + random.gauss(0, 0.4) if running else target
    await n["FillLevel"].write_value(round(level, 2))
    await n["Temperature"].write_value(ua.Variant(4.0 + random.gauss(0, 0.1), ua.VariantType.Float))
    if running and abs(level - target) > 5:
        await n["RejectCount"].write_value(
            ua.Variant(await n["RejectCount"].read_value() + 1, ua.VariantType.Int32)
        )


async def run_forever(endpoint: str) -> None:
    line = await build(endpoint)
    async with line.server:
        log.info("simulator listening on %s (ns=%d)", endpoint, line.ns)
        t = 0
        while True:
            await step(line, t)
            t += 1
            await asyncio.sleep(1)
