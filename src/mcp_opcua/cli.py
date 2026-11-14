# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Copyright (c) 2026 USTechService Corporation
"""Command line: serve, audit verify, approve, sim."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from mcp_opcua.audit import AuditLog, verify
from mcp_opcua.config import load_config


def _serve(config: Path, transport: str, host: str, port: int) -> int:
    from mcp_opcua.opcua_client import OpcUaClient
    from mcp_opcua.policy import WritePolicy
    from mcp_opcua.server import Service, build_server

    cfg = load_config(config)

    async def run() -> None:
        ua = OpcUaClient(cfg.connection, cfg.subscriptions)
        await ua.connect()
        try:
            svc = Service(
                cfg, ua, AuditLog(cfg.audit.path, cfg.audit.hash_chain), WritePolicy(cfg.writes)
            )
            server = build_server(svc)
            if transport == "stdio":
                await server.run_stdio_async()
            else:
                await server.run_streamable_http_async(host=host, port=port)
        finally:
            await ua.close()

    asyncio.run(run())
    return 0


def _approve(config: Path, token: str) -> int:
    from mcp_opcua.policy import approval_path

    cfg = load_config(config)
    f = approval_path(cfg.writes, token)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.touch()
    AuditLog(cfg.audit.path, cfg.audit.hash_chain).append(
        client="cli", tool="approve", args={"token": token[:6] + "…"}, status="ok"
    )
    print(f"approved {token[:6]}… (the agent can now confirm it before it expires)")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="mcp-opcua")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the MCP server")
    s.add_argument("--config", type=Path, required=True)
    s.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio")
    s.add_argument("--host", default="127.0.0.1", help="HTTP bind address (no auth in v0.1)")
    s.add_argument("--port", type=int, default=8000)

    a = sub.add_parser("audit", help="audit log tools")
    a.add_argument("action", choices=["verify"])
    a.add_argument("path", type=Path)

    ap = sub.add_parser("approve", help="approve a pending write (human-in-the-loop)")
    ap.add_argument("token")
    ap.add_argument("--config", type=Path, required=True)

    sm = sub.add_parser("sim", help="run the bottling-line simulator")
    sm.add_argument("--endpoint", default="opc.tcp://0.0.0.0:4840/bottling/")

    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)  # stdout is the MCP channel

    if args.cmd == "serve":
        return _serve(args.config, args.transport, args.host, args.port)
    if args.cmd == "audit":
        ok, msg = verify(args.path)
        print(msg)
        return 0 if ok else 1
    if args.cmd == "approve":
        return _approve(args.config, args.token)
    if args.cmd == "sim":
        from mcp_opcua.sim import run_forever

        asyncio.run(run_forever(args.endpoint))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
