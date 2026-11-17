# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Copyright (c) 2026 USTechService Corporation
"""Command line: serve, audit verify, approve, sim."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

from mcp_opcua.audit import AuditLog, verify
from mcp_opcua.config import load_config

_LOOPBACK = ("127.0.0.1", "localhost", "::1")


def _transport_security(extra_hosts: list[str]) -> Any:
    from mcp.server.transport_security import TransportSecuritySettings

    # Always on: binding 0.0.0.0 (e.g. in a container) would otherwise switch the SDK's
    # DNS-rebinding protection off. Hosts are Host-header values, `name:port` or `name:*`.
    hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*", *extra_hosts]
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=hosts,
        allowed_origins=[f"http://{h}" for h in hosts],
    )


def _serve(config: Path, transport: str, host: str, port: int, allowed_hosts: list[str]) -> int:
    from mcp_opcua.opcua_client import OpcUaClient
    from mcp_opcua.policy import WritePolicy
    from mcp_opcua.server import Service, build_server

    cfg = load_config(config)
    if cfg.writes.enabled:
        # Relative paths resolve against the config file: say where the kill switch really is.
        logging.getLogger("mcp_opcua").warning(
            "writes ENABLED. kill switch: touch %s or set %s=1",
            cfg.writes.kill_switch_file,
            cfg.writes.kill_switch_env,
        )
    if transport != "stdio" and cfg.writes.enabled and host not in _LOOPBACK:
        print(
            f"refusing to serve writes over unauthenticated HTTP on {host}; bind to loopback",
            file=sys.stderr,
        )
        return 2

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
                await server.run_streamable_http_async(
                    host=host, port=port, transport_security=_transport_security(allowed_hosts)
                )
        finally:
            await ua.close()

    asyncio.run(run())
    return 0


def _approve(config: Path, approval_id: str | None) -> int:
    """Show the human exactly what they approve. Only the server writes the audit log."""
    from mcp_opcua.policy import (
        PolicyError,
        _atomic_write,
        approval_path,
        pending_path,
        plan_digest,
    )

    w = load_config(config).writes
    if approval_id is None:
        pending = sorted(w.approvals_dir.glob("*.pending.json"))
        for f in pending:
            try:
                d = json.loads(f.read_text(encoding="utf-8"))
                left = d["expires_at_unix"] - time.time()
                line = (
                    f"{d['approval_id']}  {d['node_id']!r}: {d['current']!r} -> {d['proposed']!r}"
                )
            except (ValueError, KeyError, TypeError) as e:
                print(f"skipping unreadable {f.name}: {e}", file=sys.stderr)
                continue
            if left > 0:
                print(f"{line}  ({left:.0f}s left)")
        if not pending:
            print("no pending writes")
        return 0
    try:
        f = pending_path(w, approval_id)
    except PolicyError as e:
        print(e, file=sys.stderr)
        return 1
    if not f.is_file():
        print(f"no pending write {approval_id}", file=sys.stderr)
        return 1
    d = json.loads(f.read_text(encoding="utf-8"))
    if time.time() > d["expires_at_unix"]:
        print(f"{approval_id} has expired", file=sys.stderr)
        return 1
    print(f"node:     {d['node_id']!r}")  # repr: no terminal escapes from node names
    print(f"current:  {d['current']!r}")
    print(f"proposed: {d['proposed']!r}")
    print(f"checks:   {', '.join(d['checks'])}")
    # shortcut: a TTY check stops scripted approval, not an agent with a pty on the same account.
    if not sys.stdin.isatty():
        print("refusing: approval needs an interactive terminal", file=sys.stderr)
        return 1
    if input("Type 'approve' to allow this write: ").strip() != "approve":
        print("not approved")
        return 1
    digest = plan_digest(d["approval_id"], d["node_id"], d["current"], d["proposed"])
    _atomic_write(approval_path(w, approval_id), digest)
    print("approved: the agent can now confirm it before it expires")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="mcp-opcua")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the MCP server")
    s.add_argument("--config", type=Path, required=True)
    s.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio")
    s.add_argument("--host", default="127.0.0.1", help="HTTP bind address (no auth in v0.1)")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument(
        "--allowed-host",
        action="append",
        default=[],
        help="extra Host header to accept over HTTP, e.g. 'mcp:8000' (repeatable)",
    )

    a = sub.add_parser("audit", help="audit log tools")
    a.add_argument("action", choices=["verify"])
    a.add_argument("path", type=Path)

    ap = sub.add_parser("approve", help="approve a pending write (human-in-the-loop)")
    ap.add_argument("approval_id", nargs="?", help="omit to list pending writes")
    ap.add_argument("--config", type=Path, required=True)

    sm = sub.add_parser("sim", help="run the bottling-line simulator")
    sm.add_argument("--endpoint", default="opc.tcp://0.0.0.0:4840/bottling/")

    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)  # stdout is the MCP channel

    if args.cmd == "serve":
        return _serve(args.config, args.transport, args.host, args.port, args.allowed_host)
    if args.cmd == "audit":
        ok, msg = verify(args.path)
        print(msg)
        return 0 if ok else 1
    if args.cmd == "approve":
        return _approve(args.config, args.approval_id)
    if args.cmd == "sim":
        from mcp_opcua.sim import run_forever

        asyncio.run(run_forever(args.endpoint))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
