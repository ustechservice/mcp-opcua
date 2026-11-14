# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Copyright (c) 2026 USTechService Corporation
"""Regression tests for the security review findings (H1-H4, M1-M5, L1-L3)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from test_integration import SPEED, _svc, endpoint  # noqa: F401  (fixture)

from mcp_opcua.audit import verify
from mcp_opcua.cli import main
from mcp_opcua.config import Config, TagRule, WritesConfig, load_config
from mcp_opcua.policy import WritePolicy

SLOW = {
    "enabled": True,
    "tags": [
        {
            "pattern": SPEED,
            "type": "float",
            "min": 0,
            "max": 2.5,
            "max_rate_of_change": 0.5,
            "min_interval_s": 60,
        }
    ],
}


def _audit(tmp_path: Path) -> list[dict[str, Any]]:
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    return [json.loads(x) for x in lines]


# -- H1: concurrent confirms -------------------------------------------------
@pytest.mark.integration
async def test_concurrent_confirms_cannot_both_write(endpoint: str, tmp_path: Path) -> None:  # noqa: F811
    svc = await _svc(endpoint, tmp_path, SLOW)
    try:
        a = await svc.write(SPEED, 1.4, None)
        b = await svc.write(SPEED, 1.6, None)
        ra, rb = await asyncio.gather(
            svc.write(None, None, a["confirmation_token"]),
            svc.write(None, None, b["confirmation_token"]),
        )
        statuses = sorted([ra.get("code", ra["status"]), rb.get("code", rb["status"])])
        assert statuses == ["too_soon", "written"]
    finally:
        await svc.ua.close()


# -- H2: audit survives a failed read-back ------------------------------------
@pytest.mark.integration
async def test_readback_failure_is_audited(endpoint: str, tmp_path: Path) -> None:  # noqa: F811
    svc = await _svc(endpoint, tmp_path, SLOW)
    try:
        plan = await svc.write(SPEED, 1.4, None)
        real = svc.ua.read_value
        calls = 0

        async def flaky(node_id: str) -> Any:
            nonlocal calls
            calls += 1
            if calls == 2:  # 1 = fresh read before write, 2 = read-back
                raise OSError("connection lost")
            return await real(node_id)

        svc.ua.read_value = flaky  # type: ignore[method-assign]
        r = await svc.write(None, None, plan["confirmation_token"])
        assert r["status"] == "readback_failed"
        svc.ua.read_value = real  # type: ignore[method-assign]
        assert await svc.ua.read_value(SPEED) == 1.4  # the write did land
    finally:
        await svc.ua.close()
    recs = _audit(tmp_path)
    intent = [x for x in recs if x["tool"] == "write_intent"]
    final = recs[-1]
    assert intent and intent[0]["node_id"] == SPEED and intent[0]["requested"] == 1.4
    assert final["status"] == "readback_failed" and final["token_ref"] == intent[0]["token_ref"]
    assert verify(tmp_path / "audit.jsonl")[0]


# -- H3: approval id never reaches the agent; approve needs a TTY -------------
def _human_cfg(tmp_path: Path) -> Path:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "connection: {endpoint: 'opc.tcp://localhost:4840/', security_mode: 'None', "
        "allow_insecure: true}\n"
        "writes: {enabled: true, require_human: true, kill_switch_file: KILL, "
        "tags: [{pattern: 'ns=2;s=X', type: int, max: 10}]}\n"
    )
    return cfg


def test_approve_flow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _human_cfg(tmp_path)
    policy = WritePolicy(load_config(path).writes)
    plan = policy.plan("ns=2;s=X", 5, 1, "Int32")
    assert plan.approval_id

    assert main(["approve", "--config", str(path)]) == 0
    assert plan.approval_id in capsys.readouterr().out  # operator can list it

    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert main(["approve", plan.approval_id, "--config", str(path)]) == 1

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "no")
    assert main(["approve", plan.approval_id, "--config", str(path)]) == 1

    monkeypatch.setattr("builtins.input", lambda _: "approve")
    assert main(["approve", plan.approval_id, "--config", str(path)]) == 0
    assert policy.redeem(plan.token) == plan
    assert not (tmp_path / "audit.jsonl").exists()  # M3: only the server writes the log


@pytest.mark.integration
async def test_plan_response_hides_approval_id(endpoint: str, tmp_path: Path) -> None:  # noqa: F811
    svc = await _svc(endpoint, tmp_path, {**SLOW, "require_human": True})
    try:
        r = await svc.write(SPEED, 1.4, None)
        assert r["requires_human"] is True
        (pending,) = (tmp_path / "ap").glob("*.pending.json")
        approval_id = pending.name.split(".")[0]
        assert approval_id not in json.dumps(r)
        assert "mcp-opcua approve" not in r["next"]
        c = await svc.write(None, None, r["confirmation_token"])
        assert c["code"] == "awaiting_human"
    finally:
        await svc.ua.close()


# -- H4: one spelling per node ------------------------------------------------
@pytest.mark.integration
async def test_alternate_nodeid_spelling_shares_policy(endpoint: str, tmp_path: Path) -> None:  # noqa: F811
    svc = await _svc(endpoint, tmp_path, SLOW)
    try:
        r = await svc.write(SPEED, 1.4, None)
        assert (await svc.write(None, None, r["confirmation_token"]))["status"] == "written"
        alt = await svc.write("ns=02;s=ConveyorSpeed", 1.6, None)
        assert alt["code"] == "too_soon"  # same interval counter as the canonical spelling
        dup = await svc.write("ns=3;ns=2;s=ConveyorSpeed", 1.6, None)
        assert dup["code"] == "too_soon"
    finally:
        await svc.ua.close()


def test_non_canonical_pattern_rejected() -> None:
    with pytest.raises(ValidationError):
        TagRule(pattern="ns=02;s=X", type="int")


# -- M1/M2/L3 config ------------------------------------------------------------
def test_relative_paths_resolve_against_config_dir(tmp_path: Path) -> None:
    w = load_config(_human_cfg(tmp_path)).writes
    assert w.kill_switch_file == tmp_path / "KILL"
    assert w.approvals_dir == tmp_path / ".mcp-opcua" / "approvals"


def test_enabled_requires_kill_switch_file() -> None:
    with pytest.raises(ValidationError):
        WritesConfig(enabled=True, tags=[TagRule(pattern="ns=2;s=X", type="int")])


def test_rate_requires_interval() -> None:
    with pytest.raises(ValidationError):
        TagRule(pattern="ns=2;s=X", type="float", max_rate_of_change=1)


def test_insecure_writes_only_against_sim() -> None:
    conn = {"security_mode": "None", "allow_insecure": True}
    writes = {"enabled": True, "kill_switch_file": "K", "tags": [{"pattern": "i=1", "type": "int"}]}
    Config.model_validate(
        {"connection": {"endpoint": "opc.tcp://sim:4840/", **conn}, "writes": writes}
    )
    with pytest.raises(ValidationError):
        Config.model_validate(
            {"connection": {"endpoint": "opc.tcp://10.0.0.5:4840/", **conn}, "writes": writes}
        )


# -- M5: no unauthenticated writes off loopback ---------------------------------
def test_http_with_writes_refuses_non_loopback(tmp_path: Path) -> None:
    path = _human_cfg(tmp_path)
    args = ["serve", "--config", str(path), "--transport", "streamable-http", "--host", "0.0.0.0"]  # noqa: S104
    assert main(args) == 2


# -- subscription leak --------------------------------------------------------
@pytest.mark.integration
async def test_failed_subscribe_leaves_nothing_behind(endpoint: str, tmp_path: Path) -> None:  # noqa: F811
    svc = await _svc(endpoint, tmp_path)
    try:
        r = await svc.subscribe([SPEED, "ns=2;s=DoesNotExist"], 100)
        assert r["status"] == "error"
        assert svc.ua._subs == {}
    finally:
        await svc.ua.close()


# -- follow-up review ----------------------------------------------------------
def test_rate_needs_meaningful_interval() -> None:
    with pytest.raises(ValidationError):
        TagRule(pattern="ns=2;s=X", type="float", max_rate_of_change=1, min_interval_s=1e-6)


def test_home_dir_expanded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    path = _human_cfg(tmp_path)
    path.write_text(path.read_text().replace("kill_switch_file: KILL", "kill_switch_file: ~/KILL"))
    assert load_config(path).writes.kill_switch_file == tmp_path / "KILL"


def test_approve_skips_corrupt_pending(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _human_cfg(tmp_path)
    d = tmp_path / ".mcp-opcua" / "approvals"
    d.mkdir(parents=True)
    (d / "abcd.pending.json").write_text("{not json")
    assert main(["approve", "--config", str(path)]) == 0
    assert "skipping" in capsys.readouterr().err


@pytest.mark.integration
async def test_rejected_confirm_is_linked_to_plan(endpoint: str, tmp_path: Path) -> None:  # noqa: F811
    svc = await _svc(endpoint, tmp_path, {**SLOW, "require_human": True})
    try:
        r = await svc.write(SPEED, 1.4, None)
        assert (await svc.write(None, None, r["confirmation_token"]))["code"] == "awaiting_human"
    finally:
        await svc.ua.close()
    plan_rec, confirm_rec = _audit(tmp_path)[-2:]
    assert confirm_rec["status"] == "rejected:awaiting_human"
    assert confirm_rec["token_ref"] == plan_rec["token_ref"]
