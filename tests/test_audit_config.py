# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Copyright (c) 2026 USTechService Corporation
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mcp_opcua.audit import AuditLog, verify
from mcp_opcua.cli import main
from mcp_opcua.config import Config, TagRule, WritesConfig

# -- audit -------------------------------------------------------------------


def _log(tmp_path: Path, n: int = 3) -> Path:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(n):
        log.append(client="t", tool="read", args={"i": i}, status="ok")
    return path


def test_chain_verifies_and_resumes(tmp_path: Path) -> None:
    path = _log(tmp_path)
    AuditLog(path).append(client="t", tool="read", args={}, status="ok")  # reopen continues chain
    assert verify(path) == (True, "ok: 4 records verified")
    assert main(["audit", "verify", str(path)]) == 0


def test_tamper_detected(tmp_path: Path) -> None:
    path = _log(tmp_path)
    lines = path.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["status"] = "rejected"
    lines[1] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n")
    ok, msg = verify(path)
    assert not ok and "line 2" in msg
    assert main(["audit", "verify", str(path)]) == 1


def test_verify_missing_file(tmp_path: Path) -> None:
    assert main(["audit", "verify", str(tmp_path / "nope.jsonl")]) == 1


def test_deletion_detected(tmp_path: Path) -> None:
    path = _log(tmp_path)
    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    ok, msg = verify(path)
    assert not ok and "chain broken" in msg


# -- config (fail closed) ----------------------------------------------------
SIM = {"endpoint": "opc.tcp://localhost:4840/", "security_mode": "None", "allow_insecure": True}


def cfg(**conn: Any) -> Config:
    return Config.model_validate({"connection": {**SIM, **conn}})


def test_sim_config_ok() -> None:
    c = cfg()
    assert c.writes.enabled is False


@pytest.mark.parametrize(
    "conn",
    [
        {"allow_insecure": False},  # None mode without explicit opt-in
        {"endpoint": "http://x"},  # wrong scheme
        {"security_mode": "SignAndEncrypt"},  # no server cert -> unknown certs not trusted
        {"bogus": 1},  # unknown keys rejected
        {"auth": {"kind": "username"}},  # missing env var names
        {"auth": {"kind": "certificate"}},
    ],
)
def test_bad_connection_rejected(conn: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        cfg(**conn)


def test_enabled_with_empty_allowlist_rejected() -> None:
    with pytest.raises(ValidationError):
        WritesConfig(enabled=True)


@pytest.mark.parametrize(
    "rule",
    [
        {"pattern": "x", "type": "float", "min": 2, "max": 1},
        {"pattern": "x", "type": "bool", "max": 1},
        {"pattern": "x", "type": "str", "max_rate_of_change": 1},
        {"pattern": "", "type": "int"},
    ],
)
def test_bad_tag_rules(rule: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        TagRule.model_validate(rule)
