# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Copyright (c) 2026 USTechService Corporation
"""One test per rejection path, plus property tests for range checks. No OPC UA server needed."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from mcp_opcua.config import TagRule, WritesConfig
from mcp_opcua.policy import PolicyError, WritePolicy, approval_path

SPEED = "ns=2;s=ConveyorSpeed"


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def make(tmp_path: Path, clock: Clock | None = None, **over: Any) -> WritePolicy:
    tags = over.pop(
        "tags",
        [
            TagRule(
                pattern=SPEED,
                type="float",
                min=0,
                max=2.5,
                max_rate_of_change=0.5,
                min_interval_s=5,
            ),
            TagRule(pattern="ns=2;s=LineState", type="str", allowed=["Running", "Stopped"]),
            TagRule(pattern="ns=2;s=Count*", type="int", min=0, max=10),
            TagRule(pattern="ns=2;s=Enable", type="bool"),
        ],
    )
    cfg = WritesConfig(
        enabled=over.pop("enabled", True),
        tags=tags,
        approvals_dir=tmp_path / "approvals",
        kill_switch_file=tmp_path / "KILL",
        **over,
    )
    return WritePolicy(cfg, clock=clock or Clock())


def code(exc: pytest.ExceptionInfo[PolicyError]) -> str:
    return exc.value.code


# -- gates -------------------------------------------------------------------
def test_disabled_by_default() -> None:
    assert WritesConfig().enabled is False
    with pytest.raises(PolicyError) as e:
        WritePolicy(WritesConfig()).check(SPEED, 1.0, 1.0)
    assert code(e) == "writes_disabled"


def test_kill_switch_file(tmp_path: Path) -> None:
    p = make(tmp_path)
    (tmp_path / "KILL").touch()
    with pytest.raises(PolicyError) as e:
        p.check(SPEED, 1.0, 1.0)
    assert code(e) == "kill_switch"


def test_kill_switch_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = make(tmp_path)
    monkeypatch.setenv("MCP_OPCUA_KILL", "1")
    with pytest.raises(PolicyError) as e:
        p.check(SPEED, 1.0, 1.0)
    assert code(e) == "kill_switch"


def test_kill_switch_blocks_confirm_after_plan(tmp_path: Path) -> None:
    p = make(tmp_path)
    plan = p.plan(SPEED, 1.2, 1.0)
    (tmp_path / "KILL").touch()
    with pytest.raises(PolicyError) as e:
        p.redeem(plan.token)
    assert code(e) == "kill_switch"


def test_not_allowlisted(tmp_path: Path) -> None:
    with pytest.raises(PolicyError) as e:
        make(tmp_path).check("ns=2;s=FillLevel", 1.0, 1.0)
    assert code(e) == "not_allowlisted"


def test_glob_allowlist(tmp_path: Path) -> None:
    make(tmp_path).check("ns=2;s=CountA", 3, 0)


# -- constraints -------------------------------------------------------------
@pytest.mark.parametrize(
    ("node", "value"),
    [
        (SPEED, "fast"),
        (SPEED, True),
        ("ns=2;s=CountA", 1.5),
        ("ns=2;s=CountA", False),
        ("ns=2;s=Enable", 1),
        ("ns=2;s=LineState", 3),
        (SPEED, float("nan")),
        (SPEED, float("inf")),
    ],
)
def test_type(tmp_path: Path, node: str, value: Any) -> None:
    with pytest.raises(PolicyError) as e:
        make(tmp_path).check(node, value, 0)
    assert code(e) == "type"


def test_not_allowed_value(tmp_path: Path) -> None:
    with pytest.raises(PolicyError) as e:
        make(tmp_path).check("ns=2;s=LineState", "Fault", "Running")
    assert code(e) == "not_allowed_value"


def test_below_min(tmp_path: Path) -> None:
    with pytest.raises(PolicyError) as e:
        make(tmp_path).check("ns=2;s=CountA", -1, 0)
    assert code(e) == "below_min"


def test_above_max(tmp_path: Path) -> None:
    with pytest.raises(PolicyError) as e:
        make(tmp_path).check(SPEED, 2.6, 2.4)
    assert code(e) == "above_max"


def test_rate_of_change(tmp_path: Path) -> None:
    with pytest.raises(PolicyError) as e:
        make(tmp_path).check(SPEED, 2.0, 1.0)
    assert code(e) == "rate_of_change"


def test_rate_unknown_when_current_not_numeric(tmp_path: Path) -> None:
    with pytest.raises(PolicyError) as e:
        make(tmp_path).check(SPEED, 1.0, None)
    assert code(e) == "rate_unknown"


def test_min_interval(tmp_path: Path) -> None:
    clock = Clock()
    p = make(tmp_path, clock)
    p.check(SPEED, 1.1, 1.0)
    p.record_write(SPEED)
    clock.t += 4.9
    with pytest.raises(PolicyError) as e:
        p.check(SPEED, 1.2, 1.1)
    assert code(e) == "too_soon"
    clock.t += 0.2
    p.check(SPEED, 1.2, 1.1)


# -- two-phase tokens --------------------------------------------------------
def test_plan_then_redeem_once(tmp_path: Path) -> None:
    p = make(tmp_path)
    plan = p.plan(SPEED, 1.2, 1.0)
    assert plan.current == 1.0 and plan.proposed == 1.2
    assert p.redeem(plan.token) == plan
    with pytest.raises(PolicyError) as e:
        p.redeem(plan.token)
    assert code(e) == "bad_token"


def test_unknown_token(tmp_path: Path) -> None:
    with pytest.raises(PolicyError) as e:
        make(tmp_path).redeem("nope")
    assert code(e) == "bad_token"


def test_token_expired(tmp_path: Path) -> None:
    clock = Clock()
    p = make(tmp_path, clock, token_ttl_s=10)
    plan = p.plan(SPEED, 1.2, 1.0)
    clock.t += 10.1
    with pytest.raises(PolicyError) as e:
        p.redeem(plan.token)
    assert code(e) == "token_expired"


def test_plan_rejected_issues_no_token(tmp_path: Path) -> None:
    p = make(tmp_path)
    with pytest.raises(PolicyError):
        p.plan(SPEED, 9.0, 1.0)
    assert p._plans == {}


def test_human_approval_required(tmp_path: Path) -> None:
    p = make(tmp_path, require_human=True)
    plan = p.plan(SPEED, 1.2, 1.0)
    with pytest.raises(PolicyError) as e:
        p.redeem(plan.token)
    assert code(e) == "awaiting_human"
    f = approval_path(p.cfg, plan.token)
    f.parent.mkdir(parents=True)
    f.touch()
    assert p.redeem(plan.token) == plan
    assert not f.exists()  # approval is single use


@pytest.mark.parametrize("bad", ["../../etc/passwd", "a/b", "", "x y"])
def test_approval_path_rejects_traversal(tmp_path: Path, bad: str) -> None:
    with pytest.raises(PolicyError) as e:
        approval_path(make(tmp_path).cfg, bad)
    assert code(e) == "bad_token"


# -- properties --------------------------------------------------------------
LO, HI = -50.0, 50.0
finite = st.floats(allow_nan=False, allow_infinity=False, width=64)


@given(v=finite)
def test_range_property(tmp_path_factory: pytest.TempPathFactory, v: float) -> None:
    p = make(
        tmp_path_factory.mktemp("p"), tags=[TagRule(pattern="t", type="float", min=LO, max=HI)]
    )
    if LO <= v <= HI:
        p.check("t", v, 0.0)
    else:
        with pytest.raises(PolicyError) as e:
            p.check("t", v, 0.0)
        assert code(e) in ("below_min", "above_max")


@given(cur=st.floats(-100, 100), new=st.floats(-100, 100))
def test_rate_property(tmp_path_factory: pytest.TempPathFactory, cur: float, new: float) -> None:
    p = make(
        tmp_path_factory.mktemp("p"),
        tags=[TagRule(pattern="t", type="float", max_rate_of_change=1.0)],
    )
    if abs(new - cur) <= 1.0:
        p.check("t", new, cur)
    else:
        with pytest.raises(PolicyError):
            p.check("t", new, cur)
