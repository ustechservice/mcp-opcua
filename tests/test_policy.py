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
from mcp_opcua.policy import PolicyError, WritePolicy, approval_path, pending_path, plan_digest

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
            TagRule(pattern="ns=2;s=Count*", glob=True, type="int", min=0, max=10),
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
    plan = p.plan(SPEED, 1.2, 1.0, "Double")
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
    p.reserve_slot(SPEED)
    clock.t += 4.9
    with pytest.raises(PolicyError) as e:
        p.check(SPEED, 1.2, 1.1)
    assert code(e) == "too_soon"
    clock.t += 0.2
    p.check(SPEED, 1.2, 1.1)


# -- two-phase tokens --------------------------------------------------------
def test_plan_then_redeem_once(tmp_path: Path) -> None:
    p = make(tmp_path)
    plan = p.plan(SPEED, 1.2, 1.0, "Double")
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
    plan = p.plan(SPEED, 1.2, 1.0, "Double")
    clock.t += 10.1
    with pytest.raises(PolicyError) as e:
        p.redeem(plan.token)
    assert code(e) == "token_expired"


def test_plan_rejected_issues_no_token(tmp_path: Path) -> None:
    p = make(tmp_path)
    with pytest.raises(PolicyError):
        p.plan(SPEED, 9.0, 1.0, "Double")
    assert p._plans == {}


def test_glob_is_opt_in(tmp_path: Path) -> None:
    # Without glob, `[` and `*` are literal: `Tank[1]` must not also match `Tank1`.
    p = make(tmp_path, tags=[TagRule(pattern="ns=2;s=Tank[1]", type="int")])
    p.check("ns=2;s=Tank[1]", 1, 0)
    with pytest.raises(PolicyError) as e:
        p.check("ns=2;s=Tank1", 1, 0)
    assert code(e) == "not_allowlisted"


def test_ambiguous_rule(tmp_path: Path) -> None:
    tags = [
        TagRule(pattern="ns=2;s=CountA", type="int", max=100),
        TagRule(pattern="ns=2;s=Count*", glob=True, type="int", max=10),
    ]
    with pytest.raises(PolicyError) as e:
        make(tmp_path, tags=tags).check("ns=2;s=CountA", 1, 0)
    assert code(e) == "ambiguous_rule"


@pytest.mark.parametrize(
    ("node", "value", "vtype", "expect"),
    [
        (SPEED, 1.2, "String", "node_type_mismatch"),
        ("ns=2;s=CountA", 3, "Double", "node_type_mismatch"),
        ("ns=2;s=Enable", True, "Int32", "node_type_mismatch"),
    ],
)
def test_node_type_mismatch(tmp_path: Path, node: str, value: Any, vtype: str, expect: str) -> None:
    with pytest.raises(PolicyError) as e:
        make(tmp_path).plan(node, value, 0 if node != SPEED else 1.0, vtype)
    assert code(e) == expect


def test_int_must_fit_node_width(tmp_path: Path) -> None:
    p = make(tmp_path, tags=[TagRule(pattern="ns=2;s=B", type="int")])
    p.plan("ns=2;s=B", 255, 0, "Byte")
    with pytest.raises(PolicyError) as e:
        p.plan("ns=2;s=B", 256, 0, "Byte")
    assert code(e) == "type"


def _approve(p: WritePolicy, approval_id: str, node: str, cur: Any, new: Any) -> None:
    approval_path(p.cfg, approval_id).write_text(plan_digest(approval_id, node, cur, new))


def test_human_approval_required(tmp_path: Path) -> None:
    p = make(tmp_path, require_human=True)
    plan = p.plan(SPEED, 1.2, 1.0, "Double")
    assert plan.approval_id and plan.approval_id not in plan.token
    assert pending_path(p.cfg, plan.approval_id).is_file()  # what the operator will be shown
    with pytest.raises(PolicyError) as e:
        p.redeem(plan.token)
    assert code(e) == "awaiting_human"
    _approve(p, plan.approval_id, SPEED, 1.0, 1.2)
    assert p.redeem(plan.token) == plan
    assert not approval_path(p.cfg, plan.approval_id).exists()  # single use
    assert not pending_path(p.cfg, plan.approval_id).exists()


def test_approval_for_a_different_write_rejected(tmp_path: Path) -> None:
    p = make(tmp_path, require_human=True)
    plan = p.plan(SPEED, 1.2, 1.0, "Double")
    assert plan.approval_id
    _approve(p, plan.approval_id, SPEED, 1.0, 2.5)  # human approved some other value
    with pytest.raises(PolicyError) as e:
        p.redeem(plan.token)
    assert code(e) == "approval_mismatch"
    with pytest.raises(PolicyError) as e:
        p.redeem(plan.token)  # token is burned
    assert code(e) == "bad_token"


def test_expired_plan_removes_pending(tmp_path: Path) -> None:
    clock = Clock()
    p = make(tmp_path, clock, require_human=True, token_ttl_s=10)
    plan = p.plan(SPEED, 1.2, 1.0, "Double")
    assert plan.approval_id
    clock.t += 11
    with pytest.raises(PolicyError):
        p.redeem(plan.token)
    assert not pending_path(p.cfg, plan.approval_id).exists()


@pytest.mark.parametrize("bad", ["../../etc/passwd", "a/b", "", "x y", "ABCD"])
def test_approval_path_rejects_traversal(tmp_path: Path, bad: str) -> None:
    with pytest.raises(PolicyError) as e:
        approval_path(make(tmp_path).cfg, bad)
    assert code(e) == "bad_approval_id"


# -- properties --------------------------------------------------------------
LO, HI = -50.0, 50.0
T = "ns=2;s=t"
finite = st.floats(allow_nan=False, allow_infinity=False, width=64)


@given(v=finite)
def test_range_property(tmp_path_factory: pytest.TempPathFactory, v: float) -> None:
    p = make(tmp_path_factory.mktemp("p"), tags=[TagRule(pattern=T, type="float", min=LO, max=HI)])
    if LO <= v <= HI:
        p.check(T, v, 0.0)
    else:
        with pytest.raises(PolicyError) as e:
            p.check(T, v, 0.0)
        assert code(e) in ("below_min", "above_max")


@given(cur=st.floats(-100, 100), new=st.floats(-100, 100))
def test_rate_property(tmp_path_factory: pytest.TempPathFactory, cur: float, new: float) -> None:
    p = make(
        tmp_path_factory.mktemp("p"),
        tags=[TagRule(pattern=T, type="float", max_rate_of_change=1.0, min_interval_s=1)],
    )
    if abs(new - cur) <= 1.0:
        p.check(T, new, cur)
    else:
        with pytest.raises(PolicyError):
            p.check(T, new, cur)
