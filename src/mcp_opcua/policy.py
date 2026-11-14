# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Copyright (c) 2026 USTechService Corporation
"""Write policy. Pure logic, no OPC UA I/O (ADR 0001): every check runs before the network."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import math
import os
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_opcua.config import TagRule, WritesConfig

# OPC UA variant types each rule type may be written to. Anything else is rejected at plan time.
_COMPATIBLE: dict[str, frozenset[str]] = {
    "bool": frozenset({"Boolean"}),
    "int": frozenset({"SByte", "Byte", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64"}),
    "float": frozenset({"Float", "Double"}),
    "str": frozenset({"String"}),
}
_INT_RANGE: dict[str, tuple[int, int]] = {
    "SByte": (-(2**7), 2**7 - 1),
    "Byte": (0, 2**8 - 1),
    "Int16": (-(2**15), 2**15 - 1),
    "UInt16": (0, 2**16 - 1),
    "Int32": (-(2**31), 2**31 - 1),
    "UInt32": (0, 2**32 - 1),
    "Int64": (-(2**63), 2**63 - 1),
    "UInt64": (0, 2**64 - 1),
}


class PolicyError(Exception):
    """A write was rejected. `code` is stable and machine-readable."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class WritePlan:
    token: str
    node_id: str
    current: Any
    proposed: Any
    checks: tuple[str, ...]
    expires_at: float
    # Separate from `token` and never returned to the agent; shown only to the human approver.
    approval_id: str | None = None

    @property
    def token_ref(self) -> str:
        """Short, non-secret reference linking plan and execute audit records."""
        return token_ref(self.token)


@dataclass
class WritePolicy:
    cfg: WritesConfig
    clock: Callable[[], float] = time.monotonic
    _plans: dict[str, WritePlan] = field(default_factory=dict)
    _last_write: dict[str, float] = field(default_factory=dict)

    # -- gates ---------------------------------------------------------------
    def killed(self) -> bool:
        if os.environ.get(self.cfg.kill_switch_env, "").strip() not in ("", "0", "false"):
            return True
        return bool(self.cfg.kill_switch_file and self.cfg.kill_switch_file.exists())

    def gate(self) -> None:
        if not self.cfg.enabled:
            raise PolicyError("writes_disabled", "writes are disabled (writes.enabled=false)")
        if self.killed():
            raise PolicyError("kill_switch", "kill switch is active; all writes are blocked")

    def rule_for(self, node_id: str) -> TagRule:
        """Exact match unless the rule opts into globbing. A node matching two rules is rejected."""
        hits = [
            r
            for r in self.cfg.tags
            if (fnmatch.fnmatchcase(node_id, r.pattern) if r.glob else r.pattern == node_id)
        ]
        if not hits:
            raise PolicyError("not_allowlisted", f"{node_id} is not in the write allowlist")
        if len(hits) > 1:
            pats = ", ".join(r.pattern for r in hits)
            raise PolicyError("ambiguous_rule", f"{node_id} matches several rules ({pats})")
        return hits[0]

    # -- constraint checks -----------------------------------------------------
    @staticmethod
    def _check_type(rule: TagRule, value: Any) -> None:
        # bool is a subclass of int in Python; reject it explicitly for numeric tags.
        ok = {
            "bool": isinstance(value, bool),
            "int": isinstance(value, int) and not isinstance(value, bool),
            "float": isinstance(value, int | float) and not isinstance(value, bool),
            "str": isinstance(value, str),
        }[rule.type]
        if not ok:
            raise PolicyError("type", f"expected {rule.type}, got {type(value).__name__}")
        if rule.type == "float" and not math.isfinite(value):
            raise PolicyError("type", "value must be finite")

    @staticmethod
    def check_node_type(rule: TagRule, variant_type: str, value: Any) -> None:
        """The rule's type must fit the node's real OPC UA type (catches config mistakes)."""
        if variant_type not in _COMPATIBLE[rule.type]:
            raise PolicyError(
                "node_type_mismatch", f"rule type {rule.type} cannot write a {variant_type} node"
            )
        lo_hi = _INT_RANGE.get(variant_type)
        if lo_hi and not lo_hi[0] <= value <= lo_hi[1]:
            raise PolicyError("type", f"{value} does not fit in {variant_type}")

    def check(self, node_id: str, proposed: Any, current: Any) -> tuple[TagRule, list[str]]:
        """Run every constraint. Raises PolicyError on the first violation."""
        self.gate()
        rule = self.rule_for(node_id)
        passed = ["enabled", "kill_switch", f"allowlist:{rule.pattern}"]
        self._check_type(rule, proposed)
        passed.append(f"type:{rule.type}")
        if rule.allowed is not None and proposed not in rule.allowed:
            raise PolicyError("not_allowed_value", f"{proposed!r} not in {rule.allowed!r}")
        if rule.min is not None and proposed < rule.min:
            raise PolicyError("below_min", f"{proposed} < min {rule.min}")
        if rule.max is not None and proposed > rule.max:
            raise PolicyError("above_max", f"{proposed} > max {rule.max}")
        if rule.min is not None or rule.max is not None:
            passed.append(f"range:[{rule.min},{rule.max}]")
        if rule.max_rate_of_change is not None:
            if not isinstance(current, int | float) or isinstance(current, bool):
                raise PolicyError("rate_unknown", "current value is not numeric; cannot bound step")
            if abs(proposed - current) > rule.max_rate_of_change:
                raise PolicyError(
                    "rate_of_change",
                    f"step {abs(proposed - current)} exceeds max {rule.max_rate_of_change}",
                )
            passed.append(f"step<={rule.max_rate_of_change}")
        last = self._last_write.get(node_id)
        if last is not None and self.clock() - last < rule.min_interval_s:
            raise PolicyError("too_soon", f"min interval {rule.min_interval_s}s not elapsed")
        passed.append(f"interval>={rule.min_interval_s}s")
        return rule, passed

    # -- two-phase commit ------------------------------------------------------
    def plan(self, node_id: str, proposed: Any, current: Any, variant_type: str) -> WritePlan:
        """`node_id` must already be canonical (config.canonical_node_id)."""
        rule, passed = self.check(node_id, proposed, current)
        self.check_node_type(rule, variant_type, proposed)
        passed.append(f"node_type:{variant_type}")
        self._expire()
        p = WritePlan(
            token=secrets.token_urlsafe(24),
            node_id=node_id,
            current=current,
            proposed=proposed,
            checks=tuple(passed),
            expires_at=self.clock() + self.cfg.token_ttl_s,
            approval_id=secrets.token_hex(4) if self.cfg.require_human else None,
        )
        self._plans[p.token] = p
        if p.approval_id:
            write_pending(self.cfg, p)
        return p

    def redeem(self, token: str) -> WritePlan:
        """Consume a token (single use). Caller must re-run check() against a fresh read."""
        self.gate()
        p = self._plans.pop(token, None)
        if p is None:
            raise PolicyError("bad_token", "unknown, used or expired confirmation token")
        if self.clock() > p.expires_at:
            self._discard_pending(p)
            raise PolicyError("token_expired", "confirmation token expired")
        if p.approval_id and not self._consume_approval(p):
            self._plans[token] = p  # still valid until it expires; the human may approve later
            raise PolicyError("awaiting_human", "waiting for a human to approve this write")
        return p

    def reserve_slot(self, node_id: str) -> None:
        """Record the write time BEFORE the network write: a timed-out write may still land."""
        self._last_write[node_id] = self.clock()

    def _expire(self) -> None:
        now = self.clock()
        for t in [t for t, p in self._plans.items() if p.expires_at < now]:
            self._discard_pending(self._plans.pop(t))

    # -- out-of-band approval --------------------------------------------------
    def _discard_pending(self, p: WritePlan) -> None:
        if p.approval_id:
            pending_path(self.cfg, p.approval_id).unlink(missing_ok=True)
            approval_path(self.cfg, p.approval_id).unlink(missing_ok=True)

    def _consume_approval(self, p: WritePlan) -> bool:
        assert p.approval_id
        f = approval_path(self.cfg, p.approval_id)
        if not f.exists():
            return False
        approved = f.read_text(encoding="utf-8").strip()
        self._discard_pending(p)
        if approved != plan_digest(p.approval_id, p.node_id, p.current, p.proposed):
            # The human approved something other than this plan. Burn the token.
            raise PolicyError("approval_mismatch", "approval does not match the planned write")
        return True


def token_ref(token: str) -> str:
    """Short, non-secret reference for a confirmation token (links audit records)."""
    return hashlib.sha256(token.encode()).hexdigest()[:12]


def _atomic_write(path: Path, text: str) -> None:
    # A reader never sees a half-written file (a torn approval would burn the token).
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def plan_digest(approval_id: str, node_id: str, current: Any, proposed: Any) -> str:
    """Binds a human approval to the exact write that was shown to them."""
    body = {"id": approval_id, "node_id": node_id, "current": current, "proposed": proposed}
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()


def _safe_id(approval_id: str) -> str:
    # It reaches the filesystem: hex only, no traversal.
    if not approval_id or any(c not in "0123456789abcdef" for c in approval_id):
        raise PolicyError("bad_approval_id", "malformed approval id")
    return approval_id


def approval_path(cfg: WritesConfig, approval_id: str) -> Path:
    return cfg.approvals_dir / f"{_safe_id(approval_id)}.approved"


def pending_path(cfg: WritesConfig, approval_id: str) -> Path:
    return cfg.approvals_dir / f"{_safe_id(approval_id)}.pending.json"


def write_pending(cfg: WritesConfig, p: WritePlan) -> None:
    """Publish the plan so `mcp-opcua approve` can show the human exactly what they approve."""
    assert p.approval_id
    cfg.approvals_dir.mkdir(parents=True, exist_ok=True)
    body = {
        "approval_id": p.approval_id,
        "node_id": p.node_id,
        "current": p.current,
        "proposed": p.proposed,
        "checks": list(p.checks),
        "expires_at_unix": time.time() + cfg.token_ttl_s,
    }
    _atomic_write(pending_path(cfg, p.approval_id), json.dumps(body, default=str))
