# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Copyright (c) 2026 USTechService Corporation
"""Write policy. Pure logic, no OPC UA I/O (ADR 0001): every check runs before the network."""

from __future__ import annotations

import fnmatch
import math
import os
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from mcp_opcua.config import TagRule, WritesConfig


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
        for rule in self.cfg.tags:
            if rule.pattern == node_id or fnmatch.fnmatchcase(node_id, rule.pattern):
                return rule
        raise PolicyError("not_allowlisted", f"{node_id} is not in the write allowlist")

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
            passed.append(f"rate<={rule.max_rate_of_change}")
        last = self._last_write.get(node_id)
        if last is not None and self.clock() - last < rule.min_interval_s:
            raise PolicyError("too_soon", f"min interval {rule.min_interval_s}s not elapsed")
        passed.append(f"interval>={rule.min_interval_s}s")
        return rule, passed

    # -- two-phase commit ------------------------------------------------------
    def plan(self, node_id: str, proposed: Any, current: Any) -> WritePlan:
        _, passed = self.check(node_id, proposed, current)
        self._expire()
        p = WritePlan(
            token=secrets.token_urlsafe(24),
            node_id=node_id,
            current=current,
            proposed=proposed,
            checks=tuple(passed),
            expires_at=self.clock() + self.cfg.token_ttl_s,
        )
        self._plans[p.token] = p
        return p

    def redeem(self, token: str) -> WritePlan:
        """Consume a token (single use). Caller must re-run check() against a fresh read."""
        self.gate()
        p = self._plans.pop(token, None)
        if p is None:
            raise PolicyError("bad_token", "unknown, used or expired confirmation token")
        if self.clock() > p.expires_at:
            raise PolicyError("token_expired", "confirmation token expired")
        if self.cfg.require_human and not self._consume_approval(token):
            self._plans[token] = p  # still valid until it expires; the human may approve later
            raise PolicyError(
                "awaiting_human", "human approval required: run `mcp-opcua approve <token>`"
            )
        return p

    def record_write(self, node_id: str) -> None:
        self._last_write[node_id] = self.clock()

    def _expire(self) -> None:
        now = self.clock()
        for t in [t for t, p in self._plans.items() if p.expires_at < now]:
            del self._plans[t]

    # -- out-of-band approval --------------------------------------------------
    def _consume_approval(self, token: str) -> bool:
        f = approval_path(self.cfg, token)
        if not f.exists():
            return False
        f.unlink()
        return True


def approval_path(cfg: WritesConfig, token: str) -> Any:
    # Token is urlsafe base64, but sanitize anyway: it reaches the filesystem.
    safe = "".join(c for c in token if c.isalnum() or c in "-_")
    if not safe or safe != token:
        raise PolicyError("bad_token", "malformed token")
    return cfg.approvals_dir / safe
