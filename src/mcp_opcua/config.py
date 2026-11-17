# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Copyright (c) 2026 USTechService Corporation
"""Configuration models. Validated at startup; anything invalid fails closed."""

from __future__ import annotations

import os
from enum import StrEnum
from pathlib import Path
from typing import Literal, Self
from urllib.parse import urlparse

import yaml
from asyncua import ua
from pydantic import BaseModel, ConfigDict, Field, model_validator


def canonical_node_id(node_id: str) -> str:
    """One spelling per node (`ns=02;s=X` -> `ns=2;s=X`). Policy matching, rate limiting and the
    actual OPC UA call all use this form, so they can never disagree about which node is meant."""
    try:
        return str(ua.NodeId.from_string(node_id).to_string())
    except Exception as e:  # asyncua raises several types for bad NodeId strings
        raise ValueError(f"invalid NodeId {node_id!r}: {e}") from e


# Floor for min_interval_s on stepped tags: longer than a typical PLC scan + read-back.
MIN_STEP_INTERVAL_S = 1.0


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SecurityMode(StrEnum):
    NONE = "None"
    SIGN = "Sign"
    SIGN_AND_ENCRYPT = "SignAndEncrypt"


class AuthConfig(_Strict):
    """Secrets are never stored here: only the names of env vars or files holding them."""

    kind: Literal["anonymous", "username", "certificate"] = "anonymous"
    username_env: str | None = None
    password_env: str | None = None
    client_cert_file: Path | None = None
    client_key_file: Path | None = None

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.kind == "username" and not (self.username_env and self.password_env):
            raise ValueError("auth.kind=username requires username_env and password_env")
        if self.kind == "certificate" and not (self.client_cert_file and self.client_key_file):
            raise ValueError("auth.kind=certificate requires client_cert_file and client_key_file")
        return self

    def credentials(self) -> tuple[str, str]:
        assert self.username_env and self.password_env
        user, pw = os.environ.get(self.username_env), os.environ.get(self.password_env)
        if not user or not pw:
            raise ValueError(f"env vars {self.username_env}/{self.password_env} must be set")
        return user, pw


class ConnectionConfig(_Strict):
    endpoint: str = Field(pattern=r"^opc\.tcp://")
    security_mode: SecurityMode = SecurityMode.SIGN_AND_ENCRYPT
    security_policy: Literal["Basic256Sha256", "Aes128_Sha256_RsaOaep", "Aes256_Sha256_RsaPss"] = (
        "Basic256Sha256"
    )
    server_cert_file: Path | None = None
    auth: AuthConfig = AuthConfig()
    # Security mode None and anonymous auth are for the simulator only; both need this flag.
    allow_insecure: bool = False
    timeout_s: float = Field(default=4.0, gt=0, le=60)

    @model_validator(mode="after")
    def _check(self) -> Self:
        insecure = self.security_mode is SecurityMode.NONE or self.auth.kind == "anonymous"
        if insecure and not self.allow_insecure:
            raise ValueError(
                "security_mode=None or anonymous auth requires allow_insecure: true (sim only)"
            )
        if self.security_mode is not SecurityMode.NONE and self.server_cert_file is None:
            raise ValueError("server_cert_file is required: unknown server certs are rejected")
        return self


class TagRule(_Strict):
    """Constraints for writable tags. `pattern` is a NodeId or fnmatch glob."""

    pattern: str = Field(min_length=1)
    # Exact NodeId match by default. `glob: true` enables fnmatch ([...] and * are special).
    glob: bool = False
    type: Literal["bool", "int", "float", "str"]
    min: float | None = None
    max: float | None = None
    allowed: list[bool | int | float | str] | None = None
    # Largest allowed |new - current| for a single write (numeric tags).
    max_rate_of_change: float | None = Field(default=None, gt=0)
    min_interval_s: float = Field(default=0.0, ge=0)

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.min is not None and self.max is not None and self.min > self.max:
            raise ValueError(f"{self.pattern}: min > max")
        if self.type in ("bool", "str") and (
            self.min is not None or self.max is not None or self.max_rate_of_change is not None
        ):
            raise ValueError(f"{self.pattern}: numeric constraints on a {self.type} tag")
        if not self.glob and canonical_node_id(self.pattern) != self.pattern:
            raise ValueError(
                f"{self.pattern}: write it as {canonical_node_id(self.pattern)!r} (canonical form)"
            )
        if self.max_rate_of_change is not None and self.min_interval_s < MIN_STEP_INTERVAL_S:
            # Otherwise steps can stack before the PLC applies the last one (stale read-back).
            raise ValueError(
                f"{self.pattern}: max_rate_of_change needs min_interval_s >= {MIN_STEP_INTERVAL_S}"
            )
        return self


class WritesConfig(_Strict):
    enabled: bool = False
    require_human: bool = False
    token_ttl_s: float = Field(default=30.0, gt=0, le=600)
    kill_switch_file: Path | None = None
    kill_switch_env: str = "MCP_OPCUA_KILL"
    approvals_dir: Path = Path(".mcp-opcua/approvals")
    tags: list[TagRule] = []

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.enabled and not self.tags:
            raise ValueError("writes.enabled=true with an empty allowlist")
        if self.enabled and self.kill_switch_file is None:
            raise ValueError("writes.enabled=true requires kill_switch_file (runtime kill switch)")
        return self


class AuditConfig(_Strict):
    path: Path = Path("audit.jsonl")
    hash_chain: bool = True


class SubscriptionConfig(_Strict):
    max_buffer: int = Field(default=1000, ge=1, le=100_000)
    min_sampling_ms: int = Field(default=100, ge=10)
    max_subscriptions: int = Field(default=16, ge=1, le=256)


class Config(_Strict):
    connection: ConnectionConfig
    writes: WritesConfig = WritesConfig()
    audit: AuditConfig = AuditConfig()
    subscriptions: SubscriptionConfig = SubscriptionConfig()
    browse_max_depth: int = Field(default=3, ge=1, le=10)
    browse_max_nodes: int = Field(default=500, ge=1, le=10_000)

    @model_validator(mode="after")
    def _check(self) -> Self:
        host = urlparse(self.connection.endpoint).hostname or ""
        if self.connection.allow_insecure and self.writes.enabled and host not in _SIM_HOSTS:
            raise ValueError(
                f"allow_insecure with writes.enabled is only allowed for the simulator "
                f"({', '.join(sorted(_SIM_HOSTS))}), not {host!r}"
            )
        return self


_SIM_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "sim"})


def load_config(path: Path) -> Config:
    """Load and validate. Relative paths resolve against the config file's directory, never
    the process CWD (MCP hosts launch servers from arbitrary directories)."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a mapping at top level")
    cfg = Config.model_validate(data)
    base = path.resolve().parent

    def fix(p: Path | None) -> Path | None:
        if p is None:
            return None
        p = p.expanduser()
        return p if p.is_absolute() else (base / p).resolve()

    w, a, c = cfg.writes, cfg.audit, cfg.connection
    auth = c.auth.model_copy(
        update={
            "client_cert_file": fix(c.auth.client_cert_file),
            "client_key_file": fix(c.auth.client_key_file),
        }
    )
    return cfg.model_copy(
        update={
            "writes": w.model_copy(
                update={
                    "kill_switch_file": fix(w.kill_switch_file),
                    "approvals_dir": fix(w.approvals_dir),
                }
            ),
            "audit": a.model_copy(update={"path": fix(a.path)}),
            "connection": c.model_copy(
                update={"server_cert_file": fix(c.server_cert_file), "auth": auth}
            ),
        }
    )
