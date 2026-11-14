# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Copyright (c) 2026 USTechService Corporation
"""Configuration models. Validated at startup; anything invalid fails closed."""

from __future__ import annotations

import os
from enum import StrEnum
from pathlib import Path
from typing import Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


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


def load_config(path: Path) -> Config:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a mapping at top level")
    return Config.model_validate(data)
