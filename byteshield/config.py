"""Runtime settings and YAML loading."""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class UpstreamConfig:
    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)


@dataclass
class Settings:
    root: Path = ROOT
    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("BYTESHIELD_DATA", ROOT / "data")))
    servers_file: Path = field(default_factory=lambda: Path(os.environ.get("BYTESHIELD_SERVERS", ROOT / "config" / "servers.yaml")))
    policy_file: Path = field(default_factory=lambda: Path(os.environ.get("BYTESHIELD_POLICY", ROOT / "config" / "policy.yaml")))
    dashboard_dir: Path = field(default_factory=lambda: ROOT / "dashboard" / "dist")
    demo_mode: bool = field(default_factory=lambda: os.environ.get("BYTESHIELD_DEMO", "1") == "1")
    admin_token: str | None = field(default_factory=lambda: os.environ.get("BYTESHIELD_ADMIN_TOKEN") or None)
    mode_override: str | None = field(default_factory=lambda: os.environ.get("BYTESHIELD_MODE") or None)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "byteshield.db"

    def load_policy(self) -> dict[str, Any]:
        with open(self.policy_file, "r", encoding="utf-8") as fh:
            policy = yaml.safe_load(fh) or {}
        if self.mode_override:
            policy["mode"] = self.mode_override
        return policy

    def load_upstreams(self) -> list[UpstreamConfig]:
        with open(self.servers_file, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        upstreams: list[UpstreamConfig] = []
        for item in raw.get("servers", []):
            command = str(item["command"]).replace("{python}", sys.executable)
            args = [str(a).replace("{root}", str(self.root)) for a in item.get("args", [])]
            env = {"BYTESHIELD_DATA": str(self.data_dir)}
            env.update({str(k): str(v) for k, v in (item.get("env") or {}).items()})
            upstreams.append(UpstreamConfig(name=item["name"], command=command, args=args, env=env))
        return upstreams
