"""Configuration for the A/D toolkit.

Everything the tool treats as ground truth comes from a config file, never
from guessing. Unknown values stay unknown.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class TeamNetwork:
    """One team's isolated instance."""

    label: str
    cidr: str
    source: str

    def contains(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(self.cidr, strict=False)
        except ValueError:
            return False


@dataclass(frozen=True)
class FlagFormat:
    """Pattern + charset used for partial poisoning."""

    pattern: str
    prefix: str = ""
    suffix: str = ""
    body_alphabet: str = ""
    min_length: int = 0

    @property
    def known(self) -> bool:
        return bool(self.pattern)

    def literal_mask(self) -> str | None:
        """Convert an xeger-style pattern into a literal template.

        ``alctf{[a-z0-9_]{16}}`` -> ``alctf{________________}``. Returns None when
        the pattern contains constructs we cannot express as a mask.
        """
        if not self.pattern:
            return None
        from .flags import xeger_tokens

        items = xeger_tokens(self.pattern)
        if items is None:
            return None
        out: list[str] = []
        for kind, value, width in items:
            if kind == "lit":
                out.append(value)
            else:
                filler = "_" if "_" in value else "a"
                out.append(filler * (width or 1))
        return "".join(out)


DEFAULT_EXCLUDED_GLOBS = [
    "**/node_modules/**",
    "**/vendor/**",
    "**/.git/**",
    "**/__pycache__/**",
    "**/dist/**",
    "**/build/**",
    "**/storage/framework/**",
    "**/*.min.js",
    "**/*.min.css",
    "**/composer.lock",
    "**/package-lock.json",
    "**/yarn.lock",
]


@dataclass
class Config:
    service_name: str
    source_roots: list[Path] = field(default_factory=list)
    excluded_globs: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDED_GLOBS))
    # Explicit team networks. `unknown` is never a checker.
    team_networks: list[TeamNetwork] = field(default_factory=list)
    checker_networks: list[TeamNetwork] = field(default_factory=list)
    checker_ip_pattern: str = ""
    # Literal flag values observed for this service, if the operator supplied them.
    known_flags: list[str] = field(default_factory=list)
    flag_format: FlagFormat = field(default_factory=lambda: FlagFormat(pattern=""))
    # Runtime capture files (JSONL / JSON arrays / access logs).
    request_logs: list[Path] = field(default_factory=list)
    output_dir: Path = Path("reports")
    notes: str = ""

    def classify_ip(self, ip: str) -> str:
        """Return 'checker', 'team' or 'unknown'.

        Precedence matters: an explicit team list wins over inference so that a
        mis-detected checker subnet can never cause the checker to be poisoned.
        """
        for net in self.team_networks:
            if net.contains(ip):
                return "team"
        for net in self.checker_networks:
            if net.contains(ip):
                return "checker"
        return "unknown"

    @property
    def has_flag_format(self) -> bool:
        return self.flag_format.known


def _parse_networks(raw: Any, source: str) -> list[TeamNetwork]:
    nets: list[TeamNetwork] = []
    for item in raw or []:
        if isinstance(item, str):
            cidr, label = item, item
        else:
            cidr = item["cidr"]
            label = item.get("label", cidr)
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ConfigError(f"bad cidr {cidr!r}: {exc}") from exc
        nets.append(TeamNetwork(label=label, cidr=cidr, source=source))
    return nets


def _parse_flag_format(raw: dict[str, Any] | None) -> FlagFormat:
    if not raw:
        return FlagFormat(pattern="")
    pattern = raw.get("pattern", "")
    prefix = raw.get("prefix", "")
    suffix = raw.get("suffix", "")
    if not prefix and "{" in pattern:
        prefix = pattern.split("{", 1)[0]
    body = raw.get("body_alphabet", "")
    return FlagFormat(
        pattern=pattern,
        prefix=prefix,
        suffix=suffix,
        body_alphabet=body,
        min_length=int(raw.get("min_length", 0)),
    )


def load_config(path: Path) -> Config:
    # utf-8-sig: operators edit these in Notepad/VS Code, which may add a BOM.
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    base = path.parent
    roots = []
    for raw in data.get("source_roots", ["."]):
        root = (base / raw).resolve()
        if not root.exists():
            raise ConfigError(f"source root does not exist: {root}")
        roots.append(root)

    logs = []
    for raw in data.get("request_logs", []):
        candidate = (base / raw).resolve()
        if candidate.exists():
            logs.append(candidate)
        elif "*" in raw:
            logs.extend(sorted(base.glob(raw)))

    service = data.get("service_name") or path.parent.name
    out = Path(data.get("output_dir", "reports"))
    if not out.is_absolute():
        out = (base / out).resolve()

    return Config(
        service_name=service,
        source_roots=roots,
        excluded_globs=data.get("excluded_globs", DEFAULT_EXCLUDED_GLOBS),
        team_networks=_parse_networks(data.get("team_networks"), "config"),
        checker_networks=_parse_networks(data.get("checker_networks"), "config"),
        checker_ip_pattern=data.get("checker_ip_pattern", ""),
        known_flags=list(data.get("known_flags", [])),
        flag_format=_parse_flag_format(data.get("flag_format")),
        request_logs=logs,
        output_dir=out,
        notes=data.get("notes", ""),
    )