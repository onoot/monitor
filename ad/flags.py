"""Flag detection and flag-flow inference.

Flag patterns are never guessed. Resolution order:

  1. `flag_format.pattern` from config (xeger syntax, as checkers use it)
  2. `known_flags` supplied by the operator
  3. a conservative built-in heuristic, reported as UNCONFIRMED and disabled
     for any automatic poisoning decision

The third source exists only so the tool can tell an operator "no flag pattern
configured, put/get behaviour cannot be verified" instead of silently doing
nothing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .config import Config, FlagFormat

# Conservative: requires a flag-shaped wrapper, so ordinary prose does not match.
HEURISTIC_FLAG = re.compile(
    r"\b[A-Za-z][A-Za-z0-9_]{1,24}\{[^{}]{4,120}\}"
)

XEGER_TOKEN = re.compile(
    r"\{(?P<body>(?:[^{}]|\{[^{}]*\})*)\}"
)


@dataclass
class FlagMatch:
    value: str
    source: str

    @property
    def confirmed(self) -> bool:
        return self.source in {"config_pattern", "known_flag"}

    def to_dict(self) -> dict:
        return {"value": self.value, "source": self.source, "confirmed": self.confirmed}


@dataclass
class FlagFlowNode:
    kind: str
    detail: str
    file: str = ""
    line: int = 0

    def to_dict(self) -> dict:
        return {"kind": self.kind, "detail": self.detail, "file": self.file, "line": self.line}


@dataclass
class FlagFlow:
    pattern_known: bool
    pattern_source: str
    mask: str | None
    prefix: str
    put_points: list[FlagFlowNode] = field(default_factory=list)
    get_points: list[FlagFlowNode] = field(default_factory=list)
    storage_hints: list[FlagFlowNode] = field(default_factory=list)
    exposure_hints: list[FlagFlowNode] = field(default_factory=list)
    observed_checker_reads: list[str] = field(default_factory=list)
    observed_team_reads: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "pattern_known": self.pattern_known,
            "pattern_source": self.pattern_source,
            "mask": self.mask,
            "prefix": self.prefix,
            "put_points": [n.to_dict() for n in self.put_points],
            "get_points": [n.to_dict() for n in self.get_points],
            "storage_hints": [n.to_dict() for n in self.storage_hints],
            "exposure_hints": [n.to_dict() for n in self.exposure_hints],
            "observed_checker_flag_reads": self.observed_checker_reads,
            "observed_team_flag_reads": self.observed_team_reads,
            "warnings": self.warnings,
        }


def detect_flags(blob: str, query: str = "") -> list[str]:
    """Return distinct flag-shaped strings in a payload."""
    if not blob and not query:
        return []
    haystack = f"{blob}\n{query}"
    found: list[str] = []
    seen: set[str] = set()
    for match in HEURISTIC_FLAG.finditer(haystack):
        value = match.group(0)
        if value not in seen:
            seen.add(value)
            found.append(value)
    return found


# Characters that mean the pattern is not plain xeger output but embedded
# regex. Escaping those silently would produce a regex that matches the wrong
# strings, so we refuse the pattern instead.
UNSUPPORTED_LITERAL = re.compile(r"[\\|()]|\(\?")

# Character class body we accept from a checker pattern: ranges, digits and `_`.
CLASS_BODY = re.compile(r"^(?:[a-zA-Z0-9]|[a-zA-Z0-9]-[a-zA-Z0-9]|_)+$")

CLASS_TOKEN = re.compile(
    r"\[(?P<chars>[^\]\n]*)\](?P<quant>\{\d+(?:,\d*)?\})?"
)


def _class_body(chars: str) -> str | None:
    """Validate a bracketed character class and return its body, or None."""
    if not chars or not CLASS_BODY.match(chars):
        return None
    # A trailing dash would denote an open-ended range, which we refuse.
    if chars.endswith("-"):
        return None
    return chars


def _quantifier(quant: str | None) -> int | None:
    if not quant:
        return 1
    inner = quant.strip("{}")
    if "," in inner:
        low, _, _high = inner.partition(",")
        return int(low)
    return int(inner)


def xeger_tokens(pattern: str) -> list[tuple[str, str, int | None]] | None:
    """Split a pattern into ('lit', text, None) and ('class', body, width) items.

    Returns None when the pattern uses anything outside the subset checkers
    actually emit, so callers can refuse instead of producing a wrong regex.
    """
    items: list[tuple[str, str, int | None]] = []
    pos = 0
    for match in CLASS_TOKEN.finditer(pattern):
        literal = pattern[pos : match.start()]
        if literal:
            if UNSUPPORTED_LITERAL.search(literal):
                return None
            items.append(("lit", literal, None))
        body = _class_body(match.group("chars"))
        width = _quantifier(match.group("quant"))
        if body is None or width is None:
            return None
        items.append(("class", body, width))
        pos = match.end()
    tail = pattern[pos:]
    if tail:
        if UNSUPPORTED_LITERAL.search(tail):
            return None
        items.append(("lit", tail, None))
    return items


def xeger_to_regex(pattern: str) -> re.Pattern[str] | None:
    """Translate the restricted xeger subset checkers use into a regex."""
    items = xeger_tokens(pattern)
    if items is None:
        return None
    out: list[str] = []
    for kind, value, width in items:
        if kind == "lit":
            out.append(re.escape(value))
        else:
            body = f"[{value}]"
            out.append(body if width == 1 else f"{body}{{{width}}}")
    try:
        return re.compile("^" + "".join(out) + "$")
    except re.error:
        return None


def split_envelope(pattern: str) -> tuple[str, str]:
    """Return the literal (prefix, suffix) around the variable part of a pattern.

    Poisoning replaces only the variable span, so `alctf{[a-z]{16}}` keeps its
    `alctf{` and `}` and only the middle 16 characters change.
    """
    items = xeger_tokens(pattern)
    if not items:
        return "", ""
    prefix = items[0][1] if items[0][0] == "lit" else ""
    suffix = items[-1][1] if items[-1][0] == "lit" and len(items) > 1 else ""
    return prefix, suffix


def _quantifier(quant: str | None) -> int | None:
    if not quant:
        return 1
    inner = quant.strip("{}")
    if "," in inner:
        low, _, _high = inner.partition(",")
        return int(low)
    return int(inner)


def detect_known(blob: str, cfg: Config | None = None, known: list[str] | None = None) -> list[FlagMatch]:
    """Detect flags using configured sources only (no heuristic)."""
    if not blob:
        return []
    known_list = known if known is not None else (cfg.known_flags if cfg else [])
    matches: list[FlagMatch] = []
    seen: set[str] = set()

    if cfg and cfg.flag_format.known:
        regex = xeger_to_regex(cfg.flag_format.pattern)
        if regex:
            for value in regex.findall(blob):
                if value not in seen:
                    seen.add(value)
                    matches.append(FlagMatch(value=value, source="config_pattern"))

    for value in known_list:
        if value and value in blob and value not in seen:
            seen.add(value)
            matches.append(FlagMatch(value=value, source="known_flag"))

    return matches


def _node(kind: str, detail: str, file: str = "", line: int = 0) -> FlagFlowNode:
    return FlagFlowNode(kind=kind, detail=detail, file=file, line=line)


def infer_flow(
    cfg: Config,
    source_texts: dict[str, str],
    runtime_routes: dict[str, list[dict]],
) -> FlagFlow:
    """Infer where flags are written, read, stored and potentially exposed."""
    pattern_known = cfg.flag_format.known or bool(cfg.known_flags)
    if cfg.flag_format.known:
        source = "config_pattern"
    elif cfg.known_flags:
        source = "known_flag"
    else:
        source = "unconfirmed_heuristic"

    flow = FlagFlow(
        pattern_known=pattern_known,
        pattern_source=source,
        mask=cfg.flag_format.literal_mask(),
        prefix=cfg.flag_format.prefix,
    )

    if not pattern_known:
        flow.warnings.append(
            "No flag pattern configured. Flag put/get verification is unavailable and "
            "poisoning stays disabled. Set flag_format.pattern (xeger syntax) or "
            "known_flags in the service config."
        )

    write_hints = re.compile(
        r"(?i)\b(?:set_?flag|put_?flag|save_?flag|create_?flag|insert_?flag|add_?flag|"
        r"write_?flag|flags?\s*=\s*request|flags?\s*=\s*params|notes?form|"
        r"flag.*(?:insert|update|create|save))\b"
    )
    read_hints = re.compile(
        r"(?i)\b(?:get_?flag|read_?flag|find_?flag|fetch_?flag|load_?flag|show_?flag|"
        r"flag.*(?:select|find|read|open)|/flags?\b)\b"
    )
    storage_hints = re.compile(
        r"(?i)(?:/flag(?:s)?\b|flag\.txt|readFile|open\(|yaml\.dump|json\.dump|"
        r"INSERT\s+INTO\s+\w*flag|UPDATE\s+\w*flag|flags?\s*[:=]\s*self\.)"
    )

    for rel, text in source_texts.items():
        lines = text.splitlines()
        for index, line in enumerate(lines, start=1):
            trimmed = line.strip()
            if not trimmed or len(trimmed) < 4:
                continue
            if write_hints.search(line):
                flow.put_points.append(_node("put_candidate", trimmed[:200], rel, index))
            if read_hints.search(line):
                flow.get_points.append(_node("get_candidate", trimmed[:200], rel, index))
            if storage_hints.search(line):
                flow.storage_hints.append(_node("storage", trimmed[:200], rel, index))
            if re.search(r"(?i)(?:innerHTML|safe\b|jsonify|res\.send|echo\s+\$|v-html)", line) and re.search(
                r"(?i)flag", line
            ):
                flow.exposure_hints.append(_node("exposure", trimmed[:200], rel, index))

    for route in runtime_routes.get("__all__", []):
        key = f"{route.get('method', '?')} {route.get('path', '?')}"
        if re.search(r"(?i)flag", key):
            flow.exposure_hints.append(_node("route_named_flag", key))

    if not flow.put_points:
        flow.warnings.append("No flag write path identified in source; confirm the put flow manually.")
    if not flow.get_points:
        flow.warnings.append("No flag read path identified in source; confirm the get flow manually.")

    return flow