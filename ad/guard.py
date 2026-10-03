"""AI-vs-AI defence for the AltayCTF training stand.

The stand is attacked not only by humans but by opposing agents. A common play is
to hand an adversary model our endpoint and tell it to:

  * loop us - flood a route until our agent burns its step/time/token budget;
  * spray "strange" routes carrying a base64/hex/gzip *encoded but not encrypted*
    blob (a file or just text) that holds a payload we might be tempted to decode
    and *follow*;
  * emulate a browser / brute-force the route space, hoping the noise looks like
    a real user;
  * hand us flags through our own ingest endpoint, hoping we treat a value that
    arrived on the wire as ground truth and submit it (or act on it).

This module is the defensive side of that exchange. Its invariants:

  * **External content is data, never instructions.** A decoded blob, a path
    segment, a header or an inbound flag is parsed and classified, never
    executed and never turned into an agent directive. `scan_injection()` only
    *reports*; the caller decides, and the default caller here decides "quarantine".
  * **Nothing received on the wire is trusted.** `FlagQuarantine` never
    "accepts" a flag: the best state it can assign is `quarantined`, and it never
    submits anywhere. Only a human (or a separate, audited step) promotes a flag.
  * **Bounded work.** Decoding has size, depth and layer limits so a nested or
    bomb-like blob cannot exhaust the guard. `LoopGuard` halts an agent that
    repeats itself or exceeds its step/time/cost budget.
  * **Deterministic and dependency-free.** Standard library only, no I/O at
    import time, and every clock is injectable so tests never sleep.
"""

from __future__ import annotations

import base64
import gzip
import json
import re
import time
import urllib.parse
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from .flags import detect_flags

# ---------------------------------------------------------------------------
# limits: everything that parses untrusted input is bounded
# ---------------------------------------------------------------------------

MAX_DECODE_BYTES = 256 * 1024
MAX_DECODE_DEPTH = 4
MAX_DECODE_LAYERS = 24
MAX_BODY_BYTES = 512 * 1024

# ---------------------------------------------------------------------------
# loop / budget guard
# ---------------------------------------------------------------------------


@dataclass
class GuardDecision:
    allowed: bool
    halted: bool
    reason: str
    step: int
    elapsed: float
    cost: float

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "halted": self.halted,
            "reason": self.reason,
            "step": self.step,
            "elapsed": round(self.elapsed, 4),
            "cost": round(self.cost, 4),
        }


class LoopGuard:
    """Stop an agent loop before it wastes a budget.

    Halts on the first of: step budget, wall-clock budget, cost budget, a single
    action repeated too often, or a short action cycle (A,B,A,B,...). A halt is
    sticky: once halted, every later `step()` stays halted.
    """

    def __init__(
        self,
        max_steps: int = 200,
        max_seconds: float = 900.0,
        max_cost: float = float("inf"),
        max_duplicate_actions: int = 5,
        max_period: int = 8,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.max_steps = max_steps
        self.max_seconds = max_seconds
        self.max_cost = max_cost
        self.max_duplicate_actions = max_duplicate_actions
        self.max_period = max_period
        self._clock = clock or time.monotonic
        self._start = self._clock()
        self._steps = 0
        self._cost = 0.0
        self._counts: dict[str, int] = {}
        self._history: list[str] = []
        self._halted = False
        self._reason = ""

    def step(self, action_key: str, cost: float = 0.0, now: float | None = None) -> GuardDecision:
        now = self._clock() if now is None else now
        if self._halted:
            return self._decision(False, self._reason, now)

        self._steps += 1
        self._cost += max(0.0, cost)
        self._history.append(action_key)
        self._counts[action_key] = self._counts.get(action_key, 0) + 1

        reason = ""
        if self._steps > self.max_steps:
            reason = "step_budget"
        elif now - self._start > self.max_seconds:
            reason = "time_budget"
        elif self._cost > self.max_cost:
            reason = "cost_budget"
        elif self._counts[action_key] > self.max_duplicate_actions:
            reason = "duplicate_loop"
        elif self._detect_cycle():
            reason = "action_cycle"

        if reason:
            self._halted = True
            self._reason = reason
        return self._decision(not reason, reason, now)

    def _detect_cycle(self) -> bool:
        history = self._history
        for period in range(2, min(self.max_period, len(history) // 2) + 1):
            tail = history[-2 * period :]
            if tail[:period] == tail[period:]:
                return True
        return False

    def _decision(self, allowed: bool, reason: str, now: float) -> GuardDecision:
        return GuardDecision(
            allowed=allowed,
            halted=self._halted,
            reason=reason or self._reason,
            step=self._steps,
            elapsed=now - self._start,
            cost=self._cost,
        )


# ---------------------------------------------------------------------------
# encoded-payload decoding (encoded is not encrypted)
# ---------------------------------------------------------------------------


@dataclass
class DecodedLayer:
    encoding: str
    depth: int
    origin: str
    text: str
    size: int
    score: float

    def to_dict(self) -> dict:
        return {
            "encoding": self.encoding,
            "depth": self.depth,
            "origin": self.origin,
            "size": self.size,
            "score": round(self.score, 3),
            "text": self.text[:4000],
        }


def _text_score(data: bytes) -> float:
    """Fraction of bytes that look like text (ASCII printable, whitespace, utf-8)."""
    if not data:
        return 0.0
    good = sum(1 for b in data if 0x20 <= b < 0x7F or b in (9, 10, 13) or b >= 0x80)
    return good / len(data)


def _render(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", "replace")


_B64_CHARS = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_B64_URL_CHARS = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
_B32_CHARS = re.compile(r"^[A-Z2-7]+=*$")
_HEX_CHARS = re.compile(r"^(?:[0-9a-fA-F]{2})+$")


def _candidates_whole(text: str) -> list[tuple[str, bytes]]:
    """Return plausible (encoding, decoded) pairs for one text blob."""
    out: list[tuple[str, bytes]] = []
    stripped = text.strip()

    if 8 <= len(stripped) <= MAX_DECODE_BYTES and _HEX_CHARS.fullmatch(stripped):
        try:
            out.append(("hex", bytes.fromhex(stripped)))
        except ValueError:
            pass

    compact = re.sub(r"\s+", "", stripped)
    # Plain lowercase prose is valid base64 by accident; require a coded-looking
    # character (digit, '+', '/', '=' or an uppercase letter) before trying.
    if 16 <= len(compact) <= MAX_DECODE_BYTES and re.search(r"[0-9+/=]|[A-Z]", compact):
        padded = compact + "=" * (-len(compact) % 4)
        if _B64_CHARS.fullmatch(padded):
            try:
                decoded = base64.b64decode(padded, validate=True)
                if decoded:
                    out.append(("base64", decoded))
            except (ValueError, base64.binascii.Error):
                pass
        urlsafe = compact.replace("-", "+").replace("_", "/")
        urlsafe_padded = urlsafe + "=" * (-len(urlsafe) % 4)
        if "-" in compact or "_" in compact:
            try:
                decoded = base64.b64decode(urlsafe_padded, validate=True)
                if decoded:
                    out.append(("base64url", decoded))
            except (ValueError, base64.binascii.Error):
                pass

    upper = re.sub(r"\s+", "", stripped)
    if 8 <= len(upper) <= MAX_DECODE_BYTES and _B32_CHARS.fullmatch(upper):
        try:
            padded = upper + "=" * (-len(upper) % 8)
            decoded = base64.b32decode(padded)
            if decoded:
                out.append(("base32", decoded))
        except (ValueError, base64.binascii.Error):
            pass

    if "%" in text:
        unquoted = urllib.parse.unquote_plus(text)
        if unquoted != text:
            out.append(("url", unquoted.encode("utf-8", "replace")))

    raw = text.encode("latin-1", "ignore")
    if raw[:2] == b"\x1f\x8b":
        try:
            out.append(("gzip", gzip.decompress(raw)))
        except OSError:
            pass
    elif len(raw) >= 2 and raw[0] == 0x78:
        try:
            out.append(("zlib", zlib.decompress(raw)))
        except zlib.error:
            pass

    return out


_CODED_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{16,}")


def _candidates(text: str) -> list[tuple[str, bytes]]:
    """Whole blob plus encoded-looking tokens embedded in a wrapper (e.g. JSON)."""
    out: list[tuple[str, bytes]] = []
    seen: set[tuple[str, bytes]] = set()

    def absorb(pairs: list[tuple[str, bytes]]) -> None:
        for encoding, decoded in pairs:
            key = (encoding, decoded)
            if key not in seen:
                seen.add(key)
                out.append((encoding, decoded))

    absorb(_candidates_whole(text))
    stripped = text.strip()
    for token in _CODED_TOKEN.findall(text):
        if token != stripped:
            absorb(_candidates_whole(token))
    return out


def decode_payloads(
    blob: bytes | str,
    origin: str = "body",
    max_depth: int = MAX_DECODE_DEPTH,
    max_layers: int = MAX_DECODE_LAYERS,
) -> list[DecodedLayer]:
    """Recursively decode encoded-but-not-encrypted layers, bounded and deduped.

    Only layers whose bytes decode cleanly are returned; the guard never guesses
    and never executes the result. Depth and total layer count are capped so a
    nested blob degenerates into a short list instead of an infinite descent.
    """
    layers: list[DecodedLayer] = []
    seen: set[tuple[str, str]] = set()

    def walk(raw: bytes, depth: int) -> None:
        if depth > max_depth or len(layers) >= max_layers:
            return
        text = _render(raw)
        for encoding, decoded in _candidates(text):
            if len(decoded) > MAX_DECODE_BYTES or decoded == raw:
                continue
            score = _text_score(decoded)
            if encoding in {"hex", "base32"} and score < 0.7:
                continue
            if encoding in {"base64", "base64url"} and score < 0.75:
                continue
            rendered = _render(decoded)
            key = (encoding, rendered)
            if key in seen:
                continue
            seen.add(key)
            layers.append(
                DecodedLayer(
                    encoding=encoding,
                    depth=depth,
                    origin=origin,
                    text=rendered,
                    size=len(decoded),
                    score=score,
                )
            )
            if len(layers) >= max_layers:
                return
            walk(decoded, depth + 1)

    if isinstance(blob, str):
        walk(blob.encode("utf-8", "surrogatepass"), 0)
    else:
        walk(blob, 0)
    return layers


# ---------------------------------------------------------------------------
# prompt-injection / instruction-smuggling scanner (reports, never executes)
# ---------------------------------------------------------------------------

INJECTION_PATTERNS: tuple[tuple[str, str], ...] = (
    ("instruction_override", r"(?i)\b(ignore|disregard|forget)\b[^\n]{0,40}\b(previous|prior|above|all)\b[^\n]{0,20}\b(instruction|prompt|rule|message)s?\b"),
    ("instruction_override", r"(?i)\b(игнорир\w*|забудь|не\s+обращай\s+внимания)\b[^\n]{0,40}\b(предыдущ|инструкц|правил|промпт|указани)"),
    ("instruction_override", r"(?i)\b(новые|следующие|вот)\s+инструкц"),
    ("role_impersonation", r"(?i)(^|\n)\s*(system|assistant|developer|tool|assistant)\s*[:>]"),
    ("role_impersonation", r"(?i)\byou are now\b|\bact as\b[^\n]{0,30}\b(system|admin|root|developer)\b"),
    ("role_impersonation", r"(?i)\bты\s+теперь\b|\bдействуй\s+как\b"),
    ("tool_invocation", r"(?i)<\s*/?\s*(tool_call|function_call|tool_use|invoke|function)\b"),
    ("tool_invocation", r"(?i)\b(run|execute|call|выполн\w*|запусти)\b[^\n]{0,24}\b(shell|bash|cmd|powershell|exec|команд)"),
    ("exfiltration", r"(?i)\b(curl|wget|fetch|scp)\b[^\n]{0,80}(https?://|/api/|token|secret|flag|ключ)"),
    ("exfiltration", r"(?i)\b(exfiltrate|upload|send|post|отправ\w*|передай)\b[^\n]{0,60}\b(flag|secret|token|key|флаг|секрет|токен|ключ)\b"),
    ("delimiter_break", r"(?i)(```|~~~)\s*(end|system|input|user|assistant)\b"),
    ("delimiter_break", r"(?i)\[/?\s*(instruction|system|prompt|tool|assistant)\s*\]"),
)
_INJECTION = tuple((category, re.compile(pattern)) for category, pattern in INJECTION_PATTERNS)


@dataclass
class InjectionHit:
    category: str
    pattern: str
    excerpt: str

    def to_dict(self) -> dict:
        return {"category": self.category, "pattern": self.pattern, "excerpt": self.excerpt}


def scan_injection(text: str) -> list[InjectionHit]:
    """Report instruction-smuggling markers. Never returns a decision to execute."""
    if not text:
        return []
    hits: list[InjectionHit] = []
    for category, regex in _INJECTION:
        for match in regex.finditer(text):
            excerpt = match.group(0).strip()
            hits.append(InjectionHit(category=category, pattern=regex.pattern, excerpt=excerpt[:200]))
    return hits


# ---------------------------------------------------------------------------
# scanner / browser-emulation detector
# ---------------------------------------------------------------------------

HEADLESS_MARKERS = re.compile(
    r"(?i)(headlesschrome|playwright|puppeteer|selenium|phantomjs|htmlunit|"
    r"python-requests|python-urllib|aiohttp|httpx|scrapy|"
    r"go-http-client|okhttp|libwww-perl|java/|apache-httpclient|"
    r"curl/|wget/|axios/|node-fetch|undici|got\s*\(|postmanruntime|insomnia)"
)

_ENCODED_SEGMENT = re.compile(r"^[A-Za-z0-9+/=_.-]{16,}$")
_HEX_SEGMENT = re.compile(r"^[0-9a-fA-F]{16,}$")


@dataclass
class ScanSignal:
    client: str
    kind: str
    detail: str
    count: int = 0
    window_s: float = 0.0

    def to_dict(self) -> dict:
        return {
            "client": self.client,
            "kind": self.kind,
            "detail": self.detail,
            "count": self.count,
            "window_s": round(self.window_s, 2),
        }


def looks_encoded_segment(segment: str) -> bool:
    """True when a single path/query segment looks like an encoded blob."""
    if len(segment) < 16 or not _ENCODED_SEGMENT.fullmatch(segment):
        return False
    if _HEX_SEGMENT.fullmatch(segment) and len(segment) % 2 == 0:
        return True
    core = segment.replace("-", "+").replace("_", "/").rstrip("=")
    padded = core + "=" * (-len(core) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True)
    except (ValueError, base64.binascii.Error):
        return False
    return bool(decoded) and _text_score(decoded) >= 0.75


class ScannerDetector:
    """Sliding-window signals for automated enumeration / browser emulation.

    Reports only; it never blocks. Signals fire at most once per (client, kind)
    so a single adversary cannot flood the operator's log.
    """

    def __init__(
        self,
        window_s: float = 10.0,
        enum_threshold: int = 20,
        not_found_ratio: float = 0.6,
        min_samples: int = 8,
        timing_cv: float = 0.15,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.window_s = window_s
        self.enum_threshold = enum_threshold
        self.not_found_ratio = not_found_ratio
        self.min_samples = min_samples
        self.timing_cv = timing_cv
        self._clock = clock or time.monotonic
        self._events: dict[str, list[tuple[float, str, int, str, str]]] = {}
        self._signals: list[ScanSignal] = []
        self._fired: set[tuple[str, str]] = set()

    def observe(
        self,
        client: str,
        path: str,
        method: str = "GET",
        status: int = 0,
        user_agent: str = "",
        now: float | None = None,
    ) -> list[ScanSignal]:
        now = self._clock() if now is None else now
        events = self._events.setdefault(client, [])
        events.append((now, path, status, method, user_agent))
        self._prune(client, now)
        before = len(self._signals)
        self._evaluate(client, now)
        return self._signals[before:]

    def _prune(self, client: str, now: float) -> None:
        cutoff = now - self.window_s
        self._events[client] = [event for event in self._events[client] if event[0] >= cutoff]

    def _evaluate(self, client: str, now: float) -> None:
        events = self._events[client]
        if not events:
            return
        paths = [event[1] for event in events]
        distinct = set(paths)

        if len(distinct) >= self.enum_threshold:
            self._fire(client, "path_enumeration", f"{len(distinct)} distinct paths in window", len(distinct))

        if len(events) >= self.min_samples:
            not_found = sum(1 for event in events if event[2] == 404)
            ratio = not_found / len(events)
            if ratio >= self.not_found_ratio:
                self._fire(client, "not_found_sweep", f"{ratio:.0%} of requests returned 404", not_found)

        agent = events[-1][4]
        if agent and HEADLESS_MARKERS.search(agent):
            self._fire(client, "automation_user_agent", f"user-agent {agent[:80]}", len(events))

        encoded = [p for p in distinct if any(looks_encoded_segment(seg) for seg in p.split("/") if seg)]
        if encoded:
            self._fire(client, "encoded_path", f"encoded path segment: {sorted(encoded)[0][:120]}", len(encoded))

        if len(events) >= self.min_samples:
            times = sorted(event[0] for event in events)
            intervals = [b - a for a, b in zip(times, times[1:]) if b > a]
            if len(intervals) >= 4:
                mean = sum(intervals) / len(intervals)
                if mean > 0:
                    variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
                    cv = (variance ** 0.5) / mean
                    if cv <= self.timing_cv:
                        self._fire(client, "regular_timing", f"inter-arrival CV={cv:.3f}", len(intervals))

    def _fire(self, client: str, kind: str, detail: str, count: int) -> None:
        key = (client, kind)
        if key in self._fired:
            return
        self._fired.add(key)
        self._signals.append(ScanSignal(client=client, kind=kind, detail=detail, count=count, window_s=self.window_s))

    def signals(self) -> list[ScanSignal]:
        return list(self._signals)

    def drain(self) -> list[ScanSignal]:
        out = list(self._signals)
        self._signals.clear()
        return out


# ---------------------------------------------------------------------------
# inbound request inspection
# ---------------------------------------------------------------------------


@dataclass
class RequestVerdict:
    path: str
    suspicious: list[str] = field(default_factory=list)
    decoded: list[DecodedLayer] = field(default_factory=list)
    injections: list[InjectionHit] = field(default_factory=list)
    embedded_flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "suspicious": self.suspicious,
            "decoded": [layer.to_dict() for layer in self.decoded],
            "injections": [hit.to_dict() for hit in self.injections],
            "embedded_flags": self.embedded_flags,
        }


def inspect_request(
    path: str = "",
    query: str = "",
    body: bytes | str = b"",
    headers: dict[str, str] | None = None,
) -> RequestVerdict:
    """Classify one inbound request. The result is data for the operator/agent."""
    parts: list[bytes | str] = [path, query, body]
    verdict = RequestVerdict(path=path)

    for index, origin in enumerate(("path", "query", "body")):
        blob = parts[index]
        if not blob:
            continue
        text = blob if isinstance(blob, str) else _render(blob[:MAX_BODY_BYTES])
        verdict.decoded.extend(decode_payloads(blob, origin=origin))
        verdict.injections.extend(scan_injection(text))
        verdict.embedded_flags.extend(detect_flags(text))

    # A decoded layer is still untrusted, but its plaintext must be inspected the
    # same way: an instruction or a flag often only appears after decoding.
    for layer in verdict.decoded:
        verdict.injections.extend(scan_injection(layer.text))
        verdict.embedded_flags.extend(detect_flags(layer.text))

    for segment in (path or "").split("/"):
        if segment and looks_encoded_segment(segment):
            verdict.suspicious.append("encoded_path_segment")
            break

    if verdict.decoded:
        verdict.suspicious.append("encoded_payload")
    if verdict.injections:
        verdict.suspicious.append("instruction_smuggling")
    if verdict.embedded_flags:
        verdict.suspicious.append("flag_shaped_string")

    if headers:
        agent = headers.get("user-agent", "") or headers.get("User-Agent", "")
        if agent and HEADLESS_MARKERS.search(agent):
            verdict.suspicious.append("automation_user_agent")

    verdict.suspicious = sorted(set(verdict.suspicious))
    verdict.embedded_flags = sorted(set(verdict.embedded_flags))
    return verdict


# ---------------------------------------------------------------------------
# flag quarantine: an inbound flag is never ground truth
# ---------------------------------------------------------------------------

DEFAULT_FLAG_SHAPE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,31}\{[^{}]{1,256}\}$")


@dataclass
class QuarantinedFlag:
    id: str
    value: str
    source: str
    client: str
    received_utc: str
    format_ok: bool
    trust: str = "untrusted"
    state: str = "quarantined"
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "value": self.value,
            "source": self.source,
            "client": self.client,
            "received_utc": self.received_utc,
            "format_ok": self.format_ok,
            "trust": self.trust,
            "state": self.state,
            "notes": self.notes,
        }


@dataclass
class QuarantineResult:
    state: str  # quarantined | duplicate | rejected | rate_limited
    id: str
    reason: str
    format_ok: bool

    def to_dict(self) -> dict:
        return {"state": self.state, "id": self.id, "reason": self.reason, "format_ok": self.format_ok}


class FlagQuarantine:
    """Hold flags that arrived on the wire, without ever trusting or submitting them.

    States are deliberately weak: `quarantined` is the success case. There is no
    `accepted` state and no submission path. `submit()` cannot promote a value;
    only `pending()` exposes it for a human to review.
    """

    def __init__(
        self,
        flag_regex: re.Pattern[str] | None = None,
        max_per_minute: int = 30,
        min_length: int = 4,
        max_length: int = 512,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.flag_regex = flag_regex
        self.max_per_minute = max_per_minute
        self.min_length = min_length
        self.max_length = max_length
        self._clock = clock or time.time
        self._seen: dict[str, str] = {}
        self._times: dict[str, list[float]] = {}
        self._items: list[QuarantinedFlag] = []
        self._counter = 0

    def _id(self) -> str:
        self._counter += 1
        return f"qf-{self._counter:04d}"

    def _rate_limited(self, client: str, now: float) -> bool:
        window = [t for t in self._times.get(client, []) if t >= now - 60.0]
        self._times[client] = window
        return len(window) >= self.max_per_minute

    def submit(self, value: str, source: str = "wire", client: str = "unknown") -> QuarantineResult:
        now = self._clock()
        value = (value or "").strip()
        if not value:
            return QuarantineResult("rejected", "", "empty value", False)
        if len(value) < self.min_length or len(value) > self.max_length:
            return QuarantineResult("rejected", "", "length outside accepted bounds", False)

        if self._rate_limited(client, now):
            return QuarantineResult("rate_limited", "", f"client {client} exceeded {self.max_per_minute}/min", False)

        if self.flag_regex is not None:
            format_ok = bool(self.flag_regex.match(value))
        else:
            format_ok = bool(DEFAULT_FLAG_SHAPE.match(value))

        if value in self._seen:
            return QuarantineResult("duplicate", self._seen[value], "already quarantined", format_ok)

        flag_id = self._id()
        self._seen[value] = flag_id
        self._times.setdefault(client, []).append(now)
        notes = []
        if self.flag_regex is None:
            notes.append("no configured flag pattern; shape check only, confirm against the checker")
        if not format_ok:
            notes.append("value does not match the configured/known flag shape")
        notes.append("untrusted: arrived from the network, never auto-submitted")
        item = QuarantinedFlag(
            id=flag_id,
            value=value,
            source=source,
            client=client,
            received_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            format_ok=format_ok,
            notes=notes,
        )
        self._items.append(item)
        return QuarantineResult("quarantined", flag_id, "held for review", format_ok)

    def pending(self) -> list[QuarantinedFlag]:
        return list(self._items)

    def to_jsonl(self) -> str:
        return "\n".join(json.dumps(item.to_dict(), ensure_ascii=False) for item in self._items)


# ---------------------------------------------------------------------------
# protected receiver
# ---------------------------------------------------------------------------

INBOUND_ROUTES = {"/flags", "/api/flags", "/api/flags/inbound", "/inbound"}


class GuardServer(ThreadingHTTPServer):
    """Threading HTTP server that carries the guard state as attributes."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, quarantine: FlagQuarantine, detector: ScannerDetector, token: str = ""):
        super().__init__(address, _GuardHandler)
        self.quarantine = quarantine
        self.detector = detector
        self.token = token


class _GuardHandler(BaseHTTPRequestHandler):
    server: GuardServer
    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:  # silence default stderr logging
        return

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return b""
        return self.rfile.read(min(length, MAX_BODY_BYTES)) if length > 0 else b""

    def _client(self) -> str:
        forwarded = self.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0] if self.client_address else "unknown"

    def _authorised(self) -> bool:
        if not self.server.token:
            return True
        return self.headers.get("X-Guard-Token", "") == self.server.token

    def do_POST(self) -> None:
        split = urllib.parse.urlsplit(self.path)
        body = self._read_body()
        client = self._client()
        verdict = inspect_request(
            path=split.path, query=split.query, body=body, headers=dict(self.headers)
        )
        self.server.detector.observe(
            client,
            split.path,
            method="POST",
            status=200,
            user_agent=self.headers.get("User-Agent", ""),
        )

        if split.path in INBOUND_ROUTES:
            value, source = _extract_flag(body, split.query)
            result = self.server.quarantine.submit(value, source=source or "wire", client=client)
            payload = result.to_dict()
            payload["suspicious"] = verdict.suspicious
            payload["decoded_layers"] = len(verdict.decoded)
            payload["injection_hits"] = len(verdict.injections)
            self._send(202, payload)
            return

        # Any other route is untrusted by definition; we observe and refuse to act.
        self._send(202, {"state": "observed", "suspicious": verdict.suspicious, "action": "none"})

    def do_GET(self) -> None:
        split = urllib.parse.urlsplit(self.path)
        if split.path == "/health":
            self._send(200, {"state": "ok"})
            return
        if split.path == "/quarantine":
            if not self._authorised():
                self._send(403, {"error": "forbidden"})
                return
            self._send(200, {"pending": [item.to_dict() for item in self.server.quarantine.pending()]})
            return
        if split.path == "/signals":
            if not self._authorised():
                self._send(403, {"error": "forbidden"})
                return
            self._send(200, {"signals": [s.to_dict() for s in self.server.detector.signals()]})
            return
        self._send(404, {"error": "not found"})


def _extract_flag(body: bytes, query: str) -> tuple[str, str]:
    """Pull a candidate flag out of a JSON or plain-text submission."""
    text = _render(body)
    source = ""
    if text:
        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            parsed = None
        if isinstance(parsed, dict):
            value = str(parsed.get("flag", "") or parsed.get("value", ""))
            source = str(parsed.get("source", "") or "")
            if value:
                return value, source
        if text.strip():
            return text.strip(), source
    params = urllib.parse.parse_qs(query)
    flag = (params.get("flag") or [""])[0]
    return flag, source


def build_server(
    host: str = "127.0.0.1",
    port: int = 8765,
    token: str = "",
    flag_pattern: str = "",
    max_per_minute: int = 30,
) -> GuardServer:
    regex = None
    if flag_pattern:
        from .flags import xeger_to_regex

        regex = xeger_to_regex(flag_pattern) or re.compile(re.escape(flag_pattern))
    quarantine = FlagQuarantine(flag_regex=regex, max_per_minute=max_per_minute)
    detector = ScannerDetector()
    return GuardServer((host, port), quarantine, detector, token=token)


def serve(host: str = "127.0.0.1", port: int = 8765, token: str = "", flag_pattern: str = "") -> None:
    server = build_server(host=host, port=port, token=token, flag_pattern=flag_pattern)
    print(f"guard receiver listening on http://{host}:{port}")
    print("  POST /flags            -> quarantine inbound flag (never submitted)")
    print("  GET  /quarantine       -> list held flags (X-Guard-Token when set)")
    print("  GET  /signals          -> scan/automation signals")
    print("  GET  /health")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    import os

    serve(
        host=os.environ.get("AD_GUARD_HOST", "127.0.0.1"),
        port=int(os.environ.get("AD_GUARD_PORT", "8765")),
        token=os.environ.get("AD_GUARD_TOKEN", ""),
        flag_pattern=os.environ.get("AD_FLAG_PATTERN", ""),
    )
