"""Runtime request analysis.

Accepts, per service:
  * JSONL / JSON array captures with fields (ts, client_ip, method, path, status, body, headers)
  * nginx/Apache combined access logs
  * gin's default access log format
  * tcpdump-style "what requests came in" dumps pasted into a .log

Everything is normalised into `ObservedRequest` and then attributed to an actor
(checker / team / unknown) using the configured networks. The output answers the
question the jury actually asks: which requests did the checker make, which did
teams make, and did the two ever see each other's data.
"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .config import Config
from .flags import detect_flags

COMBINED_LOG = re.compile(
    r'^(?P<client>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+(?P<proto>[^"]*))?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

NGINX_COMBINED_TAIL = re.compile(
    r'^(?P<extra>.*?)\s*(?P<client>\d{1,3}(?:\.\d{1,3}){3})\s+'
)

# Gin's default access logger:
#
#   [GIN] 2026/10/02 - 04:28:12 | 200 | 365.216us | 172.23.0.1 | GET  "/"
#
# The fields sit in a different order from a combined log and the timestamp is
# not bracketed, so a Go service produced no runtime records at all before this
# pattern existed. The body of a request is never in the line, which is why flag
# writes stay undetectable from this format alone.
GIN_LOG = re.compile(
    r'^\[GIN\]\s+(?P<ts>\d{4}/\d{2}/\d{2}\s+-\s+\d{2}:\d{2}:\d{2})\s*\|\s*'
    r'(?P<status>\d{3})\s*\|\s*(?P<latency>[^|]*?)\s*\|\s*'
    r'(?P<client>\S+)\s*\|\s*(?P<method>[A-Z]+)\s+"(?P<path>[^"]*)"'
)

_GIN_TS = re.compile(r'^(\d{4})/(\d{2})/(\d{2})\s+-\s+(\d{2}):(\d{2}):(\d{2})$')


def _group(match: re.Match[str], name: str) -> str:
    """Read an optional group.

    Only the combined format declares `ua`. `re` raises IndexError for a name the
    pattern never defined, rather than returning None, so a parser that accepts
    several formats has to ask safely.
    """
    try:
        return match.group(name) or ""
    except (IndexError, KeyError):
        return ""


def normalise_gin_ts(raw: str) -> str:
    """Turn gin's `2006/01/02 - 15:04:05` into the shape the combined parser
    yields, so both formats sort and group the same way.

    The line carries no zone, so the result is naive. That is deliberate:
    inventing an offset would make two records look further apart in time than
    the log can actually prove, and the engine only uses timestamps for ordering.
    """
    match = _GIN_TS.match(raw.strip())
    if not match:
        return raw.strip()
    year, month, day, hour, minute, second = match.groups()
    return f"{year}-{month}-{day}T{hour}:{minute}:{second}"


@dataclass
class ObservedRequest:
    ts: str
    client_ip: str
    actor: str
    method: str
    path: str
    status: int | None = None
    query: str = ""
    body: str = ""
    response: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    source: str = ""

    @property
    def route_key(self) -> str:
        return f"{self.method} {self.path}"

    def to_dict(self) -> dict:
        return {
            "ts": self.ts,
            "client_ip": self.client_ip,
            "actor": self.actor,
            "method": self.method,
            "path": self.path,
            "query": self.query,
            "status": self.status,
            "request_body": self.body,
            "response_body": self.response,
            "headers": self.headers,
            "flags_in_response": detect_flags(self.response, self.query),
            "flags_in_request": detect_flags(self.body),
            "source": self.source,
        }


@dataclass
class ActorProfile:
    actor: str
    ips: set[str] = field(default_factory=set)
    requests: int = 0
    routes: dict[str, int] = field(default_factory=dict)
    statuses: dict[int, int] = field(default_factory=dict)
    credential_pairs: set[tuple[str, str]] = field(default_factory=set)
    # Reads and writes are separate signals: a checker PUT hands a flag in, a
    # team GET pulls it out. Collapsing them hides exactly the transition the
    # flag-flow analysis depends on.
    flag_reads: int = 0
    flag_writes: int = 0

    def to_dict(self) -> dict:
        return {
            "actor": self.actor,
            "ips": sorted(self.ips),
            "request_count": self.requests,
            "distinct_routes": len(self.routes),
            "routes": dict(sorted(self.routes.items(), key=lambda kv: -kv[1])),
            "status_counts": {str(k): v for k, v in sorted(self.statuses.items())},
            "credential_pairs_seen": sorted(f"{u}:{p}" for u, p in self.credential_pairs),
            "flag_reads": self.flag_reads,
            "flag_writes": self.flag_writes,
        }


@dataclass
class RuntimeReport:
    requests: list[ObservedRequest] = field(default_factory=list)
    profiles: dict[str, ActorProfile] = field(default_factory=dict)
    parser_notes: list[str] = field(default_factory=list)
    cross_actor_findings: list[str] = field(default_factory=list)

    def recompute(self) -> None:
        """Rebuild every derived aggregate after actors have been reassigned."""
        self.profiles = _profile(self.requests)
        self.cross_actor_findings = _cross_actor(self)

    def classify_unknown(self, cfg: Config) -> dict[str, str]:
        """Assign actors to records still marked unknown, then recompute.

        Returns the IP -> actor mapping that was applied. Recomputing here keeps
        the profiles and cross-actor findings consistent with the new labels;
        mutating `actor` on its own would silently leave both stale.
        """
        applied: dict[str, str] = {}
        for req in self.requests:
            if req.actor != "unknown":
                continue
            actor = cfg.classify_ip(req.client_ip)
            req.actor = actor
            applied.setdefault(req.client_ip, actor)
        self.recompute()
        return applied

    def route_matrix(self) -> list[dict]:
        routes: dict[str, dict[str, dict]] = {}
        for req in self.requests:
            entry = routes.setdefault(req.route_key, {})
            actor = entry.setdefault(
                req.actor, {"count": 0, "flag_reads": 0, "flag_writes": 0, "ips": set()}
            )
            actor["count"] += 1
            actor["ips"].add(req.client_ip)
            if detect_flags(req.response, req.query):
                actor["flag_reads"] += 1
            if req.method in WRITE_METHODS and detect_flags(req.body):
                actor["flag_writes"] += 1
        out = []
        for route_key, actors in sorted(routes.items()):
            out.append(
                {
                    "route": route_key,
                    "actors": {
                        name: {
                            "count": data["count"],
                            "flag_reads": data["flag_reads"],
                            "flag_writes": data["flag_writes"],
                            "ips": sorted(data["ips"]),
                        }
                        for name, data in sorted(actors.items())
                    },
                }
            )
        return out


CREDENTIAL_KEYS = ("login", "username", "user", "email", "password", "passwd", "pass", "pwd")

WRITE_METHODS = {"POST", "PUT", "PATCH"}


def load_requests(paths: list[Path], cfg: Config) -> RuntimeReport:
    report = RuntimeReport()
    for path in paths:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        if not text.strip():
            continue
        # Monitor dumps are JSONL of records with a `principal`/`target`/`outcome`
        # shape. Try them first: a single-line file would otherwise be swallowed
        # by the JSON sniffer as an empty `requests` array.
        if _try_monitor(text, path, report):
            continue
        parsed_json = _try_json(text, path, report)
        if not parsed_json:
            _parse_lines(text, path, cfg, report)
    report.recompute()
    return report


def _try_json(text: str, path: Path, report: RuntimeReport) -> bool:
    # A gin log opens with `[GIN]`, which looks like a JSON array to the sniffer
    # below. Recognise a supported line format first so Go services do not get a
    # "not valid JSON" note on every report.
    first = next(
        (
            stripped_line
            for stripped_line in (ln.strip() for ln in text.splitlines())
            if stripped_line and not stripped_line.startswith("#")
        ),
        None,
    )
    if first and (COMBINED_LOG.match(first) or GIN_LOG.match(first)):
        return False

    stripped = text.lstrip()
    if not stripped.startswith(("[", "{")):
        return False
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        report.parser_notes.append(f"{path.name}: not valid JSON, fell back to line parser")
        return False
    records = data if isinstance(data, list) else data.get("requests", [])
    if not isinstance(records, list):
        return False
    for record in records:
        if isinstance(record, dict):
            if _looks_like_monitor(record):
                report.requests.append(_monitor_record(record, path))
            else:
                report.requests.append(_from_dict(record, path))
    report.parser_notes.append(f"{path.name}: {len(records)} requests (JSON)")
    return True


def _try_monitor(text: str, path: Path, report: RuntimeReport) -> bool:
    """Parse a monitoring stand dump (`services/monitoring/data/<svc>/<date>.jsonl`).

    Every non-comment line must be a JSON object in the monitor shape, otherwise
    the file is left to the other parsers. Accepting it only when the *whole*
    file matches avoids stealing a genuine JSON capture on the first line.
    """
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if not lines or any(not line.startswith("{") for line in lines):
        return False
    records = []
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return False
        if not isinstance(obj, dict) or not _looks_like_monitor(obj):
            return False
        records.append(obj)
    for obj in records:
        report.requests.append(_monitor_record(obj, path))
    report.parser_notes.append(f"{path.name}: {len(records)} requests (monitor JSONL)")
    return True


def _looks_like_monitor(record: dict) -> bool:
    """True for a monitoring stand record.

    The giveaway is the actor label plus either the request target the stand
    records instead of `path`, or the allow/block `outcome` it assigns.
    """
    if "principal" not in record:
        return False
    return "target" in record or "outcome" in record


_MONITOR_ACTORS = {"checker", "team", "unknown"}


def _monitor_record(record: dict, path: Path) -> ObservedRequest:
    """Map one monitoring record onto the shared request shape.

    The monitor already classifies the source (`principal`), so that label is
    trusted over re-inference. Observed `flags` are folded into `response` so the
    existing flag_reads/writes accounting sees them; the remaining monitor-only
    fields (outcome, reason, rules, team) are preserved as `x-monitor-*` headers
    so no evidence is silently dropped.
    """
    target = str(record.get("target") or record.get("path") or "/")
    path_value, _, query = target.partition("?")
    principal = str(record.get("principal") or "unknown").lower()
    actor = principal if principal in _MONITOR_ACTORS else "unknown"

    headers = record.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}
    headers = {str(k): str(v) for k, v in headers.items()}
    for source_key, header_key in (
        ("team", "x-monitor-team"),
        ("outcome", "x-monitor-outcome"),
        ("reason", "x-monitor-reason"),
    ):
        value = record.get(source_key)
        if value:
            headers.setdefault(header_key, str(value))
    rules = record.get("rules") or []
    if rules:
        headers.setdefault("x-monitor-rules", ",".join(str(rule) for rule in rules))

    status = record.get("status")
    body = _stringify(record.get("body") or "")
    # The monitor lists every flag it saw in the transaction, request or
    # response. A flag already carried in the request body is a checker *write*,
    # so keep it out of `response`; otherwise one PUT would count as both a read
    # and a write.
    flags = [str(flag) for flag in (record.get("flags") or [])]
    response = " ".join(flag for flag in flags if not body or flag not in body)
    return ObservedRequest(
        ts=str(record.get("at") or record.get("ts") or ""),
        client_ip=str(record.get("ip") or "0.0.0.0"),
        actor=actor,
        method=str(record.get("method") or "GET").upper(),
        path=path_value,
        status=int(status) if str(status).isdigit() else None,
        query=query,
        body=body,
        response=response,
        headers=headers,
        source=path.name,
    )


def _from_dict(record: dict, path: Path) -> ObservedRequest:
    ip = str(record.get("client_ip") or record.get("ip") or record.get("remote_addr") or "0.0.0.0")
    path_value = str(record.get("path") or record.get("url") or record.get("uri") or "/")
    query = str(record.get("query") or record.get("query_string") or "")
    if "?" in path_value and not query:
        path_value, _, query = path_value.partition("?")
    headers = record.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}
    status = record.get("status") or record.get("status_code")
    return ObservedRequest(
        ts=str(record.get("ts") or record.get("time") or record.get("timestamp") or ""),
        client_ip=ip,
        actor=str(record.get("actor") or "unknown"),
        method=str(record.get("method") or "GET").upper(),
        path=path_value,
        status=int(status) if str(status).isdigit() else None,
        query=query,
        body=_stringify(record.get("body") or record.get("request_body") or ""),
        response=_stringify(record.get("response") or record.get("response_body") or record.get("body_out") or ""),
        headers={str(k): str(v) for k, v in headers.items()},
        source=path.name,
    )


def _stringify(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def _parse_lines(text: str, path: Path, cfg: Config, report: RuntimeReport) -> None:
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = COMBINED_LOG.match(line) or GIN_LOG.match(line)
        if match:
            target = match.group("path")
            query = ""
            if "?" in target:
                target, _, query = target.partition("?")
            status = int(match.group("status"))
            raw_ts = match.group("ts")
            # Gin's timestamp is `2006/01/02 - 15:04:05`; the combined form is
            # already bracketed and left alone.
            ts = normalise_gin_ts(raw_ts) if "/" in raw_ts else raw_ts
            report.requests.append(
                ObservedRequest(
                    ts=ts,
                    client_ip=match.group("client"),
                    actor="unknown",
                    method=match.group("method"),
                    path=target,
                    status=status,
                    query=query,
                    body="",
                    response="",
                    headers={"user-agent": _group(match, "ua")},
                    source=path.name,
                )
            )
            continue
        report.parser_notes.append(f"{path.name}: unparsed line: {line[:120]}")


def _profile(requests: list[ObservedRequest]) -> dict[str, ActorProfile]:
    profiles: dict[str, ActorProfile] = {}
    for req in requests:
        profile = profiles.setdefault(req.actor, ActorProfile(actor=req.actor))
        profile.ips.add(req.client_ip)
        profile.requests += 1
        profile.routes[req.route_key] = profile.routes.get(req.route_key, 0) + 1
        if req.status is not None:
            profile.statuses[req.status] = profile.statuses.get(req.status, 0) + 1
        if detect_flags(req.response, req.query):
            profile.flag_reads += 1
        if req.method in WRITE_METHODS and detect_flags(req.body):
            profile.flag_writes += 1
        pair = _credential_pair(req)
        if pair:
            profile.credential_pairs.add(pair)
    return profiles


def _credential_pair(req: ObservedRequest) -> tuple[str, str] | None:
    if req.method not in WRITE_METHODS:
        return None
    blob = f"{req.body} {req.query}"
    if "=" not in blob:
        return None
    lowered = blob.lower()
    if not any(key in lowered for key in CREDENTIAL_KEYS):
        return None
    values: dict[str, str] = {}
    try:
        parsed = json.loads(req.body)
        if isinstance(parsed, dict):
            flat = _flatten(parsed)
            values = {k.lower(): v for k, v in flat.items() if isinstance(v, (str, int, float))}
    except (json.JSONDecodeError, TypeError):
        for chunk in blob.split("&"):
            if "=" not in chunk:
                continue
            key, _, value = chunk.partition("=")
            values[key.strip().lower()] = value.strip()
    user = next((values[k] for k in ("login", "username", "user", "email") if k in values), None)
    password = next((values[k] for k in ("password", "passwd", "pass", "pwd") if k in values), None)
    if user and password:
        return (str(user), str(password))
    return None


def _flatten(obj, prefix: str = "") -> dict:
    out: dict[str, str] = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            out.update(_flatten(value, name))
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            out.update(_flatten(value, f"{prefix}.{index}"))
    else:
        out[prefix] = obj
    return out


def _cross_actor(report: RuntimeReport) -> list[str]:
    """Routes touched by more than one actor class - the interesting surface."""
    notes: list[str] = []
    by_route: dict[str, dict[str, int]] = {}
    flag_by_route: dict[str, dict[str, int]] = {}
    for req in report.requests:
        by_route.setdefault(req.route_key, {})
        by_route[req.route_key][req.actor] = by_route[req.route_key].get(req.actor, 0) + 1
        if detect_flags(req.response, req.query):
            flag_by_route.setdefault(req.route_key, {})
            flag_by_route[req.route_key][req.actor] = flag_by_route[req.route_key].get(req.actor, 0) + 1

    for route_key, actors in sorted(by_route.items()):
        classes = sorted(actors)
        if len(classes) > 1:
            notes.append(
                f"{route_key}: reached by {', '.join(f'{a}({actors[a]})' for a in classes)}"
            )
        flags = flag_by_route.get(route_key)
        if flags and "checker" in flags and "team" in flags:
            notes.append(
                f"{route_key}: flag-shaped data observed for BOTH checker and team traffic - "
                f"verify the authorisation boundary"
            )
    return notes


def write_requests_csv(report: RuntimeReport, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            ["ts", "actor", "client_ip", "method", "path", "query", "status",
             "request_body", "response_body", "flags_in_request", "flags_in_response"]
        )
        for req in report.requests:
            writer.writerow(
                [
                    req.ts, req.actor, req.client_ip, req.method, req.path, req.query,
                    req.status if req.status is not None else "",
                    req.body[:2000], req.response[:2000],
                    "|".join(detect_flags(req.body)),
                    "|".join(detect_flags(req.response, req.query)),
                ]
            )