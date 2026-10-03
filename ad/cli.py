"""Command line interface.

    python -m ad scan  --config <service>.json [--monitor <dump-or-dir>]
    python -m ad init   <service-name>            # scaffold a config
    python -m ad poison --config <service>.json --actor team --team t7 \
                        --endpoint /api/flag --flag 'alctf{...}'
    python -m ad rules                            # list the rule pack
    python -m ad guard --serve                    # protected flag receiver (AI-vs-AI)
"""

from __future__ import annotations

import argparse
import glob
import json
import re
import sys
from pathlib import Path

from . import __version__
from .config import Config, ConfigError, load_config
from .flags import infer_flow
from .poison import Poisoner, PoisonerMisconfigured
from .report import write_all
from .requests import load_requests
from .sast import scan
from .topology import infer_topology

CONFIG_TEMPLATE = {
    "service_name": "CHANGE_ME",
    "source_roots": ["."],
    "output_dir": "../../reports",
    "notes": "",
    "flag_format": {
        "pattern": "",
        "prefix": "",
        "body_alphabet": "",
        "min_length": 0,
    },
    "known_flags": [],
    "team_networks": [],
    "checker_networks": [],
    "checker_ip_pattern": "",
    "request_logs": [],
    "_instructions": {
        "flag_format.pattern": "xeger syntax exactly as the checker generates it, e.g. 'alctf{[a-z0-9_]{16}}'. Leave empty rather than guessing.",
        "known_flags": "literal flags for this service, if the operator can share them. Used for exact detection.",
        "team_networks": "list of {'label','cidr'} for the participant instances. Explicit entries always win over inference.",
        "checker_networks": "list of {'label','cidr'} for the checker's source addresses.",
        "checker_ip_pattern": "IP_PATTERN from the checker config, e.g. '10.10.{team_number}.2'. Used to infer per-team instances.",
        "request_logs": "JSONL/JSON captures, combined/gin access logs, or monitoring stand dumps (services/monitoring/data/<svc>/<date>.jsonl). Monitor shape: at, ip, principal, target, outcome, flags, headers, body.",
    },
}


def _cmd_init(args) -> int:
    target = Path(args.path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(CONFIG_TEMPLATE)
    payload["service_name"] = args.name or target.stem
    target.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {target}")
    print("Fill in flag_format.pattern, team_networks and request_logs before trusting the report.")
    return 0


def _read_source_texts(cfg: Config) -> dict[str, str]:
    from .sast import TEXT_SUFFIXES, _iter_source_files

    files, _ = _iter_source_files(cfg.source_roots, cfg.excluded_globs)
    texts: dict[str, str] = {}
    for path in files:
        if path.suffix.lower() not in TEXT_SUFFIXES and not path.name.startswith(".env"):
            continue
        try:
            if path.stat().st_size > 2_000_000:
                continue
            texts[str(path)] = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return texts


def _expand_monitor(raw: str) -> list[Path]:
    """Resolve a --monitor argument: a file, a directory (all *.jsonl) or a glob."""
    path = Path(raw)
    if path.is_dir():
        return sorted(path.glob("**/*.jsonl"))
    if any(ch in raw for ch in "*?["):
        return sorted(Path(p) for p in glob.glob(raw, recursive=True))
    return [path] if path.is_file() else []


def _cmd_scan(args) -> int:
    cfg = load_config(Path(args.config))
    result = scan(cfg.source_roots, cfg.excluded_globs)
    texts = _read_source_texts(cfg)
    topo = infer_topology(list(texts.values()))
    logs = list(cfg.request_logs)
    for raw in args.monitor:
        logs.extend(_expand_monitor(raw))
    runtime = load_requests(logs, cfg)

    route_runtime: dict[str, list[dict]] = {"__all__": runtime.route_matrix()}
    flow = infer_flow(cfg, texts, route_runtime)
    flow.observed_checker_reads = [
        r["route"] for r in runtime.route_matrix()
        if r["actors"].get("checker", {}).get("flag_reads")
    ]
    flow.observed_team_reads = [
        r["route"] for r in runtime.route_matrix()
        if r["actors"].get("team", {}).get("flag_reads")
    ]

    if args.classify_ips:
        for ip, actor in sorted(runtime.classify_unknown(cfg).items()):
            print(f"ip {ip} -> {actor}")

    out = write_all(cfg, result, runtime, flow, topo, root=Path(args.out) if args.out else None)
    print(f"{cfg.service_name}: {result.files_scanned} files, {len(result.findings)} findings, "
          f"{len(runtime.requests)} requests -> {out}")
    return 0


def _cmd_poison(args) -> int:
    cfg = load_config(Path(args.config))
    try:
        poisoner = Poisoner(cfg)
    except PoisonerMisconfigured as exc:
        print(json.dumps({"action": "disabled", "reason": str(exc)}, indent=2))
        return 2
    decision = poisoner.decision(args.actor, args.team, args.endpoint, args.flag)
    print(json.dumps({
        "action": decision.action,
        "reason": decision.reason,
        "actor": decision.actor,
        "team_key": decision.team_key,
        "flag_in": args.flag,
        "flag_out": decision.value,
    }, indent=2, ensure_ascii=False))
    return 0


def _cmd_rules(args) -> int:
    from .rules import RULES

    if args.json:
        print(json.dumps([
            {
                "id": r.id, "category": r.category, "title": r.title, "severity": r.severity,
                "cwe": list(r.cwe), "sources": list(r.sources),
                "exploit": r.exploit, "breaker": r.breaker,
            } for r in RULES
        ], indent=2, ensure_ascii=False))
        return 0
    print(f"{'ID':<14} {'SEVERITY':<9} {'CATEGORY':<24} TITLE")
    for r in RULES:
        print(f"{r.id:<14} {r.severity:<9} {r.category:<24} {r.title}")
    print(f"\n{len(RULES)} rules")
    return 0


def _cmd_guard(args) -> int:
    from . import guard

    if args.decode is not None:
        layers = guard.decode_payloads(args.decode)
        print(json.dumps([layer.to_dict() for layer in layers], indent=2, ensure_ascii=False))
        return 0

    if args.inspect is not None:
        verdict = guard.inspect_request(
            path=args.inspect,
            query=args.query or "",
            body=(args.body or "").encode("utf-8"),
        )
        print(json.dumps(verdict.to_dict(), indent=2, ensure_ascii=False))
        return 0

    if args.flag is not None:
        regex = None
        if args.pattern:
            from .flags import xeger_to_regex

            regex = xeger_to_regex(args.pattern) or re.compile(re.escape(args.pattern))
        result = guard.FlagQuarantine(flag_regex=regex).submit(args.flag, client="cli")
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        return 0

    guard.serve(host=args.host, port=args.port, token=args.token, flag_pattern=args.pattern or "")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ad", description="Altay A/D service analysis toolkit")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="scaffold a service config")
    p_init.add_argument("path")
    p_init.add_argument("--name")
    p_init.set_defaults(func=_cmd_init)

    p_scan = sub.add_parser("scan", help="analyse a service and write reports")
    p_scan.add_argument("--config", required=True)
    p_scan.add_argument("--out", help="override the reports root")
    p_scan.add_argument(
        "--classify-ips",
        action="store_true",
        help="assign checker/team to runtime records whose actor is unknown, using configured networks",
    )
    p_scan.add_argument(
        "--monitor",
        action="append",
        default=[],
        metavar="PATH",
        help="monitoring stand dump (file, directory of *.jsonl, or glob) to merge into runtime",
    )
    p_scan.set_defaults(func=_cmd_scan)

    p_poison = sub.add_parser("poison", help="ask what would happen to one flag")
    p_poison.add_argument("--config", required=True)
    p_poison.add_argument("--actor", default="team", choices=("checker", "team", "unknown"))
    p_poison.add_argument("--team", default="t0")
    p_poison.add_argument("--endpoint", default="/")
    p_poison.add_argument("--flag", required=True)
    p_poison.set_defaults(func=_cmd_poison)

    p_rules = sub.add_parser("rules", help="list the detection rule pack")
    p_rules.add_argument("--json", action="store_true")
    p_rules.set_defaults(func=_cmd_rules)

    p_guard = sub.add_parser(
        "guard",
        help="AI-vs-AI defence: decode/inspect/quarantine plus a protected flag receiver",
    )
    p_guard.add_argument("--serve", action="store_true", help="run the protected receiver (default)")
    p_guard.add_argument("--host", default="127.0.0.1")
    p_guard.add_argument("--port", type=int, default=8765)
    p_guard.add_argument("--token", default="", help="required as X-Guard-Token for /quarantine and /signals")
    p_guard.add_argument("--pattern", default="", help="xeger flag pattern used for shape checks")
    p_guard.add_argument("--decode", help="decode one encoded blob (base64/hex/gzip/url/...)")
    p_guard.add_argument("--inspect", help="classify one request path for encoded payloads and injections")
    p_guard.add_argument("--query", default="")
    p_guard.add_argument("--body", default="")
    p_guard.add_argument("--flag", help="show what the quarantine would do with a value")
    p_guard.set_defaults(func=_cmd_guard)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())