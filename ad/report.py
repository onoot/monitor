"""Per-service report generation.

Each service gets its own directory:

    reports/<service>/
        report.md            human-readable
        report.json          machine-readable (stable schema, for an agent)
        findings.json
        findings.csv
        requests.csv
        requests.md
        flagflow.md
        poison.json
        run.json

report.json is the contract an AI consumes; report.md is the contract a human
reads. They are generated from the same data so they cannot drift.
"""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from .config import Config
from .flags import FlagFlow
from .poison import Poisoner, PoisonerMisconfigured
from .requests import RuntimeReport, write_requests_csv
from .sast import ScanResult, unguarded_id_routes
from .topology import Topology, lifecycle

SCHEMA_VERSION = "1.0"


def service_dir(cfg: Config, root: Path | None = None) -> Path:
    base = root or cfg.output_dir
    return Path(base) / cfg.service_name


def write_all(
    cfg: Config,
    scan: ScanResult,
    runtime: RuntimeReport,
    flow: FlagFlow,
    topo: Topology,
    root: Path | None = None,
) -> Path:
    out = service_dir(cfg, root)
    out.mkdir(parents=True, exist_ok=True)

    try:
        poisoner = Poisoner(cfg)
        poison_policy = poisoner.describe()
    except PoisonerMisconfigured as exc:
        # A scan is still useful without a key, so report the gap instead of failing.
        poison_policy = {
            "enabled": False,
            "flag_pattern": cfg.flag_format.pattern,
            "mask": None,
            "prefix": cfg.flag_format.prefix,
            "envelope": [],
            "alphabet": "",
            "checker_policy": "never modify",
            "unknown_policy": "never modify",
            "team_policy": "disabled: no private key available",
            "requires": "flag_format.pattern in the service config and AD_POISON_SECRET",
            "secret_source": "AD_POISON_SECRET",
            "error": str(exc),
        }
    routes = scan.sorted_findings()
    idor_routes = unguarded_id_routes(scan.routes)

    run_meta = {
        "schema_version": SCHEMA_VERSION,
        "service": cfg.service_name,
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_roots": [str(p) for p in cfg.source_roots],
        "files_scanned": scan.files_scanned,
        "files_skipped": scan.files_skipped,
        "request_records": len(runtime.requests),
        "rules_evaluated": "see ad.rules.RULES",
        "notes": cfg.notes,
    }

    payload = {
        "meta": run_meta,
        "topology": {
            "checker_ip_pattern": topo.ip_pattern,
            "inferred_team_ips": topo.team_ips,
            "configured_team_networks": [
                {"label": n.label, "cidr": n.cidr, "source": n.source} for n in cfg.team_networks
            ],
            "configured_checker_networks": [
                {"label": n.label, "cidr": n.cidr, "source": n.source} for n in cfg.checker_networks
            ],
            "checker_lifecycle": [
                {"phase": p.key, "description": p.description, "expected_actor": p.expected_actor}
                for p in lifecycle()
            ],
        },
        "findings": [f.to_dict() for f in routes],
        "finding_counts": _counts(routes, key=lambda f: f.severity),
        "category_counts": _counts(routes, key=lambda f: f.category),
        "routes": [r.to_dict() for r in scan.routes],
        "unguarded_id_routes": [r.to_dict() for r in idor_routes],
        "runtime": {
            "actors": {name: p.to_dict() for name, p in runtime.profiles.items()},
            "route_matrix": runtime.route_matrix(),
            "cross_actor_observations": runtime.cross_actor_findings,
            "parser_notes": runtime.parser_notes,
        },
        "flag_flow": flow.to_dict(),
        "poisoning": poison_policy,
        "warnings": _warnings(cfg, scan, runtime, flow, topo),
    }

    (out / "report.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False), encoding="utf-8"
    )
    (out / "findings.json").write_text(
        json.dumps([f.to_dict() for f in routes], indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (out / "poison.json").write_text(
        json.dumps(poison_policy, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (out / "run.json").write_text(json.dumps(run_meta, indent=2, ensure_ascii=False), encoding="utf-8")

    _write_findings_csv(routes, out / "findings.csv")
    if runtime.requests:
        write_requests_csv(runtime, out / "requests.csv")
        (out / "requests.md").write_text(_requests_md(cfg, runtime), encoding="utf-8")
    (out / "flagflow.md").write_text(_flagflow_md(cfg, flow), encoding="utf-8")
    (out / "report.md").write_text(_report_md(cfg, payload, scan, runtime), encoding="utf-8")

    return out


def _counts(items, key) -> dict:
    out: dict[str, int] = {}
    for item in items:
        name = key(item)
        out[name] = out.get(name, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def _warnings(cfg, scan, runtime, flow, topo) -> list[str]:
    warnings: list[str] = []
    if not cfg.has_flag_format:
        warnings.append(
            "flag_format.pattern is not set: flag put/get cannot be verified and poisoning is disabled."
        )
    if not cfg.team_networks:
        warnings.append(
            "No team_networks configured. Runtime IPs will classify as 'unknown' and are never poisoned."
        )
    if not cfg.checker_networks and not cfg.checker_ip_pattern:
        warnings.append(
            "No checker_networks or checker_ip_pattern configured. Checker traffic cannot be identified; "
            "treat all traffic as team traffic for reporting only, never for poisoning."
        )
    if topo.inferred and cfg.team_networks:
        overlaps = topo.overlaps_configured_team_networks([n.cidr for n in cfg.team_networks])
        if overlaps:
            warnings.append(
                "Inferred team IPs overlap configured team networks: " + ", ".join(sorted(set(overlaps)))
            )
    if scan.files_scanned == 0:
        warnings.append("No source files were scanned; static findings are empty.")
    # parser_notes also carries success summaries ("N requests (JSON)"); only the
    # per-line failures should raise a warning, otherwise a clean JSON or monitor
    # dump would be reported as unparsed.
    unparsed = [note for note in runtime.parser_notes if "unparsed" in note]
    if unparsed:
        warnings.append(f"{len(unparsed)} request log lines could not be parsed.")
    for note in flow.warnings:
        warnings.append(note)
    return warnings


def _write_findings_csv(findings, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            ["severity", "confidence", "category", "rule_id", "file", "line",
             "title", "cwe", "exploit", "breaker", "remediation", "snippet"]
        )
        for f in findings:
            writer.writerow(
                [
                    f.severity, f.confidence, f.category, f.rule_id,
                    f.evidence.file, f.evidence.line, f.title, "|".join(f.cwe),
                    f.exploit, f.breaker, f.remediation, f.evidence.snippet,
                ]
            )


def _sev_badge(sev: str) -> str:
    return f"**{sev.upper()}**"


def _report_md(cfg, payload, scan, runtime) -> str:
    lines: list[str] = []
    meta = payload["meta"]
    sev_counts = payload["finding_counts"]

    lines.append(f"# {cfg.service_name} — A/D analysis")
    lines.append("")
    lines.append(f"Generated {meta['generated_utc']} · {meta['files_scanned']} source files · "
                 f"{meta['request_records']} runtime records")
    lines.append("")
    if cfg.notes:
        lines.append(f"> Operator note: {cfg.notes}")
        lines.append("")

    warn = payload["warnings"]
    if warn:
        lines.append("## Read this first")
        lines.append("")
        for item in warn:
            lines.append(f"- {item}")
        lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | ---: |")
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in sev_counts:
            lines.append(f"| {sev} | {sev_counts[sev]} |")
    lines.append("")
    if payload["category_counts"]:
        lines.append("| Category | Count |")
        lines.append("| --- | ---: |")
        for cat, count in payload["category_counts"].items():
            lines.append(f"| {cat} | {count} |")
        lines.append("")

    # ---- topology
    topo = payload["topology"]
    lines.append("## Instance topology")
    lines.append("")
    if topo["checker_ip_pattern"]:
        lines.append(f"- Checker `IP_PATTERN`: `{topo['checker_ip_pattern']}`")
        sample = list(topo["inferred_team_ips"].items())[:8]
        if sample:
            lines.append("- Inferred team instances: " + ", ".join(f"`{n}`→`{ip}`" for n, ip in sample))
    else:
        lines.append("- Checker `IP_PATTERN` not found in source. Ask the operator; do not assume a default.")
    lines.append("")
    lines.append("| Network role | CIDR | Source |")
    lines.append("| --- | --- | --- |")
    for net in topo["configured_team_networks"]:
        lines.append(f"| team | `{net['cidr']}` | {net['source']} |")
    for net in topo["configured_checker_networks"]:
        lines.append(f"| checker | `{net['cidr']}` | {net['source']} |")
    if not topo["configured_team_networks"] and not topo["configured_checker_networks"]:
        lines.append("| _none configured_ | | |")
    lines.append("")

    # ---- lifecycle
    lines.append("## Checker lifecycle (expected traffic)")
    lines.append("")
    lines.append("| Phase | Expected actor | Description |")
    lines.append("| --- | --- | --- |")
    for phase in topo["checker_lifecycle"]:
        lines.append(f"| {phase['phase']} | {phase['expected_actor']} | {phase['description']} |")
    lines.append("")

    # ---- findings
    lines.append("## Findings")
    lines.append("")
    if not payload["findings"]:
        lines.append("No static findings.")
        lines.append("")
    current = None
    for f in payload["findings"]:
        if f["severity"] != current:
            current = f["severity"]
            lines.append(f"### {_sev_badge(current)}")
            lines.append("")
        lines.append(f"#### {f['rule_id']} · {f['title']}")
        lines.append("")
        lines.append(f"- Category: `{f['category']}` · Confidence: `{f['confidence']}`"
                     + (f" · CWE: {', '.join(f['cwe'])}" if f["cwe"] else ""))
        lines.append(f"- Evidence: `{f['evidence']['file']}:{f['evidence']['line']}`")
        lines.append(f"- Pattern source: {', '.join(f['rule_sources']) or 'local rules'}")
        lines.append("")
        if f["description"]:
            lines.append(f"{f['description']}")
            lines.append("")
        if f["exploit"]:
            lines.append(f"- **Team exploit path**: {f['exploit']}")
        if f["breaker"]:
            lines.append(f"- **Checker-breaking**: {f['breaker']}")
        if f["remediation"]:
            lines.append(f"- **Fix**: {f['remediation']}")
        lines.append("")
        lines.append("```")
        lines.append(f["evidence"]["snippet"])
        lines.append("```")
        lines.append("")

    # ---- routes
    lines.append("## Route inventory")
    lines.append("")
    lines.append(f"{len(payload['routes'])} routes extracted · "
                 f"{len(payload['unguarded_id_routes'])} take an object id with no auth hint nearby")
    lines.append("")
    if payload["unguarded_id_routes"]:
        lines.append("| Method | Path | Location |")
        lines.append("| --- | --- | --- |")
        for route in payload["unguarded_id_routes"]:
            lines.append(f"| {route['method']} | `{route['path']}` | `{route['file']}:{route['line']}` |")
        lines.append("")
        lines.append("These are candidates only: confirm at runtime before reporting as IDOR.")
        lines.append("")

    # ---- runtime
    lines.append("## Runtime traffic")
    lines.append("")
    if not runtime.requests:
        lines.append("No request logs configured. Add `request_logs` to the service config.")
        lines.append("")
    else:
        lines.append("| Actor | Requests | Distinct routes | Flag reads | Flag writes | IPs |")
        lines.append("| --- | ---: | ---: | ---: | ---: | --- |")
        for actor, profile in sorted(payload["runtime"]["actors"].items()):
            lines.append(
                f"| {actor} | {profile['request_count']} | {profile['distinct_routes']} | "
                f"{profile['flag_reads']} | {profile['flag_writes']} | "
                f"{', '.join('`%s`' % ip for ip in profile['ips'][:6])} |"
            )
        lines.append("")
        if payload["runtime"]["cross_actor_observations"]:
            lines.append("### Cross-actor observations")
            lines.append("")
            for note in payload["runtime"]["cross_actor_observations"]:
                lines.append(f"- {note}")
            lines.append("")
        lines.append("Full request/response detail: `requests.csv`, `requests.md`.")
        lines.append("")

    # ---- flag flow
    flow = payload["flag_flow"]
    lines.append("## Flag flow")
    lines.append("")
    lines.append(f"- Pattern source: `{flow['pattern_source']}` (known: {flow['pattern_known']})")
    if flow["mask"]:
        lines.append(f"- Mask: `{flow['mask']}`")
    lines.append(f"- Put candidates: {len(flow['put_points'])} · Get candidates: {len(flow['get_points'])}")
    lines.append("")
    lines.append("See `flagflow.md` for the full walkthrough.")
    lines.append("")

    # ---- poisoning
    poison = payload["poisoning"]
    lines.append("## Flag poisoning policy")
    lines.append("")
    lines.append(f"- Enabled: **{poison['enabled']}**")
    lines.append(f"- Checker traffic: {poison['checker_policy']}")
    lines.append(f"- Unclassified traffic: {poison['unknown_policy']}")
    lines.append(f"- Team traffic: {poison['team_policy']}")
    lines.append(f"- Requires: {poison['requires']}")
    if poison.get("error"):
        lines.append(f"- **Not available:** {poison['error']}")
    lines.append("")

    lines.append("## Files in this directory")
    lines.append("")
    for name, desc in (
        ("report.md", "this document"),
        ("report.json", "full machine-readable report; start here when feeding an agent"),
        ("findings.json", "static findings only"),
        ("findings.csv", "static findings, spreadsheet-friendly"),
        ("requests.csv", "every observed request with bodies and flag hits"),
        ("requests.md", "human-readable request digest"),
        ("flagflow.md", "put/get inference walkthrough"),
        ("poison.json", "poisoning policy and parameters"),
        ("run.json", "run metadata"),
    ):
        lines.append(f"- `{name}` — {desc}")
    lines.append("")
    return "\n".join(lines)


def _requests_md(cfg, runtime) -> str:
    lines = [f"# {cfg.service_name} — request digest", ""]
    for actor, profile in sorted(runtime.profiles.items()):
        lines.append(f"## Actor: {actor}")
        lines.append("")
        lines.append(f"- Requests: {profile.requests}")
        lines.append(f"- IPs: {', '.join('`%s`' % ip for ip in sorted(profile.ips))}")
        lines.append(f"- Flag reads: {profile.flag_reads}")
        lines.append(f"- Flag writes: {profile.flag_writes}")
        if profile.credential_pairs:
            pairs = ", ".join(f"`{u}:{p}`" for u, p in sorted(profile.credential_pairs))
            lines.append(f"- Credential pairs seen: {pairs}")
        lines.append("")
        lines.append("| Route | Count |")
        lines.append("| --- | ---: |")
        for route, count in sorted(profile.routes.items(), key=lambda kv: -kv[1]):
            lines.append(f"| `{route}` | {count} |")
        lines.append("")
    return "\n".join(lines)


def _flagflow_md(cfg, flow: FlagFlow) -> str:
    d = flow.to_dict()
    lines = [f"# {cfg.service_name} — flag flow", ""]
    lines.append(f"- Pattern source: `{d['pattern_source']}`")
    lines.append(f"- Pattern confirmed: {d['pattern_known']}")
    if d["mask"]:
        lines.append(f"- Literal mask: `{d['mask']}`")
    lines.append("")
    if d["warnings"]:
        lines.append("## Warnings")
        lines.append("")
        for w in d["warnings"]:
            lines.append(f"- {w}")
        lines.append("")
    for title, key in (
        ("Put (write) candidates", "put_points"),
        ("Get (read) candidates", "get_points"),
        ("Storage hints", "storage_hints"),
        ("Exposure hints", "exposure_hints"),
    ):
        rows = d[key]
        lines.append(f"## {title} ({len(rows)})")
        lines.append("")
        if not rows:
            lines.append("_none identified_")
            lines.append("")
            continue
        for row in rows[:80]:
            loc = f"`{row['file']}:{row['line']}`" if row["file"] else ""
            lines.append(f"- {row['kind']} {loc} — `{row['detail']}`")
        if len(rows) > 80:
            lines.append(f"- _… {len(rows) - 80} more in report.json_")
        lines.append("")
    return "\n".join(lines)