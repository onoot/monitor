/**
 * Per-service report generation.
 *
 * Each service gets its own directory:
 *
 *     reports/<service>/
 *         report.md            human-readable
 *         report.json          machine-readable (stable schema, for an agent)
 *         findings.json
 *         findings.csv
 *         requests.csv
 *         requests.md
 *         flagflow.md
 *         poison.json
 *         run.json
 *
 * report.json is the contract an AI consumes; report.md is the contract a human
 * reads. They are generated from the same data so they cannot drift.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import type { Config } from './config.js';
import { flagFlowToDict, type FlagFlow } from './flags.js';
import { Poisoner, PoisonerMisconfigured } from './poison.js';
import { writeRequestsCsv, type RuntimeReport } from './requests.js';
import { findingToDict, sortFindings, type Finding } from './models.js';
import { unguardedIdRoutes, type ScanResult } from './sast.js';
import { lifecycle, type Topology } from './topology.js';

export const SCHEMA_VERSION = '1.0';

export function serviceDir(cfg: Config, root?: string): string {
  return path.join(root ?? cfg.outputDir, cfg.serviceName);
}

function writeJson(file: string, value: unknown): void {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function counts<T>(items: readonly T[], key: (item: T) => string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const item of items) {
    const name = key(item);
    out[name] = (out[name] ?? 0) + 1;
  }
  return Object.fromEntries(
    Object.entries(out).sort((a, b) => b[1] - a[1]),
  );
}

export function warningsFor(
  cfg: Config,
  scan: ScanResult,
  runtime: RuntimeReport,
  flow: FlagFlow,
  topo: Topology,
): string[] {
  const warnings: string[] = [];
  if (!cfg.hasFlagFormat()) {
    warnings.push(
      'flag_format.pattern is not set: flag put/get cannot be verified and poisoning is disabled.',
    );
  }
  if (cfg.teamNetworks.length === 0) {
    warnings.push(
      "No team_networks configured. Runtime IPs will classify as 'unknown' and are never poisoned.",
    );
  }
  if (cfg.checkerNetworks.length === 0 && !cfg.checkerIpPattern) {
    warnings.push(
      'No checker_networks or checker_ip_pattern configured. Checker traffic cannot be identified; ' +
        'treat all traffic as team traffic for reporting only, never for poisoning.',
    );
  }
  if (topo.inferred() && cfg.teamNetworks.length > 0) {
    const overlaps = topo.overlapsConfiguredTeamNetworks(
      cfg.teamNetworks.map((net) => net.cidr),
    );
    if (overlaps.length > 0) {
      warnings.push(
        'Inferred team IPs overlap configured team networks: ' +
          [...new Set(overlaps)].sort().join(', '),
      );
    }
  }
  if (scan.filesScanned === 0) {
    warnings.push('No source files were scanned; static findings are empty.');
  }
  if (runtime.parserNotes.length > 0) {
    warnings.push(
      `${runtime.parserNotes.length} request log lines could not be parsed.`,
    );
  }
  warnings.push(...flow.warnings);
  return warnings;
}

export interface WriteAllResult {
  outDir: string;
  payload: Record<string, unknown>;
}

/** The full report content, before it is serialised to disk. */
export interface ReportBundle {
  payload: Record<string, unknown>;
  findings: Finding[];
  poisonPolicy: Record<string, unknown>;
  runMeta: Record<string, unknown>;
}

/**
 * Build the report content without touching the filesystem.
 *
 * Separated from `writeAll` so a dry run returns exactly what a real run would
 * produce; otherwise a caller that only wanted the payload for display would get
 * an empty object and silently render a blank dashboard.
 */
export function buildReport(
  cfg: Config,
  scan: ScanResult,
  runtime: RuntimeReport,
  flow: FlagFlow,
  topo: Topology,
): ReportBundle {
  let poisonPolicy: Record<string, unknown>;
  try {
    poisonPolicy = new Poisoner(cfg).describe();
  } catch (error) {
    // A scan is still useful without a key, so report the gap instead of failing.
    if (!(error instanceof PoisonerMisconfigured)) throw error;
    poisonPolicy = {
      enabled: false,
      flag_pattern: cfg.flagFormat.pattern,
      mask: null,
      prefix: cfg.flagFormat.prefix,
      envelope: [],
      alphabet: '',
      checker_policy: 'never modify',
      unknown_policy: 'never modify',
      team_policy: 'disabled: no private key available',
      requires: 'flag_format.pattern in the service config and AD_POISON_SECRET',
      secret_source: 'AD_POISON_SECRET',
      error: error.message,
    };
  }

  const findings = sortFindings(scan.findings);
  const idorRoutes = unguardedIdRoutes(scan.routes);

  const runMeta = {
    schema_version: SCHEMA_VERSION,
    service: cfg.serviceName,
    // `Z` and a `+00:00` offset are the same instant, but the offset form is
    // what the Python implementation emits and consumers may string-match.
    generated_utc: `${new Date().toISOString().slice(0, 19)}+00:00`,
    source_roots: [...cfg.sourceRoots],
    files_scanned: scan.filesScanned,
    files_skipped: scan.filesSkipped,
    request_records: runtime.requests.length,
    rules_evaluated: 'see @ad/engine rules',
    notes: cfg.notes,
  };

  const payload: Record<string, unknown> = {
    meta: runMeta,
    topology: {
      checker_ip_pattern: topo.ipPattern,
      inferred_team_ips: Object.fromEntries(topo.teamIps),
      configured_team_networks: cfg.teamNetworks.map((net) => ({
        label: net.label,
        cidr: net.cidr,
        source: net.source,
      })),
      configured_checker_networks: cfg.checkerNetworks.map((net) => ({
        label: net.label,
        cidr: net.cidr,
        source: net.source,
      })),
      checker_lifecycle: lifecycle().map((phase) => ({
        phase: phase.key,
        description: phase.description,
        expected_actor: phase.expectedActor,
      })),
    },
    findings: findings.map(findingToDict),
    finding_counts: counts(findings, (item) => item.severity),
    category_counts: counts(findings, (item) => item.category),
    routes: scan.routes.map((route) => route.toDict()),
    unguarded_id_routes: idorRoutes.map((route) => route.toDict()),
    runtime: {
      actors: Object.fromEntries(
        [...runtime.profiles.entries()].map(([name, profile]) => [name, profile.toDict()]),
      ),
      route_matrix: runtime.routeMatrix(),
      cross_actor_observations: runtime.crossActorFindings,
      parser_notes: runtime.parserNotes,
    },
    flag_flow: flagFlowToDict(flow),
    poisoning: poisonPolicy,
    warnings: warningsFor(cfg, scan, runtime, flow, topo),
  };

  return { payload, findings, poisonPolicy, runMeta };
}

/**
 * Build and write every artefact. Returns the payload so the HTTP layer can serve
 * exactly what landed on disk without re-reading it.
 */
export function writeAll(
  cfg: Config,
  scan: ScanResult,
  runtime: RuntimeReport,
  flow: FlagFlow,
  topo: Topology,
  root?: string,
): WriteAllResult {
  const out = serviceDir(cfg, root);
  mkdirSync(out, { recursive: true });

  const { payload, findings, poisonPolicy, runMeta } = buildReport(
    cfg,
    scan,
    runtime,
    flow,
    topo,
  );

  writeJson(path.join(out, 'report.json'), payload);
  writeJson(path.join(out, 'findings.json'), findings.map(findingToDict));
  writeJson(path.join(out, 'poison.json'), poisonPolicy);
  writeJson(path.join(out, 'run.json'), runMeta);

  writeFileSync(
    path.join(out, 'findings.csv'),
    findingsCsv(findings),
    'utf8',
  );
  if (runtime.requests.length > 0) {
    writeRequestsCsv(runtime, path.join(out, 'requests.csv'));
    writeFileSync(path.join(out, 'requests.md'), requestsMd(runtime), 'utf8');
  }
  writeFileSync(path.join(out, 'flagflow.md'), flagflowMd(cfg, flow), 'utf8');
  writeFileSync(
    path.join(out, 'report.md'),
    reportMd(cfg, payload, runtime),
    'utf8',
  );

  return { outDir: out, payload };
}

function csvCell(value: string): string {
  if (/[",\n\r]/.test(value)) return `"${value.replace(/"/g, '""')}"`;
  return value;
}

export function findingsCsv(findings: readonly Finding[]): string {
  const rows: string[] = [
    [
      'severity', 'confidence', 'category', 'rule_id', 'file', 'line',
      'title', 'cwe', 'exploit', 'breaker', 'remediation', 'snippet',
    ].join(','),
  ];
  for (const item of findings) {
    rows.push(
      [
        item.severity,
        item.confidence,
        item.category,
        item.ruleId,
        item.evidence.file,
        String(item.evidence.line),
        item.title,
        item.cwe.join('|'),
        item.exploit,
        item.breaker,
        item.remediation,
        item.evidence.snippet,
      ]
        .map((cell) => csvCell(String(cell)))
        .join(','),
    );
  }
  return `${rows.join('\n')}\n`;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function asArray(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? (value as Record<string, unknown>[]) : [];
}

function asStringMap(value: unknown): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [key, count] of Object.entries(asRecord(value))) {
    out[key] = Number(count);
  }
  return out;
}

export function reportMd(
  cfg: Config,
  payload: Record<string, unknown>,
  runtime: RuntimeReport,
): string {
  const lines: string[] = [];
  const meta = asRecord(payload.meta);
  const sevCounts = asStringMap(payload.finding_counts);

  lines.push(`# ${cfg.serviceName} — A/D analysis`, '');
  lines.push(
    `Generated ${String(meta.generated_utc)} · ${String(meta.files_scanned)} source files · ` +
      `${String(meta.request_records)} runtime records`,
    '',
  );
  if (cfg.notes) {
    lines.push(`> Operator note: ${cfg.notes}`, '');
  }

  const warn = asArray(payload.warnings).map((item) => String(item));
  if (warn.length > 0) {
    lines.push('## Read this first', '');
    for (const item of warn) lines.push(`- ${item}`);
    lines.push('');
  }

  lines.push('## Summary', '', '| Severity | Count |', '| --- | ---: |');
  for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
    if (sev in sevCounts) lines.push(`| ${sev} | ${sevCounts[sev]} |`);
  }
  lines.push('');

  const categoryCounts = asRecord(payload.category_counts);
  if (Object.keys(categoryCounts).length > 0) {
    lines.push('| Category | Count |', '| --- | ---: |');
    for (const [cat, count] of Object.entries(categoryCounts)) {
      lines.push(`| ${cat} | ${count} |`);
    }
    lines.push('');
  }

  // ---- topology
  const topo = asRecord(payload.topology);
  const inferred = asRecord(topo.inferred_team_ips);
  lines.push('## Instance topology', '');
  if (topo.checker_ip_pattern) {
    lines.push(`- Checker \`IP_PATTERN\`: \`${String(topo.checker_ip_pattern)}\``);
    const sample = Object.entries(inferred).slice(0, 8);
    if (sample.length > 0) {
      lines.push(
        '- Inferred team instances: ' +
          sample.map(([num, ip]) => `\`${num}\`→\`${ip}\``).join(', '),
      );
    }
  } else {
    lines.push(
      '- Checker `IP_PATTERN` not found in source. Ask the operator; do not assume a default.',
    );
  }
  lines.push('', '| Network role | CIDR | Source |', '| --- | --- | --- |');
  for (const net of asArray(topo.configured_team_networks)) {
    lines.push(`| team | \`${String(net.cidr)}\` | ${String(net.source)} |`);
  }
  for (const net of asArray(topo.configured_checker_networks)) {
    lines.push(`| checker | \`${String(net.cidr)}\` | ${String(net.source)} |`);
  }
  if (
    asArray(topo.configured_team_networks).length === 0 &&
    asArray(topo.configured_checker_networks).length === 0
  ) {
    lines.push('| _none configured_ | | |');
  }
  lines.push('');

  // ---- lifecycle
  lines.push(
    '## Checker lifecycle (expected traffic)',
    '',
    '| Phase | Expected actor | Description |',
    '| --- | --- | --- |',
  );
  for (const phase of asArray(topo.checker_lifecycle)) {
    lines.push(
      `| ${String(phase.phase)} | ${String(phase.expected_actor)} | ${String(phase.description)} |`,
    );
  }
  lines.push('');

  // ---- findings
  lines.push('## Findings', '');
  const findings = asArray(payload.findings);
  if (findings.length === 0) {
    lines.push('No static findings.', '');
  }
  let current: string | null = null;
  for (const item of findings) {
    if (item.severity !== current) {
      current = String(item.severity);
      lines.push(`### **${current.toUpperCase()}**`, '');
    }
    lines.push(`#### ${String(item.rule_id)} · ${String(item.title)}`, '');
    const cwe = asArray(item.cwe).map(String);
    lines.push(
      `- Category: \`${String(item.category)}\` · Confidence: \`${String(item.confidence)}\`` +
        (cwe.length > 0 ? ` · CWE: ${cwe.join(', ')}` : ''),
    );
    const ev = asRecord(item.evidence);
    lines.push(`- Evidence: \`${String(ev.file)}:${String(ev.line)}\``);
    const sources = asArray(item.rule_sources).map(String);
    lines.push(
      `- Pattern source: ${sources.length > 0 ? sources.join(', ') : 'local rules'}`,
    );
    lines.push('');
    if (item.description) lines.push(String(item.description), '');
    if (item.exploit) lines.push(`- **Team exploit path**: ${String(item.exploit)}`);
    if (item.breaker) lines.push(`- **Checker-breaking**: ${String(item.breaker)}`);
    if (item.remediation) lines.push(`- **Fix**: ${String(item.remediation)}`);
    lines.push('', '```', String(ev.snippet), '```', '');
  }

  // ---- routes
  const routes = asArray(payload.routes);
  const unguarded = asArray(payload.unguarded_id_routes);
  lines.push('## Route inventory', '');
  lines.push(
    `${routes.length} routes extracted · ` +
      `${unguarded.length} take an object id with no auth hint nearby`,
    '',
  );
  if (unguarded.length > 0) {
    lines.push('| Method | Path | Location |', '| --- | --- | --- |');
    for (const route of unguarded) {
      lines.push(
        `| ${String(route.method)} | \`${String(route.path)}\` | \`${String(route.file)}:${String(route.line)}\` |`,
      );
    }
    lines.push(
      '',
      'These are candidates only: confirm at runtime before reporting as IDOR.',
      '',
    );
  }

  // ---- runtime
  lines.push('## Runtime traffic', '');
  if (runtime.requests.length === 0) {
    lines.push(
      'No request logs configured. Add `request_logs` to the service config.',
      '',
    );
  } else {
    lines.push(
      '| Actor | Requests | Distinct routes | Flag reads | Flag writes | IPs |',
      '| --- | ---: | ---: | ---: | ---: | --- |',
    );
    const actors = asRecord(asRecord(payload.runtime).actors);
    for (const [actor, raw] of Object.entries(actors).sort(([a], [b]) => (a < b ? -1 : 1))) {
      const profile = asRecord(raw);
      const ips = Array.isArray(profile.ips) ? (profile.ips as unknown[]).map(String) : [];
      lines.push(
        `| ${actor} | ${String(profile.request_count)} | ${String(profile.distinct_routes)} | ` +
          `${String(profile.flag_reads)} | ${String(profile.flag_writes)} | ` +
          `${ips.slice(0, 6).map((ip) => `\`${ip}\``).join(', ')} |`,
      );
    }
    lines.push('');
    const cross = asArray(asRecord(payload.runtime).cross_actor_observations).map(String);
    if (cross.length > 0) {
      lines.push('### Cross-actor observations', '');
      for (const note of cross) lines.push(`- ${note}`);
      lines.push('');
    }
    lines.push('Full request/response detail: `requests.csv`, `requests.md`.', '');
  }

  // ---- flag flow
  const flow = asRecord(payload.flag_flow);
  lines.push('## Flag flow', '');
  lines.push(
    `- Pattern source: \`${String(flow.pattern_source)}\` (known: ${String(flow.pattern_known)})`,
  );
  if (flow.mask) lines.push(`- Mask: \`${String(flow.mask)}\``);
  lines.push(
    `- Put candidates: ${asArray(flow.put_points).length} · ` +
      `Get candidates: ${asArray(flow.get_points).length}`,
  );
  lines.push('', 'See `flagflow.md` for the full walkthrough.', '');

  // ---- poisoning
  const poison = asRecord(payload.poisoning);
  lines.push('## Flag poisoning policy', '');
  lines.push(`- Enabled: **${String(poison.enabled)}**`);
  lines.push(`- Checker traffic: ${String(poison.checker_policy)}`);
  lines.push(`- Unclassified traffic: ${String(poison.unknown_policy)}`);
  lines.push(`- Team traffic: ${String(poison.team_policy)}`);
  lines.push(`- Requires: ${String(poison.requires)}`);
  if (poison.error) lines.push(`- **Not available:** ${String(poison.error)}`);
  lines.push('');

  lines.push('## Files in this directory', '');
  for (const [name, desc] of [
    ['report.md', 'this document'],
    ['report.json', 'full machine-readable report; start here when feeding an agent'],
    ['findings.json', 'static findings only'],
    ['findings.csv', 'static findings, spreadsheet-friendly'],
    ['requests.csv', 'every observed request with bodies and flag hits'],
    ['requests.md', 'human-readable request digest'],
    ['flagflow.md', 'put/get inference walkthrough'],
    ['poison.json', 'poisoning policy and parameters'],
    ['run.json', 'run metadata'],
  ] as [string, string][]) {
    lines.push(`- \`${name}\` — ${desc}`);
  }
  lines.push('');
  return lines.join('\n');
}

export function requestsMd(runtime: RuntimeReport): string {
  const lines: string[] = [];
  for (const [actor, profile] of [...runtime.profiles.entries()].sort(([a], [b]) =>
    a < b ? -1 : 1,
  )) {
    lines.push(`## Actor: ${actor}`, '');
    lines.push(`- Requests: ${profile.requests}`);
    lines.push(`- IPs: ${[...profile.ips].sort().map((ip) => `\`${ip}\``).join(', ')}`);
    lines.push(`- Flag reads: ${profile.flagReads}`);
    lines.push(`- Flag writes: ${profile.flagWrites}`);
    if (profile.credentialPairs.size > 0) {
      lines.push(
        `- Credential pairs seen: ${[...profile.credentialPairs].sort().map((p) => `\`${p}\``).join(', ')}`,
      );
    }
    lines.push('', '| Route | Count |', '| --- | ---: |');
    for (const [route, count] of [...profile.routes.entries()].sort((a, b) => b[1] - a[1])) {
      lines.push(`| \`${route}\` | ${count} |`);
    }
    lines.push('');
  }
  return lines.join('\n');
}

export function flagflowMd(cfg: Config, flow: FlagFlow): string {
  const d = flagFlowToDict(flow) as unknown as Record<string, Record<string, unknown>[]>;
  const lines: string[] = [`# ${cfg.serviceName} — flag flow`, ''];
  lines.push(`- Pattern source: \`${String(d.pattern_source)}\``);
  lines.push(`- Pattern confirmed: ${String(d.pattern_known)}`);
  if (d.mask) lines.push(`- Literal mask: \`${String(d.mask)}\``);
  lines.push('');

  if (d.warnings && d.warnings.length > 0) {
    lines.push('## Warnings', '');
    for (const w of d.warnings as unknown as string[]) lines.push(`- ${w}`);
    lines.push('');
  }
  for (const [title, key] of [
    ['Put (write) candidates', 'put_points'],
    ['Get (read) candidates', 'get_points'],
    ['Storage hints', 'storage_hints'],
    ['Exposure hints', 'exposure_hints'],
  ] as [string, string][]) {
    const rows = d[key] ?? [];
    lines.push(`## ${title} (${rows.length})`, '');
    if (rows.length === 0) {
      lines.push('_none identified_', '');
      continue;
    }
    for (const row of rows.slice(0, 80)) {
      const r = asRecord(row);
      const loc = r.file ? `\`${String(r.file)}:${String(r.line)}\`` : '';
      lines.push(`- ${String(r.kind)} ${loc} — \`${String(r.detail)}\``);
    }
    if (rows.length > 80) {
      lines.push(`- _… ${rows.length - 80} more in report.json_`);
    }
    lines.push('');
  }
  return lines.join('\n');
}
