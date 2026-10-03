/**
 * One-call pipeline: load a config, scan, attribute runtime traffic, infer flag
 * flow, and write the report directory.
 *
 * Kept separate from the CLI and the HTTP layer so both share identical
 * behaviour and the tests can exercise the same code path the server uses.
 */

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import path from 'node:path';
import { loadConfig, type Config } from './config.js';
import { inferFlow, type FlagFlow } from './flags.js';
import { scan, type ScanResult } from './sast.js';
import { inferTopology, type Topology } from './topology.js';
import { createRuntimeReport, loadRequests, type RuntimeReport } from './requests.js';
import { buildReport, serviceDir, writeAll, type WriteAllResult } from './report.js';

export interface AnalysisResult {
  cfg: Config;
  scan: ScanResult;
  runtime: RuntimeReport;
  flow: FlagFlow;
  topology: Topology;
  report: WriteAllResult;
  /** Set when a misconfiguration degraded the run instead of failing it. */
  degraded: string[];
  /**
   * IP -> actor assignments applied by `classifyIps`. Empty when the option was
   * off, and the mapping is returned rather than re-derived because
   * `classifyUnknown` is idempotent: a second call would report nothing.
   */
  classified: Record<string, string>;
}

export interface AnalyzeOptions {
  /** Re-attribute `unknown` IPs from the configured networks. */
  classifyIps?: boolean;
  /** Override the report output directory. */
  outputDir?: string;
  /** Analyse without writing anything. */
  dryRun?: boolean;
}

function readSourceTexts(cfg: Config): Map<string, string> {
  const out = new Map<string, string>();
  for (const root of cfg.sourceRoots) {
    let stat;
    try {
      stat = statSync(root);
    } catch {
      continue;
    }
    const walk = (absolute: string, rel: string): void => {
      let entries: string[];
      try {
        entries = readdirSync(absolute).sort();
      } catch {
        return;
      }
      for (const entry of entries) {
        const child = path.join(absolute, entry);
        const childRel = rel ? `${rel}/${entry}` : entry;
        let childStat;
        try {
          childStat = statSync(child);
        } catch {
          continue;
        }
        if (childStat.isDirectory()) {
          walk(child, childRel);
        } else if (childStat.isFile()) {
          try {
            if (childStat.size > 2_000_000) continue;
            out.set(childRel, readFileSync(child, 'utf8').replace(/^\uFEFF/, ''));
          } catch {
            /* unreadable file: skip */
          }
        }
      }
    };
    if (stat.isFile()) {
      try {
        out.set(path.basename(root), readFileSync(root, 'utf8'));
      } catch {
        /* ignore */
      }
    } else {
      walk(root, '');
    }
  }
  return out;
}

export function analyzeConfig(cfg: Config, options: AnalyzeOptions = {}): AnalysisResult {
  const degraded: string[] = [];
  const result = scan(cfg.sourceRoots, cfg.excludedGlobs);
  const texts = readSourceTexts(cfg);

  const runtime =
    cfg.requestLogs.length > 0
      ? loadRequests(cfg.requestLogs, cfg)
      : createRuntimeReport();
  if (cfg.requestLogs.length === 0) {
    degraded.push('no request_logs configured; runtime sections are empty');
  }

  let classified: Record<string, string> = {};
  if (options.classifyIps) {
    classified = runtime.classifyUnknown(cfg);
    if (Object.keys(classified).length > 0) {
      degraded.push(
        `classified ${Object.keys(classified).length} address(es) from configured networks`,
      );
    }
  }

  // `inferFlow` only wants the observed route keys to spot flag-shaped paths.
  const observedRoutes: Record<string, { method: string; path: string }[]> = {};
  for (const row of runtime.routeMatrix()) {
    const [method = '?', routePath = '?'] = row.route.split(' ');
    (observedRoutes.__all__ ??= []).push({ method, path: routePath });
  }
  const flow = inferFlow(cfg, texts, observedRoutes);
  // The observed reads are a separate signal from the code-level get points:
  // they prove an actor actually pulled a flag at runtime.
  flow.observedCheckerReads = runtime
    .routeMatrix()
    .filter((row) => row.actors.checker?.flag_reads)
    .map((row) => row.route);
  flow.observedTeamReads = runtime
    .routeMatrix()
    .filter((row) => row.actors.team?.flag_reads)
    .map((row) => row.route);
  const topology = inferTopology(texts.values());

  let report: WriteAllResult;
  if (options.dryRun) {
    // Build the identical content but do not touch the filesystem, so a display
    // only caller gets real data instead of an empty payload.
    report = {
      outDir: options.outputDir ?? serviceDir(cfg, options.outputDir),
      payload: buildReport(cfg, result, runtime, flow, topology).payload,
    };
  } else {
    report = writeAll(cfg, result, runtime, flow, topology, options.outputDir);
  }

  return { cfg, scan: result, runtime, flow, topology, report, degraded, classified };
}

export function analyzeConfigPath(
  configPath: string,
  options: AnalyzeOptions = {},
): AnalysisResult {
  if (!existsSync(configPath)) {
    throw new Error(`config not found: ${configPath}`);
  }
  return analyzeConfig(loadConfig(configPath), options);
}

/** Discover every service config in a directory. */
export function discoverConfigs(configDir: string): string[] {
  if (!existsSync(configDir)) return [];
  return readdirSync(configDir)
    .filter((name) => name.endsWith('.json'))
    .sort()
    .map((name) => path.join(configDir, name));
}
