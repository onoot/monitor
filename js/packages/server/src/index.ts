/**
 * HTTP layer over the analysis engine.
 *
 * Every route reads through the same `analyzeConfig` entry point the CLI uses, so
 * the dashboard can never show a result the command line would not produce.
 */

import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import cors from 'cors';
import express, { type NextFunction, type Request, type Response } from 'express';
import {
  analyzeConfigPath,
  ConfigError,
  discoverConfigs,
  loadConfig,
  Poisoner,
  PoisonerMisconfigured,
  reportMd,
  RULES,
  SCHEMA_VERSION,
  VERSION,
  type AnalysisResult,
} from '@ad/engine';

/** Repository root, derived from this file's location rather than the cwd. */
const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REPO_ROOT = path.resolve(PACKAGE_ROOT, '..', '..', '..');

/** Where the service configs live. Overridable for tests and deployments. */
const CONFIG_DIR = path.resolve(process.env.AD_CONFIG_DIR ?? path.join(REPO_ROOT, 'configs'));

/** Scans are synchronous and can take seconds; cache per service until re-run. */
interface CacheEntry {
  at: number;
  analysis: AnalysisResult;
  summary: ServiceSummary;
}

const cache = new Map<string, CacheEntry>();

export interface ServiceSummary {
  name: string;
  filesScanned: number;
  filesSkipped: number;
  findings: number;
  requests: number;
  severities: Record<string, number>;
  warnings: string[];
  generatedUtc: string;
}

function countBy(items: readonly unknown[], key: string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const item of items) {
    const value = (item as Record<string, unknown> | null)?.[key];
    if (typeof value !== 'string') continue;
    out[value] = (out[value] ?? 0) + 1;
  }
  return out;
}

/**
 * Reject a service name that is not a plain filename stem.
 *
 * `resolveConfig` already matches against discovered configs, so this is belt
 * and braces: it also keeps the name safe to echo into a response body.
 */
const SAFE_NAME = /^[A-Za-z0-9._-]+$/;

function assertSafeName(name: string): string {
  if (!SAFE_NAME.test(name) || name === '.' || name === '..') {
    throw new HttpError(400, `invalid service name: ${JSON.stringify(name)}`);
  }
  return name;
}

function summarise(payload: Record<string, unknown>, configPath: string): ServiceSummary {
  const meta = (payload.meta ?? {}) as Record<string, unknown>;
  const findings = (payload.findings ?? []) as unknown[];
  return {
    name: String(meta.service ?? path.basename(configPath, '.json')),
    filesScanned: Number(meta.files_scanned ?? 0),
    filesSkipped: Number(meta.files_skipped ?? 0),
    findings: findings.length,
    requests: Number(meta.request_records ?? 0),
    severities: countBy(findings, 'severity'),
    warnings: (payload.warnings ?? []) as string[],
    generatedUtc: String(meta.generated_utc ?? ''),
  };
}

export function cacheFor(service: string): CacheEntry | undefined {
  return cache.get(service);
}

export function clearCache(service?: string): void {
  if (service) cache.delete(service);
  else cache.clear();
}

/**
 * Resolve a service name to a config file.
 *
 * The name comes from the URL, so it is matched against the discovered config
 * filenames rather than joined onto a directory. That makes traversal
 * impossible instead of merely unlikely.
 */
function resolveConfig(rawName: string): string {
  const name = assertSafeName(rawName);
  const configs = discoverConfigs(CONFIG_DIR);
  const match = configs.find(
    (configPath) => path.basename(configPath, '.json') === name,
  );
  if (!match) {
    throw new HttpError(404, `unknown service: ${name}`);
  }
  return match;
}

export class HttpError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
  }
}

/** Run or reuse an analysis for one service. */
function analysisFor(name: string, force = false): CacheEntry {
  if (!force) {
    const cached = cache.get(name);
    if (cached) return cached;
  }
  const configPath = resolveConfig(name);
  // `dryRun` computes the identical payload but skips the filesystem writes, so
  // a dashboard refresh never clobbers the operator's report directory.
  const analysis = analyzeConfigPath(configPath, { dryRun: true });
  const entry: CacheEntry = {
    at: Date.now(),
    analysis,
    summary: summarise(analysis.report.payload, configPath),
  };
  cache.set(name, entry);
  return entry;
}

function asInt(value: unknown, fallback: number): number {
  const parsed = Number.parseInt(String(value ?? ''), 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

export function createApp(): express.Express {
  const app = express();

  // The dashboard is same-origin in production (the server serves the bundle)
  // and proxied in development, so CORS is off unless an operator opts in to
  // hosting the UI separately. No credentials are ever accepted.
  const corsOrigin = process.env.AD_CORS_ORIGIN;
  if (corsOrigin) {
    app.use(cors({ origin: corsOrigin.split(',').map((value) => value.trim()) }));
  }
  app.use(express.json({ limit: '1mb' }));

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true, version: VERSION, schema: SCHEMA_VERSION, configDir: CONFIG_DIR });
  });

  app.get('/api/services', (_req, res) => {
    const configs = discoverConfigs(CONFIG_DIR);
    const services = configs.map((configPath) => {
      const name = path.basename(configPath, '.json');
      // A service that fails to analyse must not hide the other services.
      try {
        return analysisFor(name).summary;
      } catch (error) {
        return {
          name,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    });
    res.json({ services });
  });

  app.get('/api/services/:name', (req, res) => {
    const entry = analysisFor(req.params.name, req.query.refresh === '1');
    res.json(entry.analysis.report.payload);
  });

  app.get('/api/services/:name/findings', (req, res) => {
    const entry = analysisFor(req.params.name);
    const findings = (entry.analysis.report.payload.findings ?? []) as Record<string, unknown>[];
    const severity = typeof req.query.severity === 'string' ? req.query.severity : '';
    const ruleId = typeof req.query.rule === 'string' ? req.query.rule : '';
    const category = typeof req.query.category === 'string' ? req.query.category : '';
    const search = typeof req.query.q === 'string' ? req.query.q.toLowerCase() : '';

    // The report payload is snake_case (`rule_id`), matching report.json.
    const filtered = findings.filter((finding) => {
      if (severity && finding.severity !== severity) return false;
      if (ruleId && finding.rule_id !== ruleId) return false;
      if (category && finding.category !== category) return false;
      if (search) {
        const haystack =
          `${String(finding.title)} ${String(finding.description)} ` +
          `${JSON.stringify(finding.evidence)}`.toLowerCase();
        if (!haystack.includes(search)) return false;
      }
      return true;
    });

    const limit = asInt(req.query.limit, 100);
    const offset = asInt(req.query.offset, 0);
    res.json({
      total: filtered.length,
      limit,
      offset,
      findings: filtered.slice(offset, offset + limit),
    });
  });

  app.get('/api/services/:name/routes', (req, res) => {
    const entry = analysisFor(req.params.name);
    const routes = (entry.analysis.report.payload.routes ?? []) as Record<string, unknown>[];
    const unguarded = (entry.analysis.report.payload.unguarded_id_routes ?? []) as Record<string, unknown>[];
    res.json({
      total: routes.length,
      unguarded_id_routes: unguarded.length,
      routes,
      unguarded,
    });
  });

  app.get('/api/services/:name/flagflow', (req, res) => {
    const entry = analysisFor(req.params.name);
    res.json(entry.analysis.report.payload.flag_flow ?? {});
  });

  app.get('/api/services/:name/runtime', (req, res) => {
    const entry = analysisFor(req.params.name);
    res.json(entry.analysis.report.payload.runtime ?? {});
  });

  /**
   * Ask what would happen to one flag. Reports the decision; never mutates
   * anything, and never returns a poisoned value for the checker.
   */
  app.post('/api/poison', (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const flag = String(body.flag ?? '');
    if (!flag) throw new HttpError(400, 'flag is required');
    const actor = String(body.actor ?? 'team');
    if (!['checker', 'team', 'unknown'].includes(actor)) {
      throw new HttpError(400, `unknown actor: ${actor}`);
    }
    const configPath = resolveConfig(String(body.config ?? body.service ?? ''));

    const cfg = loadConfig(configPath);
    let poisoner: Poisoner;
    try {
      poisoner = new Poisoner(cfg);
    } catch (error) {
      if (error instanceof PoisonerMisconfigured) {
        // `error` carries the same text as `reason` so a client that only reads
        // the standard error field still gets the reason rather than a bare 409.
        res.status(409).json({
          action: 'disabled',
          reason: error.message,
          error: error.message,
        });
        return;
      }
      throw error;
    }
    const decision = poisoner.decide(
      actor,
      String(body.team ?? 't0'),
      String(body.endpoint ?? '/'),
      flag,
    );
    res.json({
      action: decision.action,
      reason: decision.reason,
      actor: decision.actor,
      team_key: decision.teamKey,
      flag_in: flag,
      // `decision.value` is null for every non-poison action. Report the
      // effective outgoing value instead, so a client that echoes this back
      // can never hand the checker a null where the real flag belongs.
      flag_out: decision.value ?? flag,
    });
  });

  app.get('/api/rules', (req, res) => {
    if (req.query.category) {
      const category = String(req.query.category);
      res.json({ rules: RULES.filter((rule) => rule.category === category) });
      return;
    }
    res.json({
      total: RULES.length,
      rules: RULES.map((rule) => ({
        id: rule.id,
        category: rule.category,
        title: rule.title,
        severity: rule.severity,
        source: rule.source,
        flags: rule.flags,
        languages: [...rule.languages],
        description: rule.description,
        exploit: rule.exploit,
        breaker: rule.breaker,
        remediation: rule.remediation,
        cwe: [...rule.cwe],
        sources: [...rule.sources],
      })),
    });
  });

  /**
   * The Markdown report, rendered from the same payload `report.json` carries.
   *
   * Rendering in memory rather than reading report.md off disk means the tab
   * works on a fresh checkout, where no CLI scan has written a report yet.
   */
  app.get('/api/services/:name/report.md', (req, res) => {
    const { analysis } = analysisFor(req.params.name);
    res.type('text/markdown').send(reportMd(analysis.cfg, analysis.report.payload, analysis.runtime));
  });

  // Serve the built dashboard when it exists, so one process runs the whole
  // tool. In development Vite serves the bundle and proxies /api here instead.
  const webDist = path.resolve(
    process.env.AD_WEB_DIST ?? path.join(REPO_ROOT, 'js', 'packages', 'web', 'dist'),
  );
  if (existsSync(path.join(webDist, 'index.html'))) {
    app.use(express.static(webDist));
    // Client-side routing: unknown non-API paths fall through to the SPA shell.
    app.get(/^(?!\/api\/).*/, (_req, res) => {
      res.sendFile(path.join(webDist, 'index.html'));
    });
  }

  app.use((_req, res) => {
    res.status(404).json({ error: 'not found' });
  });

  app.use((error: Error, _req: Request, res: Response, _next: NextFunction) => {
    if (error instanceof HttpError) {
      res.status(error.status).json({ error: error.message });
      return;
    }
    if (error instanceof ConfigError) {
      res.status(400).json({ error: error.message });
      return;
    }
    res.status(500).json({ error: error.message });
  });

  return app;
}

// Compare through `pathToFileURL` rather than string-building the URL: this
// path contains non-ASCII characters, which `import.meta.url` percent-encodes.
const entry = process.argv[1];
const isMain = entry !== undefined && import.meta.url === pathToFileURL(entry).href;

if (isMain) {
  const port = Number.parseInt(process.env.AD_PORT ?? '8787', 10);
  const app = createApp();
  app.listen(port, () => {
    process.stdout.write(`ad server listening on http://localhost:${port}\n`);
    process.stdout.write(`configs: ${CONFIG_DIR}\n`);
    if (
      existsSync(
        path.resolve(
          process.env.AD_WEB_DIST ??
            path.join(REPO_ROOT, 'js', 'packages', 'web', 'dist'),
          'index.html',
        ),
      )
    ) {
      process.stdout.write('dashboard: bundled and served from this process\n');
    } else {
      process.stdout.write('dashboard: run `npm run dev -w @ad/web` for the dev server\n');
    }
  });
}
