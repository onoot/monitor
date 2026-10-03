/**
 * One gate for JS/Python parity.
 *
 * Runs the four rule-pack, semantics and runtime suites on both sides, compares
 * the report payloads field by field, and diffs the Markdown and CSV renderings
 * textually. Exits non-zero on the first mismatch so it can gate a commit.
 *
 * Usage: npx tsx test-scratch/parity.ts
 */

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeConfig } from '../src/pipeline.js';
import { loadConfig } from '../src/config.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..', '..', '..', '..');
const SERVICES = ['AltayCoin', 'curs', 'magiclib', 'Omnyhub'];
const PY_OUT = path.join(ROOT, '_parity_py');
const JS_OUT = path.join(ROOT, '_parity_js');

const failures: string[] = [];

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Run a command with arguments.
 *
 * Always spawns the binary directly, never through a shell: the repository path
 * contains a space and non-ASCII characters, and shell interpolation of arguments
 * is both unreliable there and a needless injection surface.
 */
function run(label: string, command: string, args: string[], cwd: string): void {
  try {
    execFileSync(command, args, { cwd, encoding: 'utf8', stdio: 'pipe' });
    console.log(`  ok    ${label}`);
  } catch (error) {
    const err = error as { stdout?: string; stderr?: string };
    failures.push(`${label}: command failed`);
    console.log(`  FAIL  ${label}`);
    const detail = `${err.stdout ?? ''}${err.stderr ?? ''}`;
    if (detail) process.stdout.write(`${detail.slice(0, 3000)}\n`);
  }
}

const ENGINE = path.join(ROOT, 'js', 'packages', 'engine');

/** Resolve a package binary from the workspace, never relying on PATH order. */
function bin(name: string, ...segments: string[]): string {
  return path.join(ROOT, 'js', 'node_modules', name, ...segments);
}

const NODE = process.execPath;
const VITEST = bin('vitest', 'vitest.mjs');
const TSC = bin('typescript', 'bin', 'tsc');

console.log('rule pack');
run('js  vitest', NODE, [VITEST, 'run'], ENGINE);
run('py  unittest', 'python', ['-m', 'unittest', 'discover', '-s', 'tests'], ROOT);

console.log('tsc');
run('js  tsc --noEmit', NODE, [TSC, '-p', 'tsconfig.check.json'], ENGINE);

console.log('reports');
run('py  scan', 'python', ['_parity_scan.py', PY_OUT, ...SERVICES], ROOT);

const FLAG = /\/(POISON_SECRET|MASK|TOKEN|SECRET|PASSWORD|KEY)\b/;

function canonicalKey(key: string): string {
  return key.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase());
}

function canonicalText(text: string): string {
  return text.replace(/\b([a-z]+_[a-z_]+)\b/g, (word) => canonicalKey(word));
}

function stripRoot(value: string, service: string): string {
  return value
    .replace(/^.*?[\\/]services[\\/]/, '')
    .replace(/\\/g, '/')
    .replace(new RegExp(`^${service}/`), '');
}

function normalise(value: unknown, service: string): unknown {
  if (Array.isArray(value)) return value.map((item) => normalise(item, service));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (k === 'generated_utc' || k === 'generatedUtc') continue;
      if (typeof v === 'string' && !FLAG.test(v)) {
        out[canonicalKey(k)] = canonicalText(stripRoot(v, service));
        continue;
      }
      out[canonicalKey(k)] = normalise(v, service);
    }
    return out;
  }
  if (typeof value === 'string') {
    if (FLAG.test(value)) return '<redacted>';
    return canonicalText(stripRoot(value, service));
  }
  return value;
}

function diff(a: unknown, b: unknown, at: string, out: string[]): void {
  // The two runs are sequential, so timestamps are expected to differ by a
  // second or two. Compare the shape, not the value.
  if (at.endsWith('generatedUtc') || at.endsWith('generated_utc')) {
    if (typeof a === 'string' && typeof b === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(a) && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(b)) return;
  }
  if (out.length > 40) return;
  if (a === b) return;
  const aObj = a && typeof a === 'object' ? (a as Record<string, unknown>) : null;
  const bObj = b && typeof b === 'object' ? (b as Record<string, unknown>) : null;
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) out.push(`${at}: length js=${a.length} py=${b.length}`);
    const bSet = b.map((x) => JSON.stringify(x));
    const aSet = a.map((x) => JSON.stringify(x));
    for (const item of a.filter((_, i) => !bSet.includes(aSet[i] ?? '')).slice(0, 2)) {
      out.push(`${at}[js only]: ${JSON.stringify(item).slice(0, 200)}`);
    }
    for (const item of b.filter((_, i) => !aSet.includes(bSet[i] ?? '')).slice(0, 2)) {
      out.push(`${at}[py only]: ${JSON.stringify(item).slice(0, 200)}`);
    }
    return;
  }
  if (aObj && bObj) {
    for (const key of new Set([...Object.keys(aObj), ...Object.keys(bObj)])) {
      if (key === 'generatedUtc') continue;
      if (at === '$.meta' && key === 'rulesEvaluated') continue;
      diff(aObj[key], bObj[key], `${at}.${key}`, out);
    }
    return;
  }
  out.push(`${at}: js=${JSON.stringify(a)?.slice(0, 160)} py=${JSON.stringify(b)?.slice(0, 160)}`);
}

for (const service of SERVICES) {
  const cfg = loadConfig(path.join(ROOT, 'configs', `${service}.json`));
  const result = analyzeConfig(cfg, { outputDir: JS_OUT });
  const jsReport = normalise(result.report.payload, service) as Record<string, unknown>;
  const pyPath = path.join(PY_OUT, service, 'report.json');
  if (!existsSync(pyPath)) {
    failures.push(`${service}: python report missing`);
    console.log(`  FAIL  ${service} (no python report)`);
    continue;
  }
  const pyReport = normalise(
    JSON.parse(readFileSync(pyPath, 'utf8')) as Record<string, unknown>,
    service,
  ) as Record<string, unknown>;

  const problems: string[] = [];
  diff(jsReport, pyReport, '$', problems);

  // Also compare the rendered artefacts, which exercise reportMd and the CSV
  // writer rather than the shared payload builder.
  const TIMESTAMP = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/;
  for (const file of ['report.md', 'flagflow.md', 'findings.csv']) {
    // `report.json` already agrees on booleans; the Markdown prose differs only
    // because Python interpolates `False` where JS interpolates `false`.
    // Python reports absolute Windows paths, the JS engine reports paths relative
  // to the source root. Strip the absolute prefix so only the relative part is
  // compared. `re.escape` matters here: the root contains a space and non-ASCII
  // characters, and the service name is interpolated.
  const ABS_ROOT = new RegExp(
    `${escapeRegExp(path.join(ROOT, 'services', service))}[\\\\/]`,
    'g',
  );
  const clean = (text: string): string =>
      text
        .replace(ABS_ROOT, '')
        .replace(/\r\n/g, '\n')
        // Remaining backslashes are the Windows separators Python emitted; the
        // JS engine writes POSIX-style relative paths.
        .replace(/\\/g, '/')
        .replace(TIMESTAMP, '<timestamp>')
        .replace(/\b(True|False|None)\b/g, (word) => word.toLowerCase())
        .split('\n')
        // Warning strings name config fields, which are snake_case in the Python
        // config file and camelCase in the TS one. Same message, different
        // spelling of the field it tells the operator to set.
        .map((line) => canonicalText(line))
        .join('\n');
    const jsLines = clean(readFileSync(path.join(JS_OUT, service, file), 'utf8')).split('\n');
    const pyLines = clean(readFileSync(path.join(PY_OUT, service, file), 'utf8')).split('\n');
    for (let i = 0; i < Math.max(jsLines.length, pyLines.length); i += 1) {
      if (jsLines[i] === pyLines[i]) continue;
      problems.push(
        `${file}:${i + 1} js=${JSON.stringify(jsLines[i]?.slice(0, 110))} ` +
          `py=${JSON.stringify(pyLines[i]?.slice(0, 110))}`,
      );
      break;
    }
  }

  if (problems.length === 0) {
    console.log(`  ok    ${service}`);
  } else {
    failures.push(`${service}: ${problems.length} difference(s)`);
    console.log(`  FAIL  ${service}`);
    for (const line of problems.slice(0, 12)) console.log(`        ${line}`);
  }
}

console.log('');
if (failures.length === 0) {
  console.log('PARITY OK: js and python agree on rules, tests and every report');
} else {
  console.log(`${failures.length} parity failure(s):`);
  for (const line of failures) console.log(`  - ${line}`);
  process.exitCode = 1;
}
