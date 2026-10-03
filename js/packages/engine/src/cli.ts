/**
 * Command line interface.
 *
 *   ad scan  --config <service>.json
 *   ad init   <service-name>            # scaffold a config
 *   ad poison --config <service>.json --actor team --team t7 \
 *             --endpoint /api/flag --flag 'alctf{...}'
 *   ad rules                            # list the rule pack
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { ConfigError, loadConfig, type Config } from './config.js';
import { Poisoner, PoisonerMisconfigured } from './poison.js';
import { RULES } from './rules.js';
import { analyzeConfig, discoverConfigs } from './pipeline.js';
import { VERSION } from './version.js';

export const CONFIG_TEMPLATE: Record<string, unknown> = {
  service_name: 'CHANGE_ME',
  source_roots: ['.'],
  output_dir: '../../reports',
  notes: '',
  flag_format: {
    pattern: '',
    prefix: '',
    body_alphabet: '',
    min_length: 0,
  },
  known_flags: [],
  team_networks: [],
  checker_networks: [],
  checker_ip_pattern: '',
  request_logs: [],
  _instructions: {
    'flag_format.pattern':
      "xeger syntax exactly as the checker generates it, e.g. 'alctf{[a-z0-9_]{16}}'. Leave empty rather than guessing.",
    known_flags:
      'literal flags for this service, if the operator can share them. Used for exact detection.',
    team_networks:
      "list of {'label','cidr'} for the participant instances. Explicit entries always win over inference.",
    checker_networks: "list of {'label','cidr'} for the checker's source addresses.",
    checker_ip_pattern:
      "IP_PATTERN from the checker config, e.g. '10.10.{team_number}.2'. Used to infer per-team instances.",
    request_logs:
      'JSONL/JSON captures or combined access logs. Expected fields: ts, client_ip, method, path, status, body, response.',
  },
};

const USAGE = `usage: ad <command> [options]

commands:
  init <path> [--name <service>]       scaffold a service config
  scan --config <path> [--out <dir>] [--classify-ips]
  all  --config <dir> [--out <dir>]     scan every config in a directory
  poison --config <path> --flag <flag> [--actor team] [--team t0] [--endpoint /]
  rules [--json]                       list the detection rule pack
  version                              print the version

options:
  --help, -h       show this message
  --version, -v    print the version`;

export interface ParsedArgs {
  command: string;
  positionals: string[];
  options: Record<string, string | boolean>;
}

/**
 * Minimal flag parser.
 *
 * The CLI accepts a fixed option set, so a dependency would cost more than it
 * saves. Long and short single-dash forms both work (`--config`, `-config`).
 */
export function parseArgs(argv: readonly string[]): ParsedArgs {
  const options: Record<string, string | boolean> = {};
  const positionals: string[] = [];
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index] ?? '';
    if (!arg.startsWith('-')) {
      positionals.push(arg);
      continue;
    }
    const name = arg.replace(/^--?/, '');
    const next = argv[index + 1];
    if (next !== undefined && !next.startsWith('-')) {
      options[name] = next;
      index += 1;
    } else {
      options[name] = true;
    }
  }
  return { command: positionals[0] ?? '', positionals: positionals.slice(1), options };
}

export function requireOption(options: Record<string, string | boolean>, name: string): string {
  const value = options[name];
  if (typeof value !== 'string' || value.length === 0) {
    throw new ConfigError(`--${name} is required`);
  }
  return value;
}

export function cmdInit(positionals: readonly string[], options: Record<string, string | boolean>): string[] {
  const raw = positionals[0];
  if (!raw) throw new ConfigError('init needs a target path');
  const target = path.resolve(raw);
  mkdirSync(path.dirname(target), { recursive: true });
  const payload = {
    ...CONFIG_TEMPLATE,
    service_name:
      typeof options.name === 'string' ? options.name : path.basename(target, '.json'),
  };
  writeFileSync(target, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
  return [
    `wrote ${target}`,
    'Fill in flag_format.pattern, team_networks and request_logs before trusting the report.',
  ];
}

function summarize(serviceName: string, files: number, findings: number, requests: number, out: string): string {
  return `${serviceName}: ${files} files, ${findings} findings, ${requests} requests -> ${out}`;
}

export function cmdScan(options: Record<string, string | boolean>): string[] {
  const classifyIps = options['classify-ips'] === true || options['classify-ips'] === 'true';
  const out = typeof options.out === 'string' ? options.out : undefined;
  const result = analyzeConfig(loadConfig(requireOption(options, 'config')), {
    classifyIps,
    ...(out ? { outputDir: out } : {}),
  });
  return [
    // The mapping comes from the run: classifyUnknown is idempotent, so asking
    // again would print nothing.
    ...Object.entries(result.classified)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([ip, actor]) => `ip ${ip} -> ${actor}`),
    summarize(
      result.cfg.serviceName,
      result.scan.filesScanned,
      result.scan.findings.length,
      result.runtime.requests.length,
      result.report.outDir,
    ),
  ];
}

export function cmdAll(options: Record<string, string | boolean>): string[] {
  const dir = typeof options.config === 'string' ? options.config : 'configs';
  const out = typeof options.out === 'string' ? options.out : undefined;
  const configs = discoverConfigs(dir);
  if (configs.length === 0) throw new ConfigError(`no configs in ${dir}`);
  return configs.map((configPath) => {
    const result = analyzeConfig(loadConfig(configPath), out ? { outputDir: out } : {});
    return summarize(
      result.cfg.serviceName,
      result.scan.filesScanned,
      result.scan.findings.length,
      result.runtime.requests.length,
      result.report.outDir,
    );
  });
}

export interface PoisonCliResult {
  lines: string[];
  code: number;
}

export function cmdPoison(options: Record<string, string | boolean>): PoisonCliResult {
  const cfg: Config = loadConfig(requireOption(options, 'config'));
  const actor = typeof options.actor === 'string' ? options.actor : 'team';
  const team = typeof options.team === 'string' ? options.team : 't0';
  const endpoint = typeof options.endpoint === 'string' ? options.endpoint : '/';
  const flag = requireOption(options, 'flag');

  let poisoner: Poisoner;
  try {
    poisoner = new Poisoner(cfg);
  } catch (error) {
    if (error instanceof PoisonerMisconfigured) {
      return {
        lines: [JSON.stringify({ action: 'disabled', reason: error.message }, null, 2)],
        code: 2,
      };
    }
    throw error;
  }

  const decision = poisoner.decide(actor, team, endpoint, flag);
  return {
    lines: [
      JSON.stringify(
        {
          action: decision.action,
          reason: decision.reason,
          actor: decision.actor,
          team_key: decision.teamKey,
          flag_in: flag,
          flag_out: decision.value,
        },
        null,
        2,
      ),
    ],
    code: 0,
  };
}

export function cmdRules(options: Record<string, string | boolean>): string[] {
  if (options.json === true) {
    return [
      JSON.stringify(
        RULES.map((rule) => ({
          id: rule.id,
          category: rule.category,
          title: rule.title,
          severity: rule.severity,
          cwe: [...rule.cwe],
          sources: [...rule.sources],
          exploit: rule.exploit,
          breaker: rule.breaker,
        })),
        null,
        2,
      ),
    ];
  }
  return [
    `${'ID'.padEnd(14)} ${'SEVERITY'.padEnd(9)} ${'CATEGORY'.padEnd(24)} TITLE`,
    ...RULES.map(
      (rule) =>
        `${rule.id.padEnd(14)} ${rule.severity.padEnd(9)} ${rule.category.padEnd(24)} ${rule.title}`,
    ),
    '',
    `${RULES.length} rules`,
  ];
}

/** Run one invocation and return the exit code plus the lines to print. */
export function run(argv: readonly string[]): { code: number; out: string[]; err: string[] } {
  const { command, positionals, options } = parseArgs(argv);
  const wantsHelp = options.help === true || options.h === true || command === 'help';
  if (wantsHelp || command === '') {
    return { code: command === '' ? 2 : 0, out: [USAGE], err: [] };
  }
  if (options.version === true || options.v === true || command === 'version') {
    return { code: 0, out: [VERSION], err: [] };
  }

  try {
    switch (command) {
      case 'init':
        return { code: 0, out: cmdInit(positionals, options), err: [] };
      case 'scan':
        return { code: 0, out: cmdScan(options), err: [] };
      case 'all':
        return { code: 0, out: cmdAll(options), err: [] };
      case 'poison': {
        const result = cmdPoison(options);
        return { code: result.code, out: result.lines, err: [] };
      }
      case 'rules':
        return { code: 0, out: cmdRules(options), err: [] };
      default:
        return { code: 2, out: [], err: [`unknown command: ${command}\n\n${USAGE}`] };
    }
  } catch (error) {
    if (error instanceof ConfigError) {
      return { code: 2, out: [], err: [`config error: ${error.message}`] };
    }
    return { code: 1, out: [], err: [(error as Error).stack ?? String(error)] };
  }
}
