/**
 * Typed access to the analysis API.
 *
 * Field names are snake_case because the server forwards the `report.json`
 * contract verbatim; renaming here would hide a real drift from that schema.
 */

export interface Evidence {
  file: string;
  line: number;
  snippet: string;
  fingerprint: string;
}

export interface Finding {
  rule_id: string;
  category: string;
  title: string;
  severity: string;
  confidence: string;
  description: string;
  exploit: string;
  breaker: string;
  remediation: string;
  cwe: string[];
  rule_sources: string[];
  evidence: Evidence;
}

export interface RouteEntry {
  path: string;
  method: string;
  file: string;
  line: number;
  guarded: boolean;
  id_param: boolean;
}

export interface ServiceSummary {
  name: string;
  filesScanned: number;
  filesSkipped: number;
  findings: number;
  requests: number;
  severities: Record<string, number>;
  warnings: string[];
  generatedUtc: string;
  error?: string;
}

export interface ReportPayload {
  meta: {
    schema_version: string;
    service: string;
    generated_utc: string;
    source_roots: string[];
    files_scanned: number;
    files_skipped: number;
    request_records: number;
    notes: string;
  };
  findings: Finding[];
  finding_counts: Record<string, number>;
  category_counts: Record<string, number>;
  routes: RouteEntry[];
  unguarded_id_routes: RouteEntry[];
  runtime: {
    actors: Record<string, unknown>;
    route_matrix: unknown[];
    cross_actor_observations: string[];
    parser_notes: string[];
  };
  flag_flow: {
    pattern_known: boolean;
    pattern_source: string;
    mask: string | null;
    prefix: string;
    put_points: unknown[];
    get_points: unknown[];
    storage_hints: unknown[];
    exposure_hints: unknown[];
    observed_checker_flag_reads: string[];
    observed_team_flag_reads: string[];
    warnings: string[];
  };
  poisoning: Record<string, unknown>;
  topology: Record<string, unknown>;
  warnings: string[];
}

export interface RuleEntry {
  id: string;
  category: string;
  title: string;
  severity: string;
  description: string;
  exploit: string;
  breaker: string;
  remediation: string;
  cwe: string[];
  sources: string[];
}

export interface PoisonResult {
  action: string;
  reason: string;
  actor: string;
  team_key: string;
  flag_in: string;
  flag_out: string | null;
}

export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

async function get<T>(path: string): Promise<T> {
  const response = await fetch(path, { headers: { accept: 'application/json' } });
  if (!response.ok) throw new ApiError(response.status, await describe(response));
  return (await response.json()) as T;
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new ApiError(response.status, await describe(response));
  return (await response.json()) as T;
}

async function describe(response: Response): Promise<string> {
  try {
    const payload = (await response.json()) as { error?: string; reason?: string };
    return payload.error ?? payload.reason ?? `request failed (${response.status})`;
  } catch {
    return `request failed (${response.status})`;
  }
}

export const api = {
  services: (): Promise<{ services: ServiceSummary[] }> => get('/api/services'),
  report: (service: string, refresh = false): Promise<ReportPayload> =>
    get(`/api/services/${encodeURIComponent(service)}${refresh ? '?refresh=1' : ''}`),
  rules: (): Promise<{ total: number; rules: RuleEntry[] }> => get('/api/rules'),
  poison: (body: {
    service: string;
    flag: string;
    actor: string;
    team: string;
    endpoint: string;
  }): Promise<PoisonResult> => post('/api/poison', body),
  reportMarkdown: async (service: string): Promise<string> => {
    const response = await fetch(`/api/services/${encodeURIComponent(service)}/report.md`);
    if (!response.ok) throw new ApiError(response.status, await describe(response));
    return response.text();
  },
};
