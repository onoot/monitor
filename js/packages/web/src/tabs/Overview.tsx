/** Overview: counts, severity breakdown and the misconfigurations to read first. */

import type { ReactNode } from 'react';
import type { ReportPayload } from '../api';
import { Empty, SEVERITY_ORDER, Severity, Stat, Warnings } from '../components';

export function Overview({ report }: { report: ReportPayload }): ReactNode {
  const counts = report.finding_counts ?? {};
  const total = report.findings.length;
  const categories = Object.entries(report.category_counts ?? {}).sort(
    (a, b) => b[1] - a[1],
  );
  const poisoning = report.poisoning ?? {};
  const enabled = poisoning.enabled === true;

  return (
    <>
      <div className="stats">
        <Stat label="Findings" value={total} />
        <Stat label="Source files" value={report.meta.files_scanned} />
        <Stat label="Files skipped" value={report.meta.files_skipped} />
        <Stat label="Runtime records" value={report.meta.request_records} />
        <Stat
          label="Unguarded ID routes"
          value={report.unguarded_id_routes.length}
          tone={report.unguarded_id_routes.length > 0 ? 'critical' : 'low'}
        />
        <Stat
          label="Poisoning"
          value={enabled ? 'armed' : 'off'}
          tone={enabled ? 'medium' : 'info'}
        />
      </div>

      {report.meta.notes ? (
        <div className="card">
          <h3>Operator note</h3>
          <div>{report.meta.notes}</div>
        </div>
      ) : null}

      <h3>Read this first</h3>
      <Warnings
        items={report.warnings ?? []}
        tone={total > 0 ? 'danger' : 'ok'}
      />

      <h3>Findings by severity</h3>
      <div className="stats">
        {SEVERITY_ORDER.map((level) => (
          <Stat
            key={level}
            label={level}
            value={counts[level] ?? 0}
            tone={counts[level] ? level : undefined}
          />
        ))}
      </div>

      <h3>Findings by category</h3>
      {categories.length === 0 ? (
        <Empty>No findings in this service.</Empty>
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Category</th>
                <th>Count</th>
              </tr>
            </thead>
            <tbody>
              {categories.map(([category, count]) => (
                <tr key={category}>
                  <td>{category}</td>
                  <td style={{ fontVariantNumeric: 'tabular-nums' }}>{count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h3>Flag flow</h3>
      <div className="card">
        <table>
          <tbody>
            <tr>
              <th>Pattern source</th>
              <td>
                <span className="pill">{report.flag_flow.pattern_source}</span>
                {report.flag_flow.pattern_known ? null : (
                  <span className="muted">
                    {' '}
                    unconfirmed — put/get cannot be verified and poisoning stays off
                  </span>
                )}
              </td>
            </tr>
            <tr>
              <th>Put candidates</th>
              <td>{report.flag_flow.put_points.length}</td>
            </tr>
            <tr>
              <th>Get candidates</th>
              <td>{report.flag_flow.get_points.length}</td>
            </tr>
            <tr>
              <th>Storage hints</th>
              <td>{report.flag_flow.storage_hints.length}</td>
            </tr>
            <tr>
              <th>Exposure hints</th>
              <td>{report.flag_flow.exposure_hints.length}</td>
            </tr>
            <tr>
              <th>Checker flag reads observed</th>
              <td>
                {report.flag_flow.observed_checker_flag_reads.length === 0
                  ? '—'
                  : report.flag_flow.observed_checker_flag_reads.join(', ')}
              </td>
            </tr>
            <tr>
              <th>Team flag reads observed</th>
              <td>
                {report.flag_flow.observed_team_flag_reads.length === 0
                  ? '—'
                  : report.flag_flow.observed_team_flag_reads.join(', ')}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <h3>Poisoning policy</h3>
      <div className="card">
        <table>
          <tbody>
            {(
              [
                ['Enabled', String(poisoning.enabled)],
                ['Checker', String(poisoning.checker_policy)],
                ['Unknown', String(poisoning.unknown_policy)],
                ['Team', String(poisoning.team_policy)],
                ['Secret source', String(poisoning.secret_source)],
              ] as const
            ).map(([key, value]) => (
              <tr key={key}>
                <th>{key}</th>
                <td>{value}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {typeof poisoning.error === 'string' ? (
          <div className="warn danger" style={{ marginTop: 12 }}>
            {poisoning.error}
          </div>
        ) : null}
      </div>

      <h3>Source roots</h3>
      <div className="card">
        {report.meta.source_roots.map((root) => (
          <div key={root} className="snippet">
            {root}
          </div>
        ))}
        <div className="muted" style={{ marginTop: 8, fontSize: 12 }}>
          Reports are written to <code>reports/&lt;service&gt;/</code> by the CLI. This
          dashboard analyses in memory and never overwrites them.
        </div>
      </div>
    </>
  );
}

export { Severity };
