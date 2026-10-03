/** Runtime actor attribution: who did what, and where the flag moved. */

import type { ReactNode } from 'react';
import type { ReportPayload } from '../api';
import { Empty, Warnings } from '../components';

interface ActorStats {
  actor?: string;
  requests?: number;
  flag_reads?: number;
  flag_writes?: number;
  credential_pairs?: string[];
  ips?: string[];
  routes?: Record<string, number>;
}

interface RouteMatrixRow {
  route: string;
  actors: Record<string, { count: number; flag_reads: number; flag_writes: number; ips: string[] }>;
}

export function Runtime({ report }: { report: ReportPayload }): ReactNode {
  const runtime = report.runtime;
  const actors = Object.entries(runtime.actors ?? {}) as [string, ActorStats][];
  const matrix = (runtime.route_matrix ?? []) as RouteMatrixRow[];

  return (
    <>
      <h3>Actor profiles</h3>
      {actors.length === 0 ? (
        <Empty>
          No runtime records were loaded. Add <code>request_logs</code> to the service
          config to populate this tab.
        </Empty>
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Actor</th>
                <th>Requests</th>
                <th>Flag reads</th>
                <th>Flag writes</th>
                <th>Credential pairs</th>
              </tr>
            </thead>
            <tbody>
              {actors.map(([name, stats]) => (
                <tr key={name}>
                  <td>
                    <span className="pill">{name}</span>
                  </td>
                  <td style={{ fontVariantNumeric: 'tabular-nums' }}>{stats.requests ?? 0}</td>
                  <td style={{ fontVariantNumeric: 'tabular-nums', color: stats.flag_reads ? 'var(--high)' : undefined }}>
                    {stats.flag_reads ?? 0}
                  </td>
                  <td style={{ fontVariantNumeric: 'tabular-nums', color: stats.flag_writes ? 'var(--critical)' : undefined }}>
                    {stats.flag_writes ?? 0}
                  </td>
                  <td>{(stats.credential_pairs ?? []).join(', ') || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h3>Route matrix</h3>
      {matrix.length === 0 ? (
        <Empty>No observed route traffic.</Empty>
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Route</th>
                <th>Actor</th>
                <th>Count</th>
                <th>Flag reads</th>
                <th>Flag writes</th>
              </tr>
            </thead>
            <tbody>
              {matrix.flatMap((row) =>
                Object.entries(row.actors).map(([actor, stats]) => (
                  <tr key={`${row.route}|${actor}`}>
                    <td style={{ fontFamily: 'ui-monospace, monospace' }}>{row.route}</td>
                    <td>
                      <span className="pill">{actor}</span>
                    </td>
                    <td style={{ fontVariantNumeric: 'tabular-nums' }}>{stats.count}</td>
                    <td style={{ fontVariantNumeric: 'tabular-nums' }}>{stats.flag_reads}</td>
                    <td style={{ fontVariantNumeric: 'tabular-nums' }}>{stats.flag_writes}</td>
                  </tr>
                )),
              )}
            </tbody>
          </table>
        </div>
      )}

      {runtime.cross_actor_observations.length > 0 ? (
        <>
          <h3>Cross-actor observations</h3>
          <Warnings items={runtime.cross_actor_observations} tone="danger" />
        </>
      ) : null}

      {runtime.parser_notes.length > 0 ? (
        <>
          <h3>Parser notes</h3>
          <Warnings items={runtime.parser_notes} />
        </>
      ) : null}
    </>
  );
}
