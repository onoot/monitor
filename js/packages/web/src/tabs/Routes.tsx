/** Route table, with the unguarded-ID routes called out first. */

import { useState, type ReactNode } from 'react';
import type { RouteEntry } from '../api';
import { Empty } from '../components';

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'ANY'];

export function Routes({
  routes,
  unguarded,
}: {
  routes: readonly RouteEntry[];
  unguarded: readonly RouteEntry[];
}): ReactNode {
  const [search, setSearch] = useState('');
  const [unguardedOnly, setUnguardedOnly] = useState(false);

  const needle = search.toLowerCase();
  const filtered = routes.filter((route) => {
    if (unguardedOnly && !(route.id_param && !route.guarded)) return false;
    if (!needle) return true;
    return `${route.method} ${route.path} ${route.file}`.toLowerCase().includes(needle);
  });

  return (
    <>
      <div className="filters">
        <input
          value={search}
          placeholder="Search method, path or file…"
          onChange={(e) => setSearch(e.target.value)}
          style={{ flex: '1 1 260px' }}
        />
        <label style={{ alignSelf: 'center', display: 'flex', gap: 6 }}>
          <input
            type="checkbox"
            checked={unguardedOnly}
            onChange={(e) => setUnguardedOnly(e.target.checked)}
          />
          Unguarded ID routes only ({unguarded.length})
        </label>
        <span className="muted" style={{ alignSelf: 'center' }}>
          {filtered.length} of {routes.length}
        </span>
      </div>

      {routes.length === 0 ? (
        <Empty>No routes were recognised in this service.</Empty>
      ) : filtered.length === 0 ? (
        <Empty>No route matches these filters.</Empty>
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Method</th>
                <th>Path</th>
                <th>Guard</th>
                <th>Location</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((route) => {
                const risky = route.id_param && !route.guarded;
                return (
                  <tr key={`${route.method} ${route.path} ${route.file}:${route.line}`} className={risky ? 'bad' : ''}>
                    <td>
                      <span className="pill">{route.method}</span>
                    </td>
                    <td style={{ fontFamily: 'ui-monospace, monospace' }}>
                      {route.path}
                      {route.id_param ? (
                        <span className="pill" style={{ marginLeft: 6 }}>
                          id param
                        </span>
                      ) : null}
                    </td>
                    <td>
                      {route.guarded ? (
                        <span style={{ color: 'var(--low)' }}>guarded</span>
                      ) : (
                        <span style={{ color: 'var(--medium)' }}>none</span>
                      )}
                    </td>
                    <td className="muted" style={{ fontFamily: 'ui-monospace, monospace', fontSize: 12 }}>
                      {route.file}:{route.line}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {unguarded.length > 0 ? (
        <>
          <h3>Unguarded ID routes</h3>
          <p className="muted" style={{ marginTop: -4 }}>
            These take a resource identifier in the path with no authentication
            check in the same handler, so any caller who guesses the identifier
            gets the object.
          </p>
          <div className="card">
            <table>
              <thead>
                <tr>
                  <th>Route</th>
                  <th>Location</th>
                </tr>
              </thead>
              <tbody>
                {unguarded.map((route) => (
                  <tr key={`${route.method} ${route.path} ${route.file}:${route.line}`} className="bad">
                    <td style={{ fontFamily: 'ui-monospace, monospace' }}>
                      {route.method} {route.path}
                    </td>
                    <td className="muted" style={{ fontFamily: 'ui-monospace, monospace', fontSize: 12 }}>
                      {route.file}:{route.line}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      ) : null}

      <h3>Methods seen</h3>
      <div className="card">
        {METHODS.filter((method) => routes.some((route) => route.method === method)).map(
          (method) => (
            <span className="pill" key={method}>
              {method} {routes.filter((route) => route.method === method).length}
            </span>
          ),
        )}
      </div>
    </>
  );
}
