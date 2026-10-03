/**
 * Poison preview.
 *
 * The server owns the decision; this only sends the inputs and renders what
 * came back. The checker and unknown paths are called out because a poisoned
 * value reaching the checker is the one outcome that ends the run.
 */

import { useState, type ReactNode } from 'react';
import { ApiError, api, type PoisonResult } from '../api';
import { Severity } from '../components';

const ACTORS = [
  { value: 'team', label: 'team — participant traffic' },
  { value: 'checker', label: 'checker — must never be poisoned' },
  { value: 'unknown', label: 'unknown — refuses to poison' },
];

export function Poison({ service }: { service: string }): ReactNode {
  const [actor, setActor] = useState('team');
  const [team, setTeam] = useState('t0');
  const [endpoint, setEndpoint] = useState('/');
  const [flag, setFlag] = useState('');
  const [result, setResult] = useState<PoisonResult | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(): Promise<void> {
    setBusy(true);
    setError('');
    setResult(null);
    try {
      setResult(await api.poison({ service, flag, actor, team, endpoint }));
    } catch (caught) {
      setError(
        caught instanceof ApiError
          ? caught.message
          : `request failed: ${String(caught)}`,
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <p className="muted" style={{ marginTop: 0 }}>
        Ask what the engine would do to one flag. Nothing is sent anywhere and no
        request is made to the service — this is the same pure decision the CLI
        and the checker use.
      </p>

      <div className="card">
        <div className="filters">
          <select value={actor} onChange={(e) => setActor(e.target.value)}>
            {ACTORS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
          <input
            value={team}
            placeholder="team key (t0)"
            onChange={(e) => setTeam(e.target.value)}
            style={{ width: 130 }}
          />
          <input
            value={endpoint}
            placeholder="/api/flag"
            onChange={(e) => setEndpoint(e.target.value)}
            style={{ width: 160 }}
          />
          <input
            value={flag}
            placeholder="alt{…}"
            onChange={(e) => setFlag(e.target.value)}
            style={{ flex: '1 1 260px' }}
          />
          <button
            className="primary"
            onClick={() => void submit()}
            disabled={busy || !flag}
          >
            {busy ? 'Asking…' : 'Preview'}
          </button>
        </div>
      </div>

      {error ? <div className="error-banner">{error}</div> : null}

      {result ? (
        <div className="card">
          <h3 style={{ marginTop: 0 }}>
            Decision:{' '}
            {result.action === 'poison' ? (
              <Severity value="critical" />
            ) : result.action === 'pass_through' ? (
              <Severity value="low" />
            ) : (
              <Severity value="info" />
            )}{' '}
            <span style={{ textTransform: 'none' }}>{result.action}</span>
          </h3>
          <table>
            <tbody>
              <tr>
                <th>Reason</th>
                <td>{result.reason}</td>
              </tr>
              <tr>
                <th>Actor</th>
                <td>
                  <span className="pill">{result.actor}</span>
                </td>
              </tr>
              <tr>
                <th>Team key</th>
                <td>{result.team_key}</td>
              </tr>
              <tr>
                <th>Flag in</th>
                <td className="snippet">{result.flag_in}</td>
              </tr>
              <tr>
                <th>Flag out</th>
                <td className="snippet">
                  {result.flag_out ?? 'unchanged — the checker must receive the exact flag'}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      ) : null}
    </>
  );
}
