/** The detection rule pack, as served by the engine. */

import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { ApiError, api, type RuleEntry } from '../api';
import { Empty, ErrorBanner, Loading, SEVERITY_ORDER, Severity } from '../components';

export function Rules(): ReactNode {
  const [rules, setRules] = useState<RuleEntry[] | null>(null);
  const [error, setError] = useState('');
  const [severity, setSeverity] = useState('');
  const [category, setCategory] = useState('');
  const [search, setSearch] = useState('');

  useEffect(() => {
    let live = true;
    api
      .rules()
      .then((data) => {
        if (live) setRules(data.rules);
      })
      .catch((caught: unknown) => {
        if (live) setError(caught instanceof ApiError ? caught.message : String(caught));
      });
    return () => {
      live = false;
    };
  }, []);

  const categories = useMemo(
    () => [...new Set((rules ?? []).map((rule) => rule.category))].sort(),
    [rules],
  );

  if (error) return <ErrorBanner error={error} />;
  if (!rules) return <Loading what="the rule pack" />;

  const needle = search.toLowerCase();
  const filtered = rules.filter((rule) => {
    if (severity && rule.severity !== severity) return false;
    if (category && rule.category !== category) return false;
    if (needle && !`${rule.id} ${rule.title} ${rule.description}`.toLowerCase().includes(needle)) {
      return false;
    }
    return true;
  });

  return (
    <>
      <div className="filters">
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          {SEVERITY_ORDER.map((level) => (
            <option key={level} value={level}>
              {level}
            </option>
          ))}
        </select>
        <select value={category} onChange={(e) => setCategory(e.target.value)}>
          <option value="">All categories</option>
          {categories.map((name) => (
            <option key={name} value={name}>
              {name}
            </option>
          ))}
        </select>
        <input
          value={search}
          placeholder="Search rules…"
          onChange={(e) => setSearch(e.target.value)}
          style={{ flex: '1 1 240px' }}
        />
        <span className="muted" style={{ alignSelf: 'center' }}>
          {filtered.length} of {rules.length}
        </span>
      </div>

      {filtered.length === 0 ? (
        <Empty>No rule matches these filters.</Empty>
      ) : (
        <div className="findings">
          {filtered.map((rule) => (
            <details className="finding" key={rule.id}>
              <summary>
                <Severity value={rule.severity} />
                <span className="finding-id">{rule.id}</span>
                <span className="finding-title">{rule.title}</span>
                <span className="finding-loc">{rule.category}</span>
              </summary>
              <div className="finding-body">
                <dl>
                  <dt>Why it matters</dt>
                  <dd>{rule.description}</dd>
                  <dt>Exploit</dt>
                  <dd>{rule.exploit}</dd>
                  <dt>Effect on the checker</dt>
                  <dd>{rule.breaker}</dd>
                  <dt>Remediation</dt>
                  <dd>{rule.remediation}</dd>
                  <dt>CWE</dt>
                  <dd>
                    {rule.cwe.map((cwe) => (
                      <span className="pill" key={cwe}>
                        {cwe}
                      </span>
                    ))}
                  </dd>
                  <dt>Derived from</dt>
                  <dd className="muted" style={{ fontSize: 12 }}>
                    {rule.sources.join(', ')}
                  </dd>
                </dl>
              </div>
            </details>
          ))}
        </div>
      )}
    </>
  );
}
