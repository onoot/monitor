/** Findings list with severity, rule and free-text filters. */

import { useMemo, useState, type ReactNode } from 'react';
import type { Finding } from '../api';
import { Empty, SEVERITY_ORDER, Severity } from '../components';

function matches(finding: Finding, severity: string, rule: string, search: string): boolean {
  if (severity && finding.severity !== severity) return false;
  if (rule && finding.rule_id !== rule) return false;
  if (search) {
    const haystack =
      `${finding.title} ${finding.description} ${finding.exploit} ` +
      `${finding.evidence.file} ${finding.evidence.snippet}`.toLowerCase();
    if (!haystack.includes(search)) return false;
  }
  return true;
}

export function Findings({ findings }: { findings: readonly Finding[] }): ReactNode {
  const [severity, setSeverity] = useState('');
  const [rule, setRule] = useState('');
  const [search, setSearch] = useState('');

  const ruleIds = useMemo(
    () => [...new Set(findings.map((finding) => finding.rule_id))].sort(),
    [findings],
  );

  const filtered = useMemo(
    () => findings.filter((finding) => matches(finding, severity, rule, search.toLowerCase())),
    [findings, severity, rule, search],
  );

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
        <select value={rule} onChange={(e) => setRule(e.target.value)}>
          <option value="">All rules</option>
          {ruleIds.map((id) => (
            <option key={id} value={id}>
              {id}
            </option>
          ))}
        </select>
        <input
          value={search}
          placeholder="Search title, description, path, snippet…"
          onChange={(e) => setSearch(e.target.value)}
          style={{ flex: '1 1 260px' }}
        />
        <span className="muted" style={{ alignSelf: 'center' }}>
          {filtered.length} of {findings.length}
        </span>
      </div>

      {filtered.length === 0 ? (
        <Empty>
          {findings.length === 0
            ? 'No findings in this service.'
            : 'No finding matches these filters.'}
        </Empty>
      ) : (
        <div className="findings">
          {filtered.map((finding) => (
            <details className="finding" key={finding.evidence.fingerprint}>
              <summary>
                <Severity value={finding.severity} />
                <span className="finding-id">{finding.rule_id}</span>
                <span className="finding-title">{finding.title}</span>
                <span className="finding-loc">
                  {finding.evidence.file}:{finding.evidence.line}
                </span>
              </summary>
              <div className="finding-body">
                <dl>
                  <dt>Category</dt>
                  <dd>
                    <span className="pill">{finding.category}</span>
                    {finding.cwe.map((cwe) => (
                      <span className="pill" key={cwe}>
                        {cwe}
                      </span>
                    ))}
                  </dd>

                  <dt>Why it matters</dt>
                  <dd>{finding.description}</dd>

                  <dt>Exploit</dt>
                  <dd>{finding.exploit}</dd>

                  <dt>Effect on the checker</dt>
                  <dd>{finding.breaker}</dd>

                  <dt>Remediation</dt>
                  <dd>{finding.remediation}</dd>

                  <dt>
                    Code — {finding.evidence.file}:{finding.evidence.line}
                  </dt>
                  <dd>
                    <pre className="snippet">{finding.evidence.snippet}</pre>
                  </dd>

                  <dt>Fingerprint</dt>
                  <dd className="muted" style={{ fontSize: 12 }}>
                    {finding.evidence.fingerprint}
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
