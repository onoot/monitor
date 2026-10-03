/** Small presentational pieces shared by the tabs. */

import type { ReactNode } from 'react';

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export function Severity({ value }: { value: string }): ReactNode {
  const cls = SEVERITY_ORDER.includes(value) ? value : 'info';
  return <span className={`sev sev-${cls}`}>{value}</span>;
}

export function Stat({
  label,
  value,
  tone,
}: {
  label: string;
  value: ReactNode;
  tone?: string;
}): ReactNode {
  return (
    <div className="stat">
      <div className="stat-value" style={tone ? { color: `var(--${tone})` } : undefined}>
        {value}
      </div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }): ReactNode {
  return <div className="empty">{children}</div>;
}

export function Loading({ what }: { what: string }): ReactNode {
  return <div className="loading">Loading {what}…</div>;
}

export function ErrorBanner({ error }: { error: string }): ReactNode {
  return <div className="error-banner">{error}</div>;
}

export function Warnings({
  items,
  tone,
}: {
  items: readonly string[];
  tone?: 'danger' | 'ok';
}): ReactNode {
  if (items.length === 0) return null;
  return (
    <div>
      {items.map((item) => (
        <div key={item} className={`warn ${tone ?? ''}`}>
          {item}
        </div>
      ))}
    </div>
  );
}
