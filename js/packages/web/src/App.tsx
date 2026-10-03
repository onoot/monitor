import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { ApiError, api, type ReportPayload, type ServiceSummary } from './api';
import { Empty, ErrorBanner, Loading } from './components';
import { Findings } from './tabs/Findings';
import { Overview } from './tabs/Overview';
import { Poison } from './tabs/Poison';
import { ReportView } from './tabs/ReportView';
import { Routes } from './tabs/Routes';
import { Rules } from './tabs/Rules';
import { Runtime } from './tabs/Runtime';

const TABS = [
  { id: 'overview', label: 'Overview', needsService: true },
  { id: 'findings', label: 'Findings', needsService: true },
  { id: 'routes', label: 'Routes', needsService: true },
  { id: 'runtime', label: 'Runtime', needsService: true },
  { id: 'poison', label: 'Poison', needsService: true },
  { id: 'report', label: 'Report', needsService: true },
  { id: 'rules', label: 'Rule pack', needsService: false },
] as const;

type TabId = (typeof TABS)[number]['id'];

export function App(): ReactNode {
  const [services, setServices] = useState<ServiceSummary[] | null>(null);
  const [listError, setListError] = useState('');
  const [selected, setSelected] = useState('');
  const [tab, setTab] = useState<TabId>('overview');
  const [report, setReport] = useState<ReportPayload | null>(null);
  const [reportError, setReportError] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let live = true;
    api
      .services()
      .then((data) => {
        if (!live) return;
        setServices(data.services);
        // Preselect the first service that analysed cleanly.
        const first = data.services.find((service) => !service.error);
        if (first) setSelected(first.name);
      })
      .catch((caught: unknown) => {
        if (live) {
          setListError(caught instanceof ApiError ? caught.message : String(caught));
        }
      });
    return () => {
      live = false;
    };
  }, []);

  const loadReport = useCallback(
    (name: string, refresh: boolean) => {
      if (!name) return;
      setLoading(true);
      setReportError('');
      api
        .report(name, refresh)
        .then((payload) => {
          setReport(payload);
          setLoading(false);
        })
        .catch((caught: unknown) => {
          setReportError(caught instanceof ApiError ? caught.message : String(caught));
          setReport(null);
          setLoading(false);
        });
    },
    [],
  );

  useEffect(() => {
    if (selected) loadReport(selected, false);
  }, [selected, loadReport]);

  const current = services?.find((service) => service.name === selected);

  if (listError) {
    return (
      <div className="main">
        <ErrorBanner error={`Could not reach the analysis API: ${listError}`} />
      </div>
    );
  }

  return (
    <div className="app">
      <aside className="side">
        <div className="brand">
          A/D <span>service analysis</span>
        </div>
        <div className="muted" style={{ fontSize: 12 }}>
          {services === null
            ? 'Loading…'
            : `${services.length} service${services.length === 1 ? '' : 's'}`}
        </div>

        <h2>Services</h2>
        {services?.length === 0 ? (
          <Empty>No configs found.</Empty>
        ) : (
          services?.map((service) => (
            <button
              key={service.name}
              className="svc"
              aria-current={service.name === selected}
              onClick={() => setSelected(service.name)}
              disabled={Boolean(service.error)}
            >
              <span className="svc-name">
                <strong>{service.name}</strong>
                <span className={service.error ? 'svc-error' : 'muted'}>
                  {service.error ? 'error' : service.findings}
                </span>
              </span>
              <span className="svc-sub">
                {service.error
                  ? service.error
                  : `${service.filesScanned} files · ${service.requests} requests`}
              </span>
            </button>
          ))
        )}
      </aside>

      <main className="main">
        {!current ? (
          <Empty>{loading ? 'Analysing…' : 'Select a service.'}</Empty>
        ) : (
          <>
            <h1>{current.name}</h1>
            <p className="subtitle">
              {current.filesScanned} files scanned · {current.filesSkipped} skipped ·{' '}
              {current.findings} findings · analysed {current.generatedUtc}
            </p>

            <div className="tabs">
              {TABS.map((item) => (
                <button
                  key={item.id}
                  className="tab"
                  role="tab"
                  aria-selected={tab === item.id}
                  onClick={() => setTab(item.id)}
                >
                  {item.label}
                </button>
              ))}
              <button
                className="tab"
                style={{ marginLeft: 'auto' }}
                onClick={() => {
                  loadReport(selected, true);
                  void api
                    .services()
                    .then((data) => setServices(data.services))
                    .catch(() => undefined);
                }}
                disabled={loading}
              >
                {loading ? 'Analysing…' : 'Re-analyse'}
              </button>
            </div>

            {reportError ? <ErrorBanner error={reportError} /> : null}

            {tab === 'rules' ? (
              <Rules />
            ) : !report ? (
              loading ? <Loading what="the service" /> : <Empty>No report loaded.</Empty>
            ) : tab === 'overview' ? (
              <Overview report={report} />
            ) : tab === 'findings' ? (
              <Findings findings={report.findings} />
            ) : tab === 'routes' ? (
              <Routes routes={report.routes} unguarded={report.unguarded_id_routes} />
            ) : tab === 'runtime' ? (
              <Runtime report={report} />
            ) : tab === 'poison' ? (
              <Poison service={current.name} />
            ) : (
              <ReportView service={current.name} />
            )}
          </>
        )}
      </main>
    </div>
  );
}
