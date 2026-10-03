/** The generated Markdown report, for reading and copying. */

import { useEffect, useState, type ReactNode } from 'react';
import { ApiError, api } from '../api';
import { Empty, ErrorBanner, Loading } from '../components';

export function ReportView({ service }: { service: string }): ReactNode {
  const [text, setText] = useState<string | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let live = true;
    setText(null);
    setError('');
    api
      .reportMarkdown(service)
      .then((value) => {
        if (live) setText(value);
      })
      .catch((caught: unknown) => {
        if (live) setError(caught instanceof ApiError ? caught.message : String(caught));
      });
    return () => {
      live = false;
    };
  }, [service]);

  if (error) return <ErrorBanner error={error} />;
  if (text === null) return <Loading what="the report" />;
  if (text.trim() === '') return <Empty>That report is empty.</Empty>;

  return (
    <>
      <p className="muted" style={{ marginTop: 0 }}>
        This is the file the engine wrote to the service report directory, exactly
        as <code>ad scan</code> produces it.
      </p>
      <div className="md">{text}</div>
    </>
  );
}
