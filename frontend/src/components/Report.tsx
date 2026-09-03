import { useEffect, useRef } from 'react';

import type { ScanReport } from '../types';
import { CheckCard } from './CheckCard';
import { GradeSummary } from './GradeSummary';
import { RawHeaders } from './RawHeaders';

export interface ReportViewProps {
  report: ScanReport;
  onRescan: () => void;
  cachedAt: number;
}

export function ReportView({ report, onRescan, cachedAt }: ReportViewProps): React.JSX.Element {
  const heading = useRef<HTMLHeadingElement>(null);

  // Move focus to the report when a new one arrives: without this, a keyboard
  // or screen reader user is left at the submit button with no idea that the
  // page below them changed.
  useEffect(() => {
    heading.current?.focus();
  }, [report.target.final, cachedAt]);

  return (
    <section aria-labelledby="report-heading">
      <h2 id="report-heading" tabIndex={-1} ref={heading} className="visually-hidden">
        Relatório de {report.target.final}: nota {report.grade}, {report.score} de 100
      </h2>

      <GradeSummary report={report} onRescan={onRescan} cachedAt={cachedAt} />

      <h3 className="visually-hidden">Headers analisados</h3>
      <ul className="checks">
        {report.checks.map((check) => (
          <CheckCard key={check.id} check={check} />
        ))}
      </ul>

      <RawHeaders headers={report.headers} />
    </section>
  );
}
