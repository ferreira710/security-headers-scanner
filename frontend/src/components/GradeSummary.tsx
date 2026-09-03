import { useMemo } from 'react';

import { toLlmBriefing } from '../analysis/briefing';
import type { Grade, ScanReport } from '../types';
import { CopyButton } from './CopyButton';
import { StatusPill } from './StatusPill';

/** Arc length of the score ring, as a conic-gradient angle. */
function arc(score: number): string {
  return `${(score / 100) * 360}deg`;
}

const GRADE_COLOR: Record<Grade, string> = {
  A: 'var(--pass)',
  B: 'var(--pass)',
  C: 'var(--warn)',
  D: 'var(--warn)',
  E: 'var(--fail)',
  F: 'var(--fail)',
};

export interface GradeSummaryProps {
  report: ScanReport;
  onRescan: () => void;
  cachedAt: number;
}

export function GradeSummary({ report, onRescan, cachedAt }: GradeSummaryProps): React.JSX.Element {
  // The briefing walks every check and every raw header, so it is built once
  // per report rather than on each re-render of the summary.
  const briefing = useMemo(() => toLlmBriefing(report), [report]);

  const counts = {
    pass: report.checks.filter((check) => check.status === 'pass').length,
    warn: report.checks.filter((check) => check.status === 'warn').length,
    fail: report.checks.filter((check) => check.status === 'fail').length,
  };

  return (
    <div className="summary">
      {/* The ring is decoration; the same numbers are in the text beside it. */}
      <div
        className="grade"
        style={{ '--grade-arc': arc(report.score), '--grade-color': GRADE_COLOR[report.grade] } as React.CSSProperties}
        aria-hidden="true"
      >
        <span className="grade__inner">
          <span className="grade__letter">{report.grade}</span>
          <span className="grade__score">{report.score}/100</span>
        </span>
      </div>

      <div className="summary__meta">
        <h2 className="visually-hidden">Resultado</h2>
        <p className="summary__url">{report.target.final}</p>
        <p style={{ margin: 0 }}>
          Nota <strong>{report.grade}</strong> — {report.score} de 100 pontos.
        </p>

        <ul className="tally">
          {counts.fail > 0 && (
            <li>
              <StatusPill status="fail" />
              <span className="visually-hidden">{counts.fail} itens com falha</span>
              <span aria-hidden="true"> {counts.fail}</span>
            </li>
          )}
          {counts.warn > 0 && (
            <li>
              <StatusPill status="warn" />
              <span className="visually-hidden">{counts.warn} itens com atenção</span>
              <span aria-hidden="true"> {counts.warn}</span>
            </li>
          )}
          {counts.pass > 0 && (
            <li>
              <StatusPill status="pass" />
              <span className="visually-hidden">{counts.pass} itens corretos</span>
              <span aria-hidden="true"> {counts.pass}</span>
            </li>
          )}
        </ul>

        <ul className="summary__facts">
          <li>
            HTTP <strong>{report.target.statusCode}</strong>
          </li>
          <li>
            IP <strong>{report.target.resolvedIp}</strong>
          </li>
          {report.target.redirects.length > 0 && (
            <li>
              <strong>{report.target.redirects.length}</strong> redirecionamento(s)
            </li>
          )}
          <li>
            <strong>{report.durationMs} ms</strong>
          </li>
          <li>
            <span title={new Date(cachedAt).toLocaleString('pt-BR')}>
              Analisado às {new Date(cachedAt).toLocaleTimeString('pt-BR')}
            </span>
          </li>
        </ul>

        {report.insecureTransport && (
          <p className="banner">
            <span aria-hidden="true">⚠</span>
            <span>
              A resposta final veio por <strong>HTTP puro</strong>. Todo o resto é secundário: enquanto a conexão não
              for HTTPS, qualquer intermediário lê e reescreve o tráfego — inclusive esses headers. Por isso a nota está
              limitada, independentemente dos headers presentes.
            </span>
          </p>
        )}

        <div className="summary__actions">
          <button type="button" className="button button--ghost button--small" onClick={onRescan}>
            Analisar de novo
          </button>
          <CopyButton text={briefing} label="relatório para IA" caption="Copiar para IA" />
        </div>
        <p className="summary__hint">
          O relatório sai em Markdown, com o alvo, cada falha, o valor recebido e a correção proposta — pronto para
          colar num assistente e pedir a configuração do seu servidor.
        </p>
      </div>
    </div>
  );
}
