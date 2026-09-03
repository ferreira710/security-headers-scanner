import type { CheckResult } from '../types';
import { CopyButton } from './CopyButton';
import { StatusPill } from './StatusPill';

/**
 * `<details>` rather than a hand-rolled accordion: keyboard operation, the
 * expanded/collapsed state and in-page find all come from the browser.
 * Failures start open, because those are the ones worth reading.
 */
export function CheckCard({ check }: { check: CheckResult }): React.JSX.Element {
  const fixLine = `${check.fix.header}: ${check.fix.value}`;

  return (
    <li>
      <details className={`check check--${check.status}`} open={check.status === 'fail'}>
        <summary className="check__summary">
          <span className="check__chevron" aria-hidden="true">
            ›
          </span>
          <span className="check__heading">
            <span className="check__title">
              {check.label}
              <StatusPill status={check.status} />
            </span>
            <span className="check__subtitle">{check.summary}</span>
          </span>
          <span className="check__points">
            {check.points}/{check.weight}
            <span className="visually-hidden"> pontos</span>
          </span>
        </summary>

        <div className="check__body">
          <div className="check__section">
            <h4>Por que importa</h4>
            <p>{check.risk}</p>
          </div>

          {check.findings.length > 0 && (
            <div className="check__section">
              <h4>O que foi encontrado</h4>
              <ul className="check__findings">
                {check.findings.map((finding) => (
                  <li key={finding}>{finding}</li>
                ))}
              </ul>
            </div>
          )}

          {check.observed !== null && (
            <div className="check__section">
              <h4>Valor recebido</h4>
              <pre className="check__observed">{check.observed.join('\n')}</pre>
            </div>
          )}

          <div className="check__section">
            <h4>Como corrigir</h4>
            <div className="fix">
              <div className="fix__code">
                <pre>
                  <code>{fixLine}</code>
                </pre>
                <CopyButton text={fixLine} label={`header ${check.fix.header}`} />
              </div>
              <p className="fix__note">{check.fix.note}</p>
            </div>
          </div>

          <div className="check__section">
            <a href={check.docsUrl} target="_blank" rel="noreferrer noopener">
              Documentação de {check.headerName}
              <span className="visually-hidden"> (abre em nova aba)</span>
            </a>
          </div>
        </div>
      </details>
    </li>
  );
}
