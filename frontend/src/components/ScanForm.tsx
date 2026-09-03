import { useId, useState } from 'react';

const EXAMPLES = ['github.com', 'example.com', 'mozilla.org'] as const;

export interface ScanFormProps {
  onScan: (url: string) => void;
  busy: boolean;
}

/** Client-side sanity check only. The backend re-validates everything. */
function firstProblem(value: string): string | null {
  const trimmed = value.trim();
  if (trimmed === '') return 'Digite uma URL ou um domínio.';
  if (/\s/.test(trimmed)) return 'A URL não pode conter espaços.';

  const withScheme = trimmed.includes('://') ? trimmed : `https://${trimmed}`;
  let parsed: URL;
  try {
    parsed = new URL(withScheme);
  } catch {
    return 'Não consegui interpretar isso como uma URL.';
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return 'Só http e https são suportados.';
  }
  if (!parsed.hostname.includes('.')) {
    return 'Informe um domínio completo, como example.com.';
  }
  return null;
}

export function ScanForm({ onScan, busy }: ScanFormProps): React.JSX.Element {
  const [value, setValue] = useState('');
  const [error, setError] = useState<string | null>(null);
  const inputId = useId();
  const hintId = useId();
  const errorId = useId();

  const submit = (event: React.FormEvent): void => {
    event.preventDefault();
    const problem = firstProblem(value);
    setError(problem);
    if (problem === null) onScan(value);
  };

  const runExample = (example: string): void => {
    setValue(example);
    setError(null);
    onScan(example);
  };

  return (
    <form className="scan-form" onSubmit={submit} noValidate>
      <label className="scan-form__label" htmlFor={inputId}>
        Endereço do site
      </label>

      <div className="scan-form__row">
        <input
          id={inputId}
          className="scan-form__input"
          type="text"
          inputMode="url"
          autoComplete="url"
          spellCheck={false}
          placeholder="exemplo.com"
          value={value}
          onChange={(event) => {
            setValue(event.target.value);
            if (error) setError(null);
          }}
          aria-invalid={error !== null}
          aria-describedby={error !== null ? `${hintId} ${errorId}` : hintId}
        />
        <button type="submit" className="button" disabled={busy}>
          {busy ? 'Analisando…' : 'Analisar headers'}
        </button>
      </div>

      <p className="scan-form__hint" id={hintId}>
        Sem esquema, assumimos https. Só endereços públicos: IPs internos e localhost são recusados.
      </p>

      {error !== null && (
        <p className="scan-form__error" id={errorId}>
          {error}
        </p>
      )}

      <div className="examples">
        <span id={`${inputId}-examples`}>Exemplos:</span>
        {EXAMPLES.map((example) => (
          <button
            key={example}
            type="button"
            className="button button--ghost button--small"
            onClick={() => runExample(example)}
            disabled={busy}
          >
            {example}
          </button>
        ))}
      </div>
    </form>
  );
}
