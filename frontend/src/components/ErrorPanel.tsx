import type { ScanFailure, ScanErrorCode } from '../types';

/** A next step for each failure, so the panel is never a dead end. */
const NEXT_STEP: Record<ScanErrorCode, string> = {
  invalid_url: 'Confira o endereço e tente de novo — algo como example.com ou https://example.com/pagina.',
  blocked_target:
    'Só analisamos endereços públicos. Bloquear IPs privados, localhost e a faixa 169.254.x.x é o que impede que este scanner seja usado para alcançar a rede interna de quem o hospeda (SSRF).',
  dns_failure: 'O domínio não resolveu. Verifique a grafia ou se o site ainda existe.',
  unreachable: 'O servidor recusou a conexão ou o certificado TLS falhou. O site pode estar fora do ar.',
  timeout: 'O site demorou demais para responder. Tente novamente em alguns segundos.',
  too_many_redirects: 'A cadeia de redirecionamentos é longa demais — provavelmente um laço.',
  rate_limited: 'Você atingiu o limite de análises. O limite existe para o scanner não virar ferramenta de varredura.',
  network: 'O frontend não alcançou a API. Se estiver rodando local, confirme que o backend está de pé na porta 8000.',
  unexpected: 'Tente novamente. Se persistir, é bug do scanner e não do site analisado.',
};

const TITLE: Partial<Record<ScanErrorCode, string>> = {
  blocked_target: 'Endereço bloqueado por segurança',
  rate_limited: 'Muitas análises seguidas',
  timeout: 'Tempo esgotado',
  network: 'API fora de alcance',
};

export function ErrorPanel({ failure, onRetry }: { failure: ScanFailure; onRetry: () => void }): React.JSX.Element {
  return (
    <div className="panel panel--error">
      <h2>{TITLE[failure.code] ?? 'Não foi possível analisar'}</h2>
      <p>{failure.message}</p>
      <p>{NEXT_STEP[failure.code]}</p>
      {failure.retryAfterSeconds !== undefined && (
        <p>
          Tente novamente em <strong>{failure.retryAfterSeconds} segundos</strong>.
        </p>
      )}
      <button type="button" className="button button--ghost" onClick={onRetry}>
        Tentar de novo
      </button>
    </div>
  );
}
