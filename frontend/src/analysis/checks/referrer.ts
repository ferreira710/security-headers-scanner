import type { CheckOutcome } from '../../types';
import { parseTokenList, type ScanContext } from '../headers';
import type { CheckDefinition } from '../registry';

/** Policies that never leak a path or query string across origins. */
const STRONG = new Set(['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin']);
/** Valid, but they send the origin (or more) to third parties. */
const WEAK = new Set(['origin', 'origin-when-cross-origin', 'no-referrer-when-downgrade']);
const DANGEROUS = 'unsafe-url';

const ALL_KNOWN = new Set([...STRONG, ...WEAK, DANGEROUS]);

const FIX = {
  header: 'Referrer-Policy',
  value: 'strict-origin-when-cross-origin',
  note: 'Mantém o Referer completo dentro do próprio site (útil para analytics interno) e envia só a origem para terceiros. Use `no-referrer` se nem a origem puder vazar.',
};

function run(context: ScanContext): CheckOutcome {
  const tokens = parseTokenList(context.headers.all('referrer-policy'));

  if (tokens.length === 0) {
    return {
      status: 'warn',
      ratio: 0.5,
      summary: 'Ausente. Vale o padrão do navegador, que varia entre versões.',
      findings: [
        'Navegadores atuais usam `strict-origin-when-cross-origin` por padrão, então o risco imediato é baixo.',
        'Mas o padrão já foi `no-referrer-when-downgrade`, e navegadores antigos ainda enviam a URL inteira para terceiros. Declarar o valor tira a proteção das mãos do cliente.',
      ],
      fix: FIX,
    };
  }

  // The browser applies the last token it recognises, so unknown values at the
  // end are skipped rather than overriding a valid earlier one.
  const effective = [...tokens].reverse().find((token) => ALL_KNOWN.has(token));

  if (effective === undefined) {
    return {
      status: 'warn',
      ratio: 0.5,
      summary: `Nenhum valor reconhecido em \`${tokens.join(', ')}\` — o navegador cai no padrão dele.`,
      findings: [`\`${tokens.join(', ')}\` não contém nenhuma política válida, então o header não tem efeito.`],
      fix: FIX,
    };
  }

  if (effective === DANGEROUS) {
    return {
      status: 'fail',
      ratio: 0,
      summary: '`unsafe-url` envia a URL completa para qualquer destino, inclusive por HTTP.',
      findings: [
        'Tokens de reset de senha, convites e IDs internos costumam viver na query string. Com `unsafe-url` eles saem no header `Referer` para todo domínio de terceiro que a página carregar — e ficam no log dele.',
      ],
      fix: FIX,
    };
  }

  if (WEAK.has(effective)) {
    return {
      status: 'warn',
      ratio: 0.6,
      summary: `\`${effective}\` protege o caminho, mas ainda revela a origem para terceiros.`,
      findings: [
        effective === 'no-referrer-when-downgrade'
          ? '`no-referrer-when-downgrade` envia a URL completa para qualquer destino HTTPS, incluindo terceiros.'
          : `\`${effective}\` envia a origem para todo destino externo. \`strict-origin-when-cross-origin\` faz o mesmo sem vazar em downgrade para HTTP.`,
      ],
      fix: FIX,
    };
  }

  return {
    status: 'pass',
    ratio: 1,
    summary: `\`${effective}\` impede que a URL completa vaze para outras origens.`,
    findings:
      tokens.length > 1
        ? [`A resposta traz ${tokens.length} valores; o navegador aplica o último que reconhece (\`${effective}\`).`]
        : [],
    fix: FIX,
  };
}

export const referrerPolicyCheck: CheckDefinition = {
  id: 'referrer-policy',
  label: 'Referrer-Policy',
  headerName: 'Referrer-Policy',
  observedHeaders: ['referrer-policy'],
  weight: 10,
  risk:
    'Define quanto da URL atual viaja no header Referer quando o usuário sai da página. Sem controle, um token de reset de senha na query string acaba nos logs de todo script de terceiro que a página carrega.',
  docsUrl: 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy',
  run,
};
