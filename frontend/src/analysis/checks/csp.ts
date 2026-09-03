import type { CheckOutcome } from '../../types';
import { clampRatio, effectiveSources, parseCsp, type ScanContext } from '../headers';
import type { CheckDefinition } from '../registry';

const SCRIPT_CHAIN = ['script-src-elem', 'script-src', 'default-src'] as const;
const OBJECT_CHAIN = ['object-src', 'default-src'] as const;

const NONCE_OR_HASH = /^'(nonce-|sha(256|384|512)-)/;
/** Sources broad enough that an attacker can almost always find a way in. */
const WILDCARD_SOURCES = new Set(['*', 'http:', 'https:', 'data:', 'blob:']);

interface PolicyVerdict {
  readonly ratio: number;
  readonly findings: readonly string[];
}

export function evaluatePolicy(policy: string): PolicyVerdict {
  const directives = parseCsp(policy);
  const findings: string[] = [];
  let ratio = 1;

  const scriptSources = effectiveSources(directives, SCRIPT_CHAIN);

  if (scriptSources === null) {
    ratio -= 0.5;
    findings.push(
      'Nenhum `default-src` nem `script-src`: a política existe, mas não limita de onde scripts podem ser carregados.',
    );
  } else {
    const hasNonceOrHash = scriptSources.some((source) => NONCE_OR_HASH.test(source));
    const hasStrictDynamic = scriptSources.includes("'strict-dynamic'");

    // A nonce or hash makes the browser ignore 'unsafe-inline', so the keyword
    // is only a fallback for old browsers there -- not a hole.
    if (scriptSources.includes("'unsafe-inline'") && !hasNonceOrHash && !hasStrictDynamic) {
      ratio -= 0.35;
      findings.push(
        "`'unsafe-inline'` em script-src desliga a principal defesa contra XSS: um `<script>` injetado na página executa normalmente.",
      );
    }

    if (scriptSources.includes("'unsafe-eval'")) {
      ratio -= 0.12;
      findings.push(
        "`'unsafe-eval'` libera `eval()` e `new Function()`, transformando qualquer string controlada pelo atacante em código.",
      );
    }

    const wildcards = scriptSources.filter((source) => WILDCARD_SOURCES.has(source));
    if (wildcards.length > 0 && !hasStrictDynamic) {
      ratio -= 0.25;
      findings.push(
        `Origem curinga em script-src (${wildcards.join(', ')}): o atacante só precisa hospedar o payload em qualquer domínio para a política aprovar.`,
      );
    }
  }

  const objectSources = effectiveSources(directives, OBJECT_CHAIN);
  if (objectSources === null || !objectSources.includes("'none'")) {
    ratio -= 0.08;
    findings.push(
      "Sem `object-src 'none'`: `<object>` e `<embed>` continuam sendo um caminho para executar conteúdo injetado.",
    );
  }

  // base-uri has no fallback to default-src -- a policy without it is open even
  // when default-src is 'self'.
  if (!directives.has('base-uri')) {
    ratio -= 0.1;
    findings.push(
      'Sem `base-uri`: uma tag `<base>` injetada reescreve todas as URLs relativas da página, inclusive as de script.',
    );
  }

  return { ratio: clampRatio(ratio), findings };
}

function run(context: ScanContext): CheckOutcome {
  const policies = context.headers.all('content-security-policy');
  const reportOnly = context.headers.all('content-security-policy-report-only');

  const fix = {
    header: 'Content-Security-Policy',
    value:
      "default-src 'self'; script-src 'self' 'nonce-{RANDOM}'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    note: 'Gere um nonce novo por resposta e use-o nas tags `<script>`. Vale publicar primeiro em `Content-Security-Policy-Report-Only` para ver o que quebraria.',
  };

  if (policies.length === 0) {
    if (reportOnly.length > 0) {
      return {
        status: 'warn',
        ratio: 0.15,
        summary: 'Existe apenas em modo report-only: as violações são reportadas, mas nada é bloqueado.',
        findings: [
          'A política está só em `Content-Security-Policy-Report-Only`. É o passo certo antes de aplicar, mas hoje não impede nenhum ataque.',
        ],
        fix,
      };
    }

    return {
      status: 'fail',
      ratio: 0,
      summary: 'Ausente. Nada restringe de onde a página carrega scripts.',
      findings: [
        'Sem CSP, qualquer XSS que passe pela validação de entrada vira execução de código com acesso total à sessão do usuário.',
      ],
      fix,
    };
  }

  // Multiple CSP headers are *intersected* by the browser: content has to pass
  // every policy. So the effective protection is that of the strictest one.
  const verdicts = policies.map(evaluatePolicy);
  const best = verdicts.reduce((a, b) => (b.ratio > a.ratio ? b : a));
  const findings = [...best.findings];

  if (policies.length > 1) {
    findings.push(
      `A resposta traz ${policies.length} políticas; o browser aplica a interseção delas. A nota reflete a mais restritiva.`,
    );
  }

  const status = best.ratio >= 0.9 ? 'pass' : best.ratio >= 0.35 ? 'warn' : 'fail';
  const summary =
    status === 'pass'
      ? 'Política restritiva e sem escapes óbvios.'
      : `Política presente, mas com ${best.findings.length} ponto(s) que a enfraquecem.`;

  return { status, ratio: best.ratio, summary, findings, fix };
}

export const cspCheck: CheckDefinition = {
  id: 'csp',
  label: 'Content-Security-Policy',
  headerName: 'Content-Security-Policy',
  observedHeaders: ['content-security-policy', 'content-security-policy-report-only'],
  weight: 30,
  risk:
    'É a última barreira contra XSS. Sem ela, um único campo que renderiza HTML sem escape deixa o atacante executar JavaScript no domínio da vítima: ler o DOM, roubar tokens do localStorage e agir como o usuário logado.',
  docsUrl: 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy',
  run,
};
