import type { CheckOutcome } from '../../types';
import { parseCsp, type ScanContext } from '../headers';
import type { CheckDefinition } from '../registry';

const FIX = {
  header: 'Content-Security-Policy',
  value: "frame-ancestors 'none'",
  note: "Use `'none'` se a página nunca deve ser embutida, ou `'self'` se você mesmo a embute. Mantenha `X-Frame-Options: DENY` junto enquanto precisar suportar navegadores antigos — quando os dois existem, o `frame-ancestors` prevalece.",
};

/** `frame-ancestors` is the modern control; X-Frame-Options is its predecessor. */
function readFrameAncestors(context: ScanContext): readonly string[] | null {
  for (const policy of context.headers.all('content-security-policy')) {
    const values = parseCsp(policy).get('frame-ancestors');
    if (values) return values.map((value) => value.toLowerCase());
  }
  return null;
}

function run(context: ScanContext): CheckOutcome {
  const frameAncestors = readFrameAncestors(context);
  const xfo = context.headers.first('x-frame-options')?.trim().toLowerCase() ?? null;

  if (frameAncestors !== null) {
    if (frameAncestors.includes('*')) {
      return {
        status: 'fail',
        ratio: 0,
        summary: '`frame-ancestors *` permite que qualquer site embuta a página.',
        findings: ['O curinga anula a diretiva: qualquer domínio pode carregar a página num iframe.'],
        fix: FIX,
      };
    }

    const findings: string[] = [];
    if (xfo === null) {
      findings.push(
        'Só `frame-ancestors` está presente. Navegadores atuais bastam, mas adicionar `X-Frame-Options: DENY` cobre clientes antigos sem custo.',
      );
    }

    return {
      status: 'pass',
      ratio: 1,
      summary: `Embutir a página está restrito a: ${frameAncestors.join(', ')}.`,
      findings,
      fix: FIX,
    };
  }

  if (xfo === null) {
    return {
      status: 'fail',
      ratio: 0,
      summary: 'Ausente. A página pode ser embutida em um iframe por qualquer site.',
      findings: [
        'Clickjacking: o atacante carrega esta página invisível (opacity 0) sobre a dele e posiciona um botão falso exatamente em cima de uma ação real — "excluir conta", "autorizar pagamento". O clique é do usuário, autenticado, na sua origem.',
      ],
      fix: FIX,
    };
  }

  if (xfo === 'deny' || xfo === 'sameorigin') {
    return {
      status: 'pass',
      ratio: 0.85,
      summary: `\`X-Frame-Options: ${xfo.toUpperCase()}\` bloqueia o embutimento.`,
      findings: [
        'Funciona, mas `X-Frame-Options` é o mecanismo antigo. `Content-Security-Policy: frame-ancestors` o substitui e permite listar origens específicas.',
      ],
      fix: FIX,
    };
  }

  if (xfo.startsWith('allow-from')) {
    return {
      status: 'fail',
      ratio: 0.1,
      summary: '`ALLOW-FROM` foi removido dos navegadores — na prática não há proteção.',
      findings: [
        'Nenhum navegador atual implementa `X-Frame-Options: ALLOW-FROM`. O header é ignorado e a página fica embutível por qualquer origem.',
      ],
      fix: FIX,
    };
  }

  return {
    status: 'fail',
    ratio: 0,
    summary: `Valor não reconhecido (\`${xfo}\`), então o header é ignorado.`,
    findings: [`\`X-Frame-Options: ${xfo}\` não é um valor válido. Os únicos aceitos são DENY e SAMEORIGIN.`],
    fix: FIX,
  };
}

export const framingCheck: CheckDefinition = {
  id: 'frame-ancestors',
  label: 'Proteção contra clickjacking',
  headerName: 'X-Frame-Options / frame-ancestors',
  observedHeaders: ['x-frame-options', 'content-security-policy'],
  weight: 15,
  risk:
    'Controla quem pode embutir a página num iframe. Sem isso vem o clickjacking: a vítima acha que clica no site do atacante e na verdade clica num botão real do seu, já autenticada.',
  docsUrl: 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors',
  run,
};
