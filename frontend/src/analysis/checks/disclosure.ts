import type { CheckOutcome } from '../../types';
import { clampRatio, type ScanContext } from '../headers';
import type { CheckDefinition } from '../registry';

/** Headers that name the stack running behind the request. */
const TELLTALE_HEADERS = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator'];
const VERSION_PATTERN = /\d+\.\d+/;

const FIX = {
  header: 'Server / X-Powered-By',
  value: '(remover, ou reduzir a um nome sem versão)',
  note: 'nginx: `server_tokens off;`. Express: `app.disable("x-powered-by")`. Apache: `ServerTokens Prod`. PHP: `expose_php = Off`.',
};

function run(context: ScanContext): CheckOutcome {
  const findings: string[] = [];
  let ratio = 1;

  const exposed = TELLTALE_HEADERS.flatMap((name) => {
    const value = context.headers.first(name);
    return value === null ? [] : [{ name, value }];
  });

  const withVersion = exposed.filter((entry) => VERSION_PATTERN.test(entry.value));

  if (withVersion.length > 0) {
    ratio -= 0.6;
    findings.push(
      `Versão exata publicada em ${withVersion.map((e) => `\`${e.name}: ${e.value}\``).join(', ')}. ` +
        'É o suficiente para cruzar com um CVE conhecido e escolher um exploit sem precisar testar nada no seu servidor.',
    );
  } else if (exposed.length > 0) {
    ratio -= 0.25;
    findings.push(
      `Tecnologia identificável em ${exposed.map((e) => `\`${e.name}: ${e.value}\``).join(', ')}, mas sem número de versão — impacto pequeno.`,
    );
  }

  // X-XSS-Protection was removed from browsers; its filter introduced bugs of
  // its own, so a non-zero value is worse than not sending the header.
  const xss = context.headers.first('x-xss-protection')?.trim().toLowerCase();
  if (xss !== undefined && xss !== '0' && xss !== '') {
    ratio -= 0.15;
    findings.push(
      `\`X-XSS-Protection: ${xss}\` é um header morto: o filtro foi removido dos navegadores e chegou a criar vulnerabilidades próprias. O valor correto hoje é \`0\`, ou simplesmente não enviar.`,
    );
  }

  const finalRatio = clampRatio(ratio);
  const status = finalRatio >= 0.9 ? 'pass' : 'warn';

  return {
    status,
    ratio: finalRatio,
    summary:
      status === 'pass'
        ? 'A resposta não anuncia versões de software.'
        : 'A resposta entrega detalhes da stack de graça.',
    findings,
    fix: FIX,
  };
}

export const informationDisclosureCheck: CheckDefinition = {
  id: 'info-disclosure',
  label: 'Exposição da stack',
  headerName: 'Server, X-Powered-By',
  observedHeaders: ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator', 'x-xss-protection'],
  weight: 5,
  risk:
    'Não é uma falha por si só, mas encurta o trabalho de quem procura uma. "nginx/1.18.0" transforma uma varredura genérica numa busca por CVEs daquela versão exata.',
  docsUrl: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server',
  run,
};
