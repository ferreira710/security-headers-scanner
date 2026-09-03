import type { CheckOutcome } from '../../types';
import type { ScanContext } from '../headers';
import type { CheckDefinition } from '../registry';

const FIX = {
  header: 'X-Content-Type-Options',
  value: 'nosniff',
  note: 'Valor único e sem efeitos colaterais — desde que os `Content-Type` do servidor estejam corretos. Se algo quebrar, o bug está no tipo declarado, não neste header.',
};

function run(context: ScanContext): CheckOutcome {
  const value = context.headers.first('x-content-type-options');

  if (value === null) {
    return {
      status: 'fail',
      ratio: 0,
      summary: 'Ausente. O browser pode ignorar o `Content-Type` declarado e adivinhar o tipo.',
      findings: [
        'MIME sniffing: um arquivo enviado por usuário e servido como `text/plain` pode ser interpretado como HTML ou JavaScript se o conteúdo parecer com isso — virando XSS armazenado a partir de um upload aparentemente inofensivo.',
      ],
      fix: FIX,
    };
  }

  if (value.trim().toLowerCase() === 'nosniff') {
    return {
      status: 'pass',
      ratio: 1,
      summary: 'O browser respeita o `Content-Type` declarado.',
      findings: [],
      fix: FIX,
    };
  }

  return {
    status: 'fail',
    ratio: 0,
    summary: `Valor inválido (\`${value}\`): o header só reconhece \`nosniff\`.`,
    findings: [`\`${value}\` não é um valor válido, então o browser trata o header como ausente.`],
    fix: FIX,
  };
}

export const contentTypeOptionsCheck: CheckDefinition = {
  id: 'content-type-options',
  label: 'X-Content-Type-Options',
  headerName: 'X-Content-Type-Options',
  observedHeaders: ['x-content-type-options'],
  weight: 10,
  risk:
    'Impede que o navegador "adivinhe" o tipo de um arquivo em vez de confiar no Content-Type. Sem isso, um upload de usuário servido com o tipo errado pode ser executado como script.',
  docsUrl: 'https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options',
  run,
};
