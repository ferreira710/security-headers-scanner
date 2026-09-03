import type { CheckOutcome } from '../../types';
import { clampRatio, parseHsts, type ScanContext } from '../headers';
import type { CheckDefinition } from '../registry';

const ONE_YEAR = 31_536_000;
const SIX_MONTHS = 15_768_000;
const ONE_DAY = 86_400;

const FIX = {
  header: 'Strict-Transport-Security',
  value: 'max-age=31536000; includeSubDomains; preload',
  note: 'Suba o `max-age` aos poucos (1 dia, 1 semana, 1 ano). `includeSubDomains` afeta todos os subdomínios, então confirme que todos já servem HTTPS antes de ativar.',
};

function run(context: ScanContext): CheckOutcome {
  if (!context.isHttps) {
    return {
      status: 'fail',
      ratio: 0,
      summary: 'O site respondeu em HTTP puro, então o HSTS nem chega a ser considerado.',
      findings: [
        'A resposta veio por HTTP. Navegadores ignoram `Strict-Transport-Security` em conexões não criptografadas, justamente porque um atacante na rede poderia forjá-lo.',
        'Antes de qualquer header, o tráfego precisa sair de HTTP: hoje ele é legível e modificável por quem estiver no caminho.',
      ],
      fix: FIX,
    };
  }

  const value = context.headers.first('strict-transport-security');
  if (value === null) {
    return {
      status: 'fail',
      ratio: 0,
      summary: 'Ausente. A primeira visita do usuário ainda pode ser interceptada.',
      findings: [
        'Sem HSTS, quem digita `site.com` faz um pedido HTTP antes do redirect. Numa rede hostil esse pedido é sequestrado (sslstrip) e a vítima nunca chega ao HTTPS.',
        'Ressalva: domínios já na preload list dos navegadores ficam protegidos mesmo sem o header. Isso não aparece na resposta HTTP, então este relatório não tem como saber — mas o header continua valendo para clientes que não consultam a lista.',
      ],
      fix: FIX,
    };
  }

  const { maxAge, includeSubDomains, preload } = parseHsts(value);
  const findings: string[] = [];

  if (maxAge === null) {
    return {
      status: 'fail',
      ratio: 0.05,
      summary: 'O header existe, mas sem `max-age` válido — o browser descarta a política inteira.',
      findings: ['`max-age` ausente ou não numérico. A diretiva é obrigatória; sem ela o header é ignorado.'],
      fix: FIX,
    };
  }

  let ratio: number;
  if (maxAge >= ONE_YEAR) {
    ratio = 0.8;
  } else if (maxAge >= SIX_MONTHS) {
    ratio = 0.65;
    findings.push(`\`max-age=${maxAge}\` (~${Math.round(maxAge / 2_592_000)} meses). O recomendado é 31536000 (1 ano).`);
  } else if (maxAge >= ONE_DAY) {
    ratio = 0.4;
    findings.push(
      `\`max-age=${maxAge}\` é curto: a proteção expira em ${Math.round(maxAge / ONE_DAY)} dia(s) sem novas visitas.`,
    );
  } else {
    ratio = 0.15;
    findings.push(`\`max-age=${maxAge}\` é curto demais para proteger qualquer coisa na prática.`);
  }

  if (includeSubDomains) {
    ratio += 0.15;
  } else {
    findings.push(
      'Sem `includeSubDomains`: um subdomínio esquecido servindo HTTP (staging, legado) continua sendo porta de entrada para roubo de cookie de sessão.',
    );
  }

  if (preload) ratio += 0.05;
  else findings.push('Sem `preload`: a primeira visita de um usuário novo ainda depende de um pedido HTTP.');

  const finalRatio = clampRatio(ratio);
  const status = finalRatio >= 0.9 ? 'pass' : finalRatio >= 0.4 ? 'warn' : 'fail';

  return {
    status,
    ratio: finalRatio,
    summary:
      status === 'pass'
        ? 'Configurado com prazo longo e cobrindo subdomínios.'
        : 'Presente, mas com margem para endurecer.',
    findings,
    fix: FIX,
  };
}

export const hstsCheck: CheckDefinition = {
  id: 'hsts',
  label: 'Strict-Transport-Security',
  headerName: 'Strict-Transport-Security',
  observedHeaders: ['strict-transport-security'],
  weight: 20,
  risk:
    'Obriga o browser a só falar HTTPS com o domínio, mesmo que o usuário digite http:// ou clique num link antigo. Sem isso, um atacante na mesma rede Wi-Fi rebaixa a conexão e lê tudo em texto claro, incluindo cookies de sessão.',
  docsUrl: 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security',
  run,
};
