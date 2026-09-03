import type { CheckOutcome } from '../../types';
import { clampRatio, parsePermissionsPolicy, type ScanContext } from '../headers';
import type { CheckDefinition } from '../registry';

/**
 * The features worth locking down on a site that does not use them. An empty
 * allowlist -- `camera=()` -- denies the feature to the page and to everything
 * it embeds.
 */
const SENSITIVE_FEATURES = ['camera', 'microphone', 'geolocation', 'payment', 'usb'] as const;

const FIX = {
  header: 'Permissions-Policy',
  value: 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  note: 'Liste apenas o que o site realmente usa; o resto fica com allowlist vazia. Se a página precisa da câmera, use `camera=(self)`.',
};

function isLocked(allowlist: string): boolean {
  const normalized = allowlist.trim().toLowerCase();
  return normalized === '()' || normalized === '(none)' || normalized === '';
}

function run(context: ScanContext): CheckOutcome {
  const value = context.headers.first('permissions-policy');
  const legacy = context.headers.first('feature-policy');

  if (value === null) {
    return {
      status: 'warn',
      ratio: 0,
      summary: 'Ausente. Nada impede a página ou um iframe dela de pedir câmera, microfone ou localização.',
      findings: [
        legacy !== null
          ? 'Só o antigo `Feature-Policy` está presente. Ele foi substituído por `Permissions-Policy` e navegadores atuais o ignoram.'
          : 'Sem esse header, um script de terceiro comprometido (ou um iframe de anúncio) pode disparar o prompt de permissão do navegador em nome do seu domínio — e é o seu nome que aparece no diálogo.',
        'Não é uma vulnerabilidade por si só, mas é a diferença entre "o navegador nega direto" e "depende do usuário clicar certo".',
      ],
      fix: FIX,
    };
  }

  const features = parsePermissionsPolicy(value);
  const locked = SENSITIVE_FEATURES.filter((feature) => {
    const allowlist = features.get(feature);
    return allowlist !== undefined && isLocked(allowlist);
  });
  const wideOpen = SENSITIVE_FEATURES.filter((feature) => features.get(feature)?.includes('*'));

  const findings: string[] = [];
  const missing = SENSITIVE_FEATURES.filter(
    (feature) => !locked.includes(feature) && !wideOpen.includes(feature),
  );

  if (missing.length > 0) {
    findings.push(
      `Não restringido: ${missing.join(', ')}. Se o site não usa esses recursos, negá-los custa nada.`,
    );
  }
  if (wideOpen.length > 0) {
    findings.push(`Liberado para qualquer origem com \`*\`: ${wideOpen.join(', ')}.`);
  }

  const ratio = clampRatio(0.35 + (0.65 * locked.length) / SENSITIVE_FEATURES.length - 0.2 * wideOpen.length);
  const status = ratio >= 0.9 ? 'pass' : 'warn';

  return {
    status,
    ratio,
    summary: `${locked.length} de ${SENSITIVE_FEATURES.length} recursos sensíveis estão bloqueados.`,
    findings,
    fix: FIX,
  };
}

export const permissionsPolicyCheck: CheckDefinition = {
  id: 'permissions-policy',
  label: 'Permissions-Policy',
  headerName: 'Permissions-Policy',
  observedHeaders: ['permissions-policy', 'feature-policy'],
  weight: 10,
  risk:
    'Desliga APIs do navegador que o site não usa — câmera, microfone, geolocalização, pagamento. Reduz o estrago quando um script de terceiro é comprometido: ele não consegue nem pedir a permissão.',
  docsUrl: 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy',
  run,
};
