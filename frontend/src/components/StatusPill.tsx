import type { CheckStatus } from '../types';

/**
 * Status is carried by an icon *and* a word, never by colour alone (WCAG 1.4.1).
 * The icon is `aria-hidden` because the word next to it already says it.
 */
const PRESENTATION: Record<CheckStatus, { icon: string; label: string }> = {
  pass: { icon: '✓', label: 'OK' },
  warn: { icon: '!', label: 'Atenção' },
  fail: { icon: '✕', label: 'Falha' },
};

export function StatusPill({ status }: { status: CheckStatus }): React.JSX.Element {
  const { icon, label } = PRESENTATION[status];
  return (
    <span className={`pill pill--${status}`}>
      <span aria-hidden="true">{icon}</span>
      {label}
    </span>
  );
}
