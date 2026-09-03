import { useEffect, useRef, useState } from 'react';

export interface CopyButtonProps {
  text: string;
  /** Named in the live region, so "Copiado" alone never reaches a screen reader. */
  label: string;
  /** Visible face of the button before the copy lands. */
  caption?: string;
}

/** Copies `text`, and says so in a live region for screen readers. */
export function CopyButton({ text, label, caption = 'Copiar' }: CopyButtonProps): React.JSX.Element {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);

  useEffect(() => () => clearTimeout(timer.current), []);

  const copy = async (): Promise<void> => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  return (
    <>
      <button type="button" className="button button--ghost button--small" onClick={() => void copy()}>
        {copied ? 'Copiado' : caption}
        <span className="visually-hidden"> {label}</span>
      </button>
      <span role="status" className="visually-hidden">
        {copied ? `${label} copiado para a área de transferência` : ''}
      </span>
    </>
  );
}
