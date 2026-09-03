/** Placeholder that matches the report's shape, so nothing jumps on arrival. */
export function ScanSkeleton({ url }: { url: string }): React.JSX.Element {
  return (
    <div className="skeleton" aria-hidden="true" data-testid="scan-skeleton">
      <div className="skeleton__block" style={{ '--h': '9rem' } as React.CSSProperties} />
      {[0, 1, 2, 3].map((index) => (
        <div key={index} className="skeleton__block" style={{ '--h': '4.5rem' } as React.CSSProperties} />
      ))}
      <span className="visually-hidden">Analisando {url}…</span>
    </div>
  );
}
