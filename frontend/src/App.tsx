import { ErrorPanel } from './components/ErrorPanel';
import { ReportView } from './components/Report';
import { ScanForm } from './components/ScanForm';
import { ScanSkeleton } from './components/ScanSkeleton';
import { useScan } from './hooks/useScan';
import type { ScanState } from './types';

/**
 * One `switch` over the scan union. Every branch is a complete screen, and the
 * compiler rejects a new state that nobody renders.
 */
function ScanOutcome({
  state,
  onRescan,
  cachedAt,
}: {
  state: ScanState;
  onRescan: () => void;
  cachedAt: number;
}): React.JSX.Element | null {
  switch (state.status) {
    case 'idle':
      return (
        <div className="panel">
          <h2>O que este scanner faz</h2>
          <p>
            Ele pede a página como um navegador pediria, lê só os headers da resposta e explica o que cada um protege —
            ou deixa de proteger. Nenhum conteúdo da página é baixado ou armazenado.
          </p>
          <p style={{ marginBottom: 0 }}>
            Cole um endereço acima ou clique num dos exemplos.
          </p>
        </div>
      );
    case 'scanning':
      return <ScanSkeleton url={state.url} />;
    case 'error':
      return <ErrorPanel failure={state.failure} onRetry={onRescan} />;
    case 'success':
      return <ReportView report={state.report} onRescan={onRescan} cachedAt={cachedAt} />;
  }
}

export function App(): React.JSX.Element {
  const { state, scan, rescan, updatedAt } = useScan();

  return (
    <>
      <a className="skip-link" href="#main">
        Pular para o conteúdo
      </a>

      <div className="page">
        <header className="site-header">
          <h1>Security Headers Scanner</h1>
          <p>
            Cole a URL de um site e receba uma nota de A a F pelos headers de segurança que ele envia — com o risco real
            de cada um que estiver faltando e o valor exato para corrigir.
          </p>
        </header>

        <main id="main">
          <ScanForm onScan={scan} busy={state.status === 'scanning'} />

          {/* Results are announced, not just rendered: `polite` waits for the
              user to pause instead of interrupting them mid-sentence. */}
          <div aria-live="polite" aria-busy={state.status === 'scanning'} style={{ marginTop: '1.5rem' }}>
            <ScanOutcome state={state} onRescan={rescan} cachedAt={updatedAt} />
          </div>
        </main>

        <footer className="site-footer">
          <p style={{ margin: 0 }}>
            A nota pesa cada header pelo estrago que a ausência dele causa: CSP 30, HSTS 20, clickjacking 15,
            X-Content-Type-Options 10, Referrer-Policy 10, Permissions-Policy 10, exposição da stack 5. É um
            critério defensável, não um padrão da indústria.
          </p>
        </footer>
      </div>
    </>
  );
}
