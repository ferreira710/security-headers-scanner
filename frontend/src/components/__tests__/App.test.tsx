import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App } from '../../App';
import type { RawHeader, ScanResponseDto } from '../../types';

function dto(headers: Record<string, string>, finalUrl = 'https://example.com/'): ScanResponseDto {
  const raw: RawHeader[] = Object.entries(headers).map(([name, value]) => ({ name, value }));
  return {
    target: { requested: finalUrl, final: finalUrl, statusCode: 200, redirects: [], resolvedIp: '93.184.216.34' },
    headers: raw,
    durationMs: 87,
    fetchedAt: '2026-09-03T00:00:00+00:00',
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

function renderApp() {
  // retry: false so a failure test asserts the error screen, not three retries.
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <App />
    </QueryClientProvider>,
  );
  return userEvent.setup();
}

const fetchMock = vi.fn<typeof fetch>();

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock);
  fetchMock.mockReset();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('App', () => {
  it('shows an explanation before any scan runs', () => {
    renderApp();
    expect(screen.getByRole('heading', { name: /o que este scanner faz/i })).toBeInTheDocument();
  });

  it('scans a site and renders the grade with a per-header breakdown', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(
        dto({
          'content-security-policy':
            "default-src 'self'; script-src 'self' 'nonce-x'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
          'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
          'x-content-type-options': 'nosniff',
          'referrer-policy': 'strict-origin-when-cross-origin',
          'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
        }),
      ),
    );

    const user = renderApp();
    await user.type(screen.getByLabelText(/endereço do site/i), 'example.com{Enter}');

    // The accessible name of the report heading carries the whole verdict.
    const report = await screen.findByRole('region', { name: /nota A, 100 de 100/i });
    expect(within(report).getByText('Content-Security-Policy')).toBeInTheDocument();
    // Exact match: the region's own heading also contains the URL, in a longer sentence.
    expect(within(report).getByText('https://example.com/')).toBeInTheDocument();
  });

  it('explains the risk and the fix for a missing header', async () => {
    fetchMock.mockResolvedValue(jsonResponse(dto({ server: 'nginx' })));

    const user = renderApp();
    await user.type(screen.getByLabelText(/endereço do site/i), 'example.com{Enter}');
    await screen.findByRole('region', { name: /nota F/i });

    // Failing checks render expanded, so both the risk and the concrete attack
    // are on screen without a click. Each appears twice by design: once as the
    // header's purpose, once as what was actually found.
    expect(screen.getAllByText(/clickjacking/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/MIME sniffing/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/botão falso exatamente em cima/i)).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /copiar/i }).length).toBeGreaterThan(0);
  });

  it('sends the URL to the API as JSON', async () => {
    fetchMock.mockResolvedValue(jsonResponse(dto({})));

    const user = renderApp();
    await user.type(screen.getByLabelText(/endereço do site/i), 'example.com{Enter}');
    await screen.findByRole('region', { name: /nota/i });

    const [, init] = fetchMock.mock.calls[0] ?? [];
    expect(init?.method).toBe('POST');
    expect(JSON.parse(String(init?.body))).toEqual({ url: 'example.com' });
  });

  it('surfaces a blocked target as an explained refusal, not a crash', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ code: 'blocked_target', message: 'localhost aponta para um endereco interno (127.0.0.1).' }, 400),
    );

    const user = renderApp();
    await user.type(screen.getByLabelText(/endereço do site/i), 'internal.example.com{Enter}');

    expect(await screen.findByRole('heading', { name: /bloqueado por segurança/i })).toBeInTheDocument();
    expect(screen.getByText(/SSRF/i)).toBeInTheDocument();
  });

  it('reports a rate limit with the wait time', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ code: 'rate_limited', message: 'Limite atingido.', retryAfterSeconds: 42 }, 429),
    );

    const user = renderApp();
    await user.type(screen.getByLabelText(/endereço do site/i), 'example.com{Enter}');

    expect(await screen.findByRole('heading', { name: /muitas análises/i })).toBeInTheDocument();
    expect(screen.getByText('42 segundos')).toBeInTheDocument();
  });

  it('handles the API being unreachable', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'));

    const user = renderApp();
    await user.type(screen.getByLabelText(/endereço do site/i), 'example.com{Enter}');

    // A network blip is one of the two codes useScan retries, so this resolves
    // only after the retries are exhausted.
    expect(
      await screen.findByRole('heading', { name: /API fora de alcance/i }, { timeout: 5000 }),
    ).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('serves a repeated scan from cache instead of hitting the API again', async () => {
    fetchMock.mockResolvedValue(jsonResponse(dto({ 'x-content-type-options': 'nosniff' })));

    const user = renderApp();
    await user.type(screen.getByLabelText(/endereço do site/i), 'example.com{Enter}');
    await screen.findByRole('region', { name: /nota/i });
    expect(fetchMock).toHaveBeenCalledTimes(1);

    await user.click(screen.getByRole('button', { name: 'example.com' }));
    await waitFor(() => expect(screen.getByRole('region', { name: /nota/i })).toBeInTheDocument());
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('caps the grade and warns when the final response is plain HTTP', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(
        dto(
          {
            'content-security-policy':
              "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
            'x-content-type-options': 'nosniff',
            'referrer-policy': 'no-referrer',
          },
          'http://example.com/',
        ),
      ),
    );

    const user = renderApp();
    await user.type(screen.getByLabelText(/endereço do site/i), 'example.com{Enter}');

    await screen.findByRole('region', { name: /nota F/i });
    // Called out twice: the banner at the top, and the HSTS check below it.
    expect(screen.getAllByText(/HTTP puro/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/a nota está limitada/i)).toBeInTheDocument();
  });

  it('marks the results region busy while a scan is running', async () => {
    let release: (value: Response) => void = () => {};
    fetchMock.mockReturnValue(new Promise<Response>((resolve) => (release = resolve)));

    const user = renderApp();
    await user.type(screen.getByLabelText(/endereço do site/i), 'example.com{Enter}');

    const live = document.querySelector('[aria-live="polite"]');
    expect(live).toHaveAttribute('aria-busy', 'true');

    release(jsonResponse(dto({})));
    await screen.findByRole('region', { name: /nota/i });
    expect(live).toHaveAttribute('aria-busy', 'false');
  });
});
