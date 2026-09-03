import type { ScanFailure, ScanResponseDto } from '../types';

const API_BASE = import.meta.env['VITE_API_BASE'] ?? '';

/** Carries the typed failure so the UI can switch on `code` instead of parsing text. */
export class ScanApiError extends Error {
  readonly failure: ScanFailure;

  constructor(failure: ScanFailure) {
    super(failure.message);
    this.name = 'ScanApiError';
    this.failure = failure;
  }
}

function isScanFailure(value: unknown): value is ScanFailure {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { code?: unknown }).code === 'string' &&
    typeof (value as { message?: unknown }).message === 'string'
  );
}

export async function requestScan(url: string, signal?: AbortSignal): Promise<ScanResponseDto> {
  let response: Response;

  try {
    response = await fetch(`${API_BASE}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      ...(signal ? { signal } : {}),
    });
  } catch (error) {
    // An aborted request is React Query cancelling the previous scan, not a
    // failure worth showing.
    if (error instanceof DOMException && error.name === 'AbortError') throw error;
    throw new ScanApiError({
      code: 'network',
      message: 'Não consegui falar com a API. Confira se o backend está no ar.',
    });
  }

  if (response.ok) {
    return (await response.json()) as ScanResponseDto;
  }

  const body: unknown = await response.json().catch(() => null);

  if (isScanFailure(body)) throw new ScanApiError(body);

  throw new ScanApiError({
    code: 'unexpected',
    message: `A API respondeu ${response.status} sem um corpo que eu soubesse ler.`,
  });
}
