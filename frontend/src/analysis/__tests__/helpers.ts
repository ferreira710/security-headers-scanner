import type { RawHeader, ScanResponseDto } from '../../types';
import { buildContext, type ScanContext } from '../headers';

export function headers(entries: Record<string, string | string[]>): RawHeader[] {
  return Object.entries(entries).flatMap(([name, value]) =>
    (Array.isArray(value) ? value : [value]).map((v) => ({ name, value: v })),
  );
}

export function context(
  entries: Record<string, string | string[]>,
  finalUrl = 'https://example.com/',
): ScanContext {
  return buildContext(finalUrl, headers(entries));
}

export function response(
  entries: Record<string, string | string[]>,
  finalUrl = 'https://example.com/',
): ScanResponseDto {
  return {
    target: {
      requested: finalUrl,
      final: finalUrl,
      statusCode: 200,
      redirects: [],
      resolvedIp: '93.184.216.34',
    },
    headers: headers(entries),
    durationMs: 120,
    fetchedAt: '2026-09-03T00:00:00+00:00',
  };
}

/** A response that should grade A, used as the baseline to weaken in tests. */
export const PERFECT_HEADERS: Record<string, string> = {
  'content-security-policy':
    "default-src 'self'; script-src 'self' 'nonce-abc123'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
  'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
};
