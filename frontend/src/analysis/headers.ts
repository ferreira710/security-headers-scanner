/**
 * Header lookup and the small parsers the checks share.
 *
 * All of it is pure and works on the raw header list, so the same functions
 * that drive the report also drive the tests.
 */

import type { RawHeader } from '../types';

/** Read-only view over one response's headers. */
export class HeaderBag {
  private readonly byName: ReadonlyMap<string, readonly string[]>;

  constructor(headers: readonly RawHeader[]) {
    const map = new Map<string, string[]>();
    for (const { name, value } of headers) {
      const key = name.trim().toLowerCase();
      const existing = map.get(key);
      if (existing) existing.push(value.trim());
      else map.set(key, [value.trim()]);
    }
    this.byName = map;
  }

  /** All values sent under this name, in wire order. Empty if absent. */
  all(name: string): readonly string[] {
    return this.byName.get(name.toLowerCase()) ?? [];
  }

  /** The first value, or null when the header was not sent. */
  first(name: string): string | null {
    return this.all(name)[0] ?? null;
  }

  has(name: string): boolean {
    return this.all(name).length > 0;
  }
}

/** Context handed to every check. */
export interface ScanContext {
  readonly headers: HeaderBag;
  /** Final URL after redirects. */
  readonly url: URL;
  readonly isHttps: boolean;
}

export function buildContext(finalUrl: string, headers: readonly RawHeader[]): ScanContext {
  const url = new URL(finalUrl);
  return { headers: new HeaderBag(headers), url, isHttps: url.protocol === 'https:' };
}

// --- Parsers ----------------------------------------------------------------

/** A CSP policy as `directive -> values`, lower-cased, order preserved. */
export type CspDirectives = ReadonlyMap<string, readonly string[]>;

export function parseCsp(policy: string): CspDirectives {
  const directives = new Map<string, string[]>();
  for (const segment of policy.split(';')) {
    const tokens = segment.trim().split(/\s+/).filter(Boolean);
    const [name, ...values] = tokens;
    if (!name) continue;
    const key = name.toLowerCase();
    // A repeated directive inside one policy is ignored by the browser after
    // the first occurrence, so we keep the first too.
    if (!directives.has(key)) directives.set(key, values);
  }
  return directives;
}

/**
 * The source list a browser would apply for `directive`, walking the fallback
 * chain (`script-src-elem` -> `script-src` -> `default-src`). Returns null when
 * nothing in the chain is set, which means "not restricted at all".
 */
export function effectiveSources(
  directives: CspDirectives,
  chain: readonly string[],
): readonly string[] | null {
  for (const name of chain) {
    const values = directives.get(name);
    if (values) return values.map((value) => value.toLowerCase());
  }
  return null;
}

export interface HstsDirectives {
  readonly maxAge: number | null;
  readonly includeSubDomains: boolean;
  readonly preload: boolean;
}

export function parseHsts(value: string): HstsDirectives {
  let maxAge: number | null = null;
  let includeSubDomains = false;
  let preload = false;

  for (const raw of value.split(';')) {
    const token = raw.trim().toLowerCase();
    if (token === 'includesubdomains') includeSubDomains = true;
    else if (token === 'preload') preload = true;
    else if (token.startsWith('max-age')) {
      const [, rawSeconds = ''] = token.split('=');
      // Quoted forms (`max-age="31536000"`) are legal per RFC 6797.
      const parsed = Number.parseInt(rawSeconds.trim().replace(/"/g, ''), 10);
      if (Number.isFinite(parsed) && parsed >= 0) maxAge = parsed;
    }
  }

  return { maxAge, includeSubDomains, preload };
}

/** `camera=(), geolocation=(self "https://x")` -> `feature -> allowlist`. */
export function parsePermissionsPolicy(value: string): ReadonlyMap<string, string> {
  const features = new Map<string, string>();
  // Split on commas that are not inside parentheses.
  for (const segment of value.split(/,(?![^(]*\))/)) {
    const trimmed = segment.trim();
    if (!trimmed) continue;
    const equals = trimmed.indexOf('=');
    if (equals === -1) continue;
    const feature = trimmed.slice(0, equals).trim().toLowerCase();
    const allowlist = trimmed.slice(equals + 1).trim();
    if (feature) features.set(feature, allowlist);
  }
  return features;
}

/** Comma-separated token list, lower-cased and de-blanked. */
export function parseTokenList(values: readonly string[]): readonly string[] {
  return values
    .flatMap((value) => value.split(','))
    .map((token) => token.trim().toLowerCase())
    .filter(Boolean);
}

export function clampRatio(value: number): number {
  if (Number.isNaN(value)) return 0;
  return Math.min(1, Math.max(0, value));
}
