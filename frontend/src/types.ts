/**
 * Domain types shared by the API client, the analysis engine and the UI.
 *
 * Every union here is discriminated on a literal field, so `switch` on it is
 * exhaustive and adding a case makes the compiler point at every place that
 * has to handle it.
 */

// --- Wire format (mirrors backend/internal/api/api.go) ----------------------

/**
 * One header line. Duplicates are preserved and meaningful: two
 * Content-Security-Policy headers are intersected by the browser.
 *
 * Ordering is by header name, not wire order -- Go's net/http lands response
 * headers in a map, so the order they arrived in is not recoverable. Repeats of
 * the *same* name do keep their arrival order, which is what the analysis
 * needs. Hop-by-hop headers (Connection, Transfer-Encoding) never appear:
 * net/http consumes them, and none of them affect the grade.
 */
export interface RawHeader {
  readonly name: string;
  readonly value: string;
}

export interface ScanTargetDto {
  readonly requested: string;
  readonly final: string;
  readonly statusCode: number;
  readonly redirects: readonly string[];
  readonly resolvedIp: string;
}

export interface ScanResponseDto {
  readonly target: ScanTargetDto;
  readonly headers: readonly RawHeader[];
  readonly durationMs: number;
  readonly fetchedAt: string;
}

// --- Errors -----------------------------------------------------------------

/** Mirrors `Code` in backend/internal/scanner/errors.go, plus client-only cases. */
export type ScanErrorCode =
  | 'invalid_url'
  | 'blocked_target'
  | 'dns_failure'
  | 'unreachable'
  | 'timeout'
  | 'too_many_redirects'
  | 'rate_limited'
  | 'network'
  | 'unexpected';

export interface ScanFailure {
  readonly code: ScanErrorCode;
  readonly message: string;
  readonly retryAfterSeconds?: number;
}

// --- Analysis ---------------------------------------------------------------

export type Grade = 'A' | 'B' | 'C' | 'D' | 'E' | 'F';

/**
 * `pass`  - the header is present and configured well.
 * `warn`  - present but weakened, or absent where the browser default softens
 *           the blow. Worth fixing, not an open door.
 * `fail`  - absent or actively harmful. There is a concrete attack behind it.
 */
export type CheckStatus = 'pass' | 'warn' | 'fail';

export type CheckId =
  | 'csp'
  | 'hsts'
  | 'frame-ancestors'
  | 'content-type-options'
  | 'referrer-policy'
  | 'permissions-policy'
  | 'info-disclosure';

/** The corrected header the user should ship. */
export interface HeaderFix {
  readonly header: string;
  readonly value: string;
  readonly note: string;
}

/** What a single check decided, before the registry attaches its metadata. */
export interface CheckOutcome {
  readonly status: CheckStatus;
  /** Fraction of the check's weight that was earned, clamped to 0..1. */
  readonly ratio: number;
  /** One line stating the current state, shown as the card subtitle. */
  readonly summary: string;
  /** Specific problems found, each phrased as something to fix. */
  readonly findings: readonly string[];
  readonly fix: HeaderFix;
}

/** A check plus everything the UI needs to explain it. */
export interface CheckResult extends CheckOutcome {
  readonly id: CheckId;
  readonly label: string;
  readonly headerName: string;
  readonly weight: number;
  readonly points: number;
  /** What an attacker actually does when this is missing. Not a definition. */
  readonly risk: string;
  readonly docsUrl: string;
  /** The observed header value(s), or null when the header is absent. */
  readonly observed: readonly string[] | null;
}

export interface ScanReport {
  readonly target: ScanTargetDto;
  readonly score: number;
  readonly grade: Grade;
  readonly checks: readonly CheckResult[];
  readonly headers: readonly RawHeader[];
  readonly durationMs: number;
  readonly fetchedAt: string;
  /** Set when the final URL is plain HTTP, which caps the grade. */
  readonly insecureTransport: boolean;
}

// --- UI state ---------------------------------------------------------------

/**
 * The whole scan lifecycle as one closed union. The UI switches on `status`
 * and cannot read `report` before it exists.
 */
export type ScanState =
  | { readonly status: 'idle' }
  | { readonly status: 'scanning'; readonly url: string }
  | { readonly status: 'success'; readonly report: ScanReport }
  | { readonly status: 'error'; readonly url: string; readonly failure: ScanFailure };
