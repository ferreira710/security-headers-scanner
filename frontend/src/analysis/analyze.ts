/**
 * Turns a raw HTTP response into a graded report.
 *
 * Pure: same headers in, same report out. That is what makes the scoring rules
 * testable without a network, a browser or a mock server.
 */

import type { CheckResult, Grade, ScanReport, ScanResponseDto } from '../types';
import { CHECKS } from './checks';
import { buildContext } from './headers';

/** Lower bound of each grade, checked in order. */
const GRADE_THRESHOLDS: readonly (readonly [Grade, number])[] = [
  ['A', 90],
  ['B', 80],
  ['C', 70],
  ['D', 60],
  ['E', 50],
  ['F', 0],
];

/**
 * A site served over plain HTTP cannot score above this, no matter how good
 * its headers are: every one of them is advisory when the connection itself
 * can be rewritten in transit.
 */
export const INSECURE_TRANSPORT_CAP = 45;

export function gradeFor(score: number): Grade {
  for (const [grade, minimum] of GRADE_THRESHOLDS) {
    if (score >= minimum) return grade;
  }
  return 'F';
}

export function totalWeight(): number {
  return CHECKS.reduce((sum, check) => sum + check.weight, 0);
}

export function analyze(response: ScanResponseDto): ScanReport {
  const context = buildContext(response.target.final, response.headers);

  const checks: CheckResult[] = CHECKS.map((definition) => {
    const outcome = definition.run(context);
    const observed = definition.observedHeaders.flatMap((name) =>
      context.headers.all(name).map((value) => `${name}: ${value}`),
    );

    return {
      ...outcome,
      id: definition.id,
      label: definition.label,
      headerName: definition.headerName,
      weight: definition.weight,
      points: Math.round(outcome.ratio * definition.weight * 10) / 10,
      risk: definition.risk,
      docsUrl: definition.docsUrl,
      observed: observed.length > 0 ? observed : null,
    };
  });

  const earned = checks.reduce((sum, check) => sum + check.ratio * check.weight, 0);
  const rawScore = Math.round((earned / totalWeight()) * 100);
  const insecureTransport = !context.isHttps;
  const score = insecureTransport ? Math.min(rawScore, INSECURE_TRANSPORT_CAP) : rawScore;

  return {
    target: response.target,
    score,
    grade: gradeFor(score),
    checks,
    headers: response.headers,
    durationMs: response.durationMs,
    fetchedAt: response.fetchedAt,
    insecureTransport,
  };
}
