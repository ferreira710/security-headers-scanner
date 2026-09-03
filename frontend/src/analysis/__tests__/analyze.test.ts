import { describe, expect, it } from 'vitest';

import { CHECKS } from '../checks';
import { analyze, gradeFor, INSECURE_TRANSPORT_CAP, totalWeight } from '../analyze';
import { PERFECT_HEADERS, response } from './helpers';

describe('scoring invariants', () => {
  it('keeps the weights summing to 100', () => {
    // If this fails, every historical grade just changed meaning.
    expect(totalWeight()).toBe(100);
  });

  it('gives every check a unique id', () => {
    expect(new Set(CHECKS.map((c) => c.id)).size).toBe(CHECKS.length);
  });

  it('never produces a score outside 0..100', () => {
    expect(analyze(response({})).score).toBeGreaterThanOrEqual(0);
    expect(analyze(response(PERFECT_HEADERS)).score).toBeLessThanOrEqual(100);
  });

  it('awards points proportional to each check weight', () => {
    const report = analyze(response(PERFECT_HEADERS));
    for (const check of report.checks) {
      expect(check.points).toBeLessThanOrEqual(check.weight);
      expect(check.points).toBeCloseTo(check.ratio * check.weight, 1);
    }
  });
});

describe('gradeFor', () => {
  it.each([
    [100, 'A'],
    [90, 'A'],
    [89, 'B'],
    [80, 'B'],
    [70, 'C'],
    [60, 'D'],
    [50, 'E'],
    [49, 'F'],
    [0, 'F'],
  ])('maps %i to %s', (score, expected) => {
    expect(gradeFor(score)).toBe(expected);
  });
});

describe('analyze', () => {
  it('grades a fully hardened response an A', () => {
    const report = analyze(response(PERFECT_HEADERS));
    expect(report.grade).toBe('A');
    expect(report.score).toBe(100);
    expect(report.checks.every((check) => check.status === 'pass')).toBe(true);
  });

  it('grades a bare response an F', () => {
    const report = analyze(response({}));
    expect(report.grade).toBe('F');
    expect(report.checks.filter((check) => check.status === 'fail').length).toBeGreaterThanOrEqual(4);
  });

  it('drops exactly one check weight when an isolated header is removed', () => {
    const { 'x-content-type-options': _cto, ...withoutContentType } = PERFECT_HEADERS;
    const full = analyze(response(PERFECT_HEADERS)).score;
    expect(full - analyze(response(withoutContentType)).score).toBe(10);
  });

  it('costs more than its own weight to drop CSP, because frame-ancestors goes with it', () => {
    const { 'content-security-policy': _csp, ...withoutCsp } = PERFECT_HEADERS;
    const full = analyze(response(PERFECT_HEADERS)).score;
    const report = analyze(response(withoutCsp));

    // 30 points for the CSP check itself, plus the clickjacking check falling
    // back from `frame-ancestors` to the older X-Frame-Options.
    expect(full - report.score).toBe(32);
    expect(report.checks.find((check) => check.id === 'frame-ancestors')?.status).toBe('pass');
    expect(report.checks.find((check) => check.id === 'frame-ancestors')?.ratio).toBeLessThan(1);
  });

  it('weighs CSP above the cheaper headers', () => {
    const { 'content-security-policy': _csp, ...withoutCsp } = PERFECT_HEADERS;
    const { 'x-content-type-options': _cto, ...withoutContentType } = PERFECT_HEADERS;
    expect(analyze(response(withoutCsp)).score).toBeLessThan(analyze(response(withoutContentType)).score);
  });

  it('caps a plain-HTTP site regardless of its headers', () => {
    const report = analyze(response(PERFECT_HEADERS, 'http://example.com/'));
    expect(report.insecureTransport).toBe(true);
    expect(report.score).toBe(INSECURE_TRANSPORT_CAP);
    expect(report.grade).toBe('F');
  });

  it('does not flag HTTPS responses as insecure transport', () => {
    expect(analyze(response(PERFECT_HEADERS)).insecureTransport).toBe(false);
  });

  it('attaches the observed values to each check, or null when absent', () => {
    const report = analyze(response({ 'x-frame-options': 'DENY' }));
    const framing = report.checks.find((check) => check.id === 'frame-ancestors');
    const csp = report.checks.find((check) => check.id === 'csp');

    expect(framing?.observed).toEqual(['x-frame-options: DENY']);
    expect(csp?.observed).toBeNull();
  });

  it('carries the target and timing through untouched', () => {
    const dto = response(PERFECT_HEADERS);
    const report = analyze(dto);
    expect(report.target).toEqual(dto.target);
    expect(report.durationMs).toBe(dto.durationMs);
    expect(report.headers).toEqual(dto.headers);
  });

  it('is deterministic', () => {
    expect(analyze(response(PERFECT_HEADERS))).toEqual(analyze(response(PERFECT_HEADERS)));
  });

  it('gives every check a risk explanation and a fix', () => {
    for (const check of analyze(response({})).checks) {
      expect(check.risk.length).toBeGreaterThan(40);
      expect(check.fix.value.length).toBeGreaterThan(0);
      expect(check.docsUrl).toMatch(/^https:\/\//);
    }
  });
});
