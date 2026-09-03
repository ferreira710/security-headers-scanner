import { describe, expect, it } from 'vitest';

import { contentTypeOptionsCheck } from '../checks/contentType';
import { cspCheck } from '../checks/csp';
import { informationDisclosureCheck } from '../checks/disclosure';
import { framingCheck } from '../checks/framing';
import { hstsCheck } from '../checks/hsts';
import { permissionsPolicyCheck } from '../checks/permissions';
import { referrerPolicyCheck } from '../checks/referrer';
import { context } from './helpers';

describe('Content-Security-Policy', () => {
  it('fails when absent', () => {
    const outcome = cspCheck.run(context({}));
    expect(outcome.status).toBe('fail');
    expect(outcome.ratio).toBe(0);
  });

  it('passes a nonce-based policy that closes base-uri and object-src', () => {
    const outcome = cspCheck.run(
      context({
        'content-security-policy':
          "default-src 'self'; script-src 'self' 'nonce-r4nd0m'; object-src 'none'; base-uri 'self'",
      }),
    );
    expect(outcome.status).toBe('pass');
    expect(outcome.ratio).toBe(1);
    expect(outcome.findings).toEqual([]);
  });

  it("penalises 'unsafe-inline' heavily when no nonce or hash is present", () => {
    const strict = cspCheck.run(
      context({ 'content-security-policy': "default-src 'self'; object-src 'none'; base-uri 'self'" }),
    );
    const loose = cspCheck.run(
      context({
        'content-security-policy': "default-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'",
      }),
    );
    expect(loose.ratio).toBeLessThan(strict.ratio);
    expect(loose.status).toBe('warn');
    expect(loose.findings.join(' ')).toContain("'unsafe-inline'");
  });

  it("does not penalise 'unsafe-inline' alongside a nonce, since browsers ignore it there", () => {
    const outcome = cspCheck.run(
      context({
        'content-security-policy':
          "default-src 'self'; script-src 'nonce-abc' 'unsafe-inline'; object-src 'none'; base-uri 'self'",
      }),
    );
    expect(outcome.ratio).toBe(1);
  });

  it('flags a wildcard script source', () => {
    const outcome = cspCheck.run(
      context({ 'content-security-policy': "default-src 'self'; script-src *; object-src 'none'; base-uri 'self'" }),
    );
    expect(outcome.findings.join(' ')).toContain('curinga');
    expect(outcome.ratio).toBeLessThan(0.8);
  });

  it('flags a missing base-uri even when default-src is strict', () => {
    const outcome = cspCheck.run(
      context({ 'content-security-policy': "default-src 'none'; script-src 'self'" }),
    );
    expect(outcome.findings.join(' ')).toContain('base-uri');
  });

  it('treats a policy with no script restriction as barely better than nothing', () => {
    const outcome = cspCheck.run(context({ 'content-security-policy': "img-src 'self'" }));
    expect(outcome.status).toBe('fail');
    expect(outcome.ratio).toBeLessThan(0.35);
  });

  it('gives partial credit for report-only mode', () => {
    const outcome = cspCheck.run(
      context({ 'content-security-policy-report-only': "default-src 'self'" }),
    );
    expect(outcome.status).toBe('warn');
    expect(outcome.ratio).toBeGreaterThan(0);
    expect(outcome.summary).toContain('report-only');
  });

  it('scores duplicate policies by the strictest one, since browsers intersect them', () => {
    const outcome = cspCheck.run(
      context({
        'content-security-policy': [
          "script-src 'unsafe-inline' *",
          "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
        ],
      }),
    );
    expect(outcome.ratio).toBe(1);
    expect(outcome.findings.join(' ')).toContain('interseção');
  });
});

describe('Strict-Transport-Security', () => {
  it('fails when absent', () => {
    expect(hstsCheck.run(context({})).status).toBe('fail');
  });

  it('passes a one-year policy covering subdomains', () => {
    const outcome = hstsCheck.run(
      context({ 'strict-transport-security': 'max-age=31536000; includeSubDomains; preload' }),
    );
    expect(outcome.status).toBe('pass');
    expect(outcome.ratio).toBe(1);
  });

  it('warns when includeSubDomains is missing', () => {
    const outcome = hstsCheck.run(context({ 'strict-transport-security': 'max-age=31536000' }));
    expect(outcome.status).toBe('warn');
    expect(outcome.findings.join(' ')).toContain('includeSubDomains');
  });

  it('scores a short max-age below a long one', () => {
    const short = hstsCheck.run(context({ 'strict-transport-security': 'max-age=300' }));
    const long = hstsCheck.run(context({ 'strict-transport-security': 'max-age=31536000' }));
    expect(short.ratio).toBeLessThan(long.ratio);
  });

  it('treats a header without max-age as ineffective', () => {
    const outcome = hstsCheck.run(context({ 'strict-transport-security': 'includeSubDomains' }));
    expect(outcome.status).toBe('fail');
    expect(outcome.summary).toContain('max-age');
  });

  it('fails over plain HTTP no matter what the header says', () => {
    const outcome = hstsCheck.run(
      context({ 'strict-transport-security': 'max-age=31536000; includeSubDomains' }, 'http://example.com/'),
    );
    expect(outcome.status).toBe('fail');
    expect(outcome.ratio).toBe(0);
  });
});

describe('clickjacking protection', () => {
  it('fails when neither header is present', () => {
    const outcome = framingCheck.run(context({}));
    expect(outcome.status).toBe('fail');
    expect(outcome.findings.join(' ')).toContain('Clickjacking');
  });

  it.each(['DENY', 'SAMEORIGIN', 'sameorigin'])('accepts X-Frame-Options: %s', (value) => {
    expect(framingCheck.run(context({ 'x-frame-options': value })).status).toBe('pass');
  });

  it('prefers frame-ancestors over X-Frame-Options and scores it higher', () => {
    const modern = framingCheck.run(context({ 'content-security-policy': "frame-ancestors 'none'" }));
    const legacy = framingCheck.run(context({ 'x-frame-options': 'DENY' }));
    expect(modern.ratio).toBeGreaterThan(legacy.ratio);
  });

  it('rejects a wildcard frame-ancestors', () => {
    const outcome = framingCheck.run(context({ 'content-security-policy': 'frame-ancestors *' }));
    expect(outcome.status).toBe('fail');
  });

  it('treats the removed ALLOW-FROM directive as no protection', () => {
    const outcome = framingCheck.run(context({ 'x-frame-options': 'ALLOW-FROM https://a.example' }));
    expect(outcome.status).toBe('fail');
    expect(outcome.findings.join(' ')).toContain('ALLOW-FROM');
  });

  it('rejects a value the browser would not understand', () => {
    expect(framingCheck.run(context({ 'x-frame-options': 'ALLOWALL' })).status).toBe('fail');
  });
});

describe('X-Content-Type-Options', () => {
  it('fails when absent and names the MIME sniffing risk', () => {
    const outcome = contentTypeOptionsCheck.run(context({}));
    expect(outcome.status).toBe('fail');
    expect(outcome.findings.join(' ')).toContain('MIME');
  });

  it('passes on nosniff regardless of case', () => {
    expect(contentTypeOptionsCheck.run(context({ 'x-content-type-options': 'NoSniff' })).ratio).toBe(1);
  });

  it('fails on any other value', () => {
    expect(contentTypeOptionsCheck.run(context({ 'x-content-type-options': 'sniff' })).status).toBe('fail');
  });
});

describe('Referrer-Policy', () => {
  it('warns rather than fails when absent, because the browser default is sane', () => {
    const outcome = referrerPolicyCheck.run(context({}));
    expect(outcome.status).toBe('warn');
    expect(outcome.ratio).toBeGreaterThan(0);
  });

  it.each(['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'])(
    'accepts the strict policy %s',
    (value) => {
      expect(referrerPolicyCheck.run(context({ 'referrer-policy': value })).status).toBe('pass');
    },
  );

  it('fails unsafe-url and explains what leaks', () => {
    const outcome = referrerPolicyCheck.run(context({ 'referrer-policy': 'unsafe-url' }));
    expect(outcome.status).toBe('fail');
    expect(outcome.ratio).toBe(0);
    expect(outcome.findings.join(' ')).toContain('reset de senha');
  });

  it('warns on origin-only policies', () => {
    expect(referrerPolicyCheck.run(context({ 'referrer-policy': 'origin' })).status).toBe('warn');
  });

  it('applies the last recognised token, like the browser does', () => {
    const outcome = referrerPolicyCheck.run(context({ 'referrer-policy': 'unsafe-url, no-referrer' }));
    expect(outcome.status).toBe('pass');
  });

  it('skips unknown tokens instead of letting them override a valid one', () => {
    const outcome = referrerPolicyCheck.run(context({ 'referrer-policy': 'no-referrer, made-up-policy' }));
    expect(outcome.status).toBe('pass');
  });
});

describe('Permissions-Policy', () => {
  it('warns when absent without calling it a vulnerability', () => {
    const outcome = permissionsPolicyCheck.run(context({}));
    expect(outcome.status).toBe('warn');
    expect(outcome.ratio).toBe(0);
  });

  it('passes when every sensitive feature is denied', () => {
    const outcome = permissionsPolicyCheck.run(
      context({ 'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()' }),
    );
    expect(outcome.status).toBe('pass');
  });

  it('lists the features left unrestricted', () => {
    const outcome = permissionsPolicyCheck.run(context({ 'permissions-policy': 'camera=()' }));
    expect(outcome.status).toBe('warn');
    expect(outcome.findings.join(' ')).toContain('microphone');
  });

  it('penalises a feature opened to every origin', () => {
    const locked = permissionsPolicyCheck.run(context({ 'permissions-policy': 'camera=(), microphone=()' }));
    const open = permissionsPolicyCheck.run(context({ 'permissions-policy': 'camera=*, microphone=()' }));
    expect(open.ratio).toBeLessThan(locked.ratio);
  });

  it('notes that the legacy Feature-Policy header is ignored today', () => {
    const outcome = permissionsPolicyCheck.run(context({ 'feature-policy': "camera 'none'" }));
    expect(outcome.findings.join(' ')).toContain('Feature-Policy');
  });
});

describe('information disclosure', () => {
  it('passes a response that names nothing', () => {
    expect(informationDisclosureCheck.run(context({})).status).toBe('pass');
  });

  it('penalises an exact version more than a bare product name', () => {
    const bare = informationDisclosureCheck.run(context({ server: 'nginx' }));
    const versioned = informationDisclosureCheck.run(context({ server: 'nginx/1.18.0' }));
    expect(versioned.ratio).toBeLessThan(bare.ratio);
    expect(versioned.findings.join(' ')).toContain('CVE');
  });

  it('flags a non-zero X-XSS-Protection as a dead header', () => {
    const outcome = informationDisclosureCheck.run(context({ 'x-xss-protection': '1; mode=block' }));
    expect(outcome.findings.join(' ')).toContain('X-XSS-Protection');
  });

  it('accepts X-XSS-Protection: 0, which is the current recommendation', () => {
    expect(informationDisclosureCheck.run(context({ 'x-xss-protection': '0' })).status).toBe('pass');
  });
});
