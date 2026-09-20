// This edge function exists only to carry the `rateLimit` config below.
//
// The scanner's API is a Go function, and Netlify's rate limiting cannot reach
// it any other way: limits for functions are declared in an exported `config`
// object, which is a JS/TS-only mechanism, and a `[redirects.rate_limit]` in
// netlify.toml is documented as not applying to functions (it was tried, and
// 25 requests in a burst all reached the function untouched).
//
// An edge function runs ahead of the rewrite, so the limit is counted at the
// edge -- across every warm instance -- before the Go function is invoked.
import type { Config, Context } from '@netlify/edge-functions';

export default async (_request: Request, context: Context) => {
  // No logic of its own: hand the request straight on to the rewrite that
  // sends /api/* to the Go function.
  return context.next();
};

export const config: Config = {
  path: '/api/*',
  rateLimit: {
    // Deliberately above the app's own 10/60s limiter. That one answers first,
    // with a typed JSON body and Retry-After that the frontend knows how to
    // render; this is the hard ceiling for a burst that spreads across
    // instances, where an in-process counter multiplies by instance count.
    windowLimit: 20,
    windowSize: 60, // maximum allowed: 180
    aggregateBy: ['ip', 'domain'],
  },
};
