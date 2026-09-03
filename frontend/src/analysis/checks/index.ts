import type { CheckDefinition } from '../registry';
import { contentTypeOptionsCheck } from './contentType';
import { cspCheck } from './csp';
import { informationDisclosureCheck } from './disclosure';
import { framingCheck } from './framing';
import { hstsCheck } from './hsts';
import { permissionsPolicyCheck } from './permissions';
import { referrerPolicyCheck } from './referrer';

/**
 * Ordered worst-consequence-first, which is also the order the report renders.
 * Weights sum to 100 -- `analyze.test.ts` asserts it, so adding a check without
 * rebalancing fails the build rather than silently changing every grade.
 */
export const CHECKS: readonly CheckDefinition[] = [
  cspCheck,
  hstsCheck,
  framingCheck,
  contentTypeOptionsCheck,
  referrerPolicyCheck,
  permissionsPolicyCheck,
  informationDisclosureCheck,
];
