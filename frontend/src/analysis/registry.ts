import type { CheckId, CheckOutcome } from '../types';
import type { ScanContext } from './headers';

/**
 * A check knows how to grade one concern and how to explain it. Weights sum to
 * 100 across the registry; see `checks/index.ts`.
 */
export interface CheckDefinition {
  readonly id: CheckId;
  readonly label: string;
  readonly headerName: string;
  /** Header names whose observed values belong on this card. */
  readonly observedHeaders: readonly string[];
  readonly weight: number;
  /** What an attacker does when this is missing -- the attack, not a definition. */
  readonly risk: string;
  readonly docsUrl: string;
  run(context: ScanContext): CheckOutcome;
}
