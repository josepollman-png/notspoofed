import type { SpfEvaluation } from './spf/evaluate.js';
import { LOOKUP_LIMIT } from './spf/evaluate.js';

/** The SPF part of the one-line summary at the top of a report. */
export function spfSummary(spf: SpfEvaluation): string {
  if (spf.lookupError) return 'could not be checked';
  if (!spf.found) return 'not published';
  if (spf.permerror) {
    // centos.org: "permerror (1 lookups counted)".
    return `permerror (${spf.lookupCount} ${spf.lookupCount === 1 ? 'lookup' : 'lookups'} counted)`;
  }
  return `${spf.lookupCount}/${LOOKUP_LIMIT} lookups`;
}
