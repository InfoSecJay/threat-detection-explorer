/** One vocabulary for the three actor/software rule-matching tiers,
 * shared by the hero stat, the toggle and its tooltips (DX-08). Wire
 * values stay exact/coverage/mention for URL and API stability
 * (issue #34); only the display names and definitions changed. */

import type { ActorMatchMode } from '../../../services/api';

export const MATCH_MODE_LABEL: Record<ActorMatchMode, string> = {
  exact: 'Named',
  coverage: 'Technique overlap',
  mention: 'Mentions',
};

export const MATCH_MODE_DEFINITION: Record<ActorMatchMode, string> = {
  exact: 'Rules built FOR this actor: an ATT&CK ID tag, an analytic story named after it, or its name in the rule title.',
  coverage: 'Rules tagged with any technique this actor is known to use, regardless of whether the rule mentions the actor.',
  mention: 'Rules that only cite the actor -- name/alias in the description, tags, use cases, or a reference URL (excludes Named rules).',
};
