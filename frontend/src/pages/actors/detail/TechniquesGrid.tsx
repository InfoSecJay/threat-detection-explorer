/** Techniques the actor is known to use, with our coverage indicator
 * per technique; each links into the MITRE browser. */

import { Link } from 'react-router-dom';
import { clipSm } from '../../../constants/style';
import { SectionHead } from './SectionHead';
import type { ActorDetail as ActorDetailData } from '../../../services/api';

export function TechniquesGrid({ actor }: { actor: ActorDetailData }) {
  const isGroup = actor.kind === 'group';
  return (
  <section>
    <SectionHead
      title="Techniques used"
      subtitle={`${actor.covered_technique_count} of ${actor.technique_count} have rules in our catalog · click to open in mitre browser`}
    />
    {actor.techniques.length === 0 ? (
      <div className="text-center py-6 text-gray-500 font-mono text-xs">
        No techniques associated in MITRE for this {isGroup ? 'actor' : 'software'}.
      </div>
    ) : (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
        {actor.techniques.map((t) => (
          <Link
            key={t.technique_id}
            to={`/mitre/${t.technique_id}`}
            className={`group block border px-3 py-2 transition-colors ${
              t.has_rules
                ? 'bg-void-850 border-void-700 hover:border-matrix-500/50'
                : 'bg-void-900/60 border-void-800 hover:border-void-600'
            }`}
            style={clipSm}
            title={t.has_rules ? `${t.rule_count} rule(s) in our catalog` : 'Gap: no rules in our catalog for this technique'}
          >
            <div className="flex items-center gap-2">
              <span
                className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                  t.has_rules ? 'bg-matrix-500' : 'bg-gray-700'
                }`}
                aria-hidden="true"
              />
              <span
                className={`text-xs font-mono tabular-nums shrink-0 ${
                  t.has_rules ? 'text-matrix-500' : 'text-gray-600'
                }`}
              >
                {t.technique_id}
              </span>
              <span
                className={`text-xs truncate flex-1 min-w-0 ${
                  t.has_rules ? 'text-gray-300 group-hover:text-white' : 'text-gray-500 italic'
                }`}
              >
                {t.technique_name || 'Unknown technique'}
              </span>
              <span
                className={`text-xs font-mono tabular-nums shrink-0 ${
                  t.has_rules ? 'text-white' : 'text-gray-700'
                }`}
              >
                {t.has_rules ? t.rule_count : 'gap'}
              </span>
            </div>
          </Link>
        ))}
      </div>
    )}
  </section>
  );
}
