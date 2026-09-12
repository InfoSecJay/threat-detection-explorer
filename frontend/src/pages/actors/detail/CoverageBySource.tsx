/** Coverage by source (#18): which vendor covers this actor's
 * techniques and which does not. Each card links to the catalog
 * filtered to that source and the actor's technique set. */

import { Link } from 'react-router-dom';
import { sourceTheme as sourceConfig, clipSm } from '../../../constants/style';
import { ALL_SOURCES } from '../../../constants/sources';
import { SectionHead } from './SectionHead';
import type { ActorDetail as ActorDetailData } from '../../../services/api';
import type { CoverageScopeState } from '../../../hooks/useCoverageScope';

export function CoverageBySource({ actor, scope }: { actor: ActorDetailData; scope?: CoverageScopeState }) {
  if (actor.technique_count === 0) return null;
  // "My stack" (#143): only the reader's sources are scored, so only
  // they are shown; the rest are named as hidden, not rendered as gaps.
  const shown = scope?.sources ? ALL_SOURCES.filter((s) => scope.sources!.includes(s)) : [...ALL_SOURCES];
  const hidden = ALL_SOURCES.length - shown.length;
  return (
    <section>
      <SectionHead
        title="Coverage by source"
        subtitle={`of ${actor.technique_count} techniques, per vendor · sources with no rules are the gap${
          hidden > 0 ? ` · ${hidden} source${hidden === 1 ? '' : 's'} outside your stack hidden` : ''
        }`}
      />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-1.5">
        {shown.map((src) => {
          const cov = actor.coverage_by_source?.[src];
          const covered = cov?.techniques_covered ?? 0;
          const pct = actor.technique_count ? Math.round((covered / actor.technique_count) * 100) : 0;
          const cfg = sourceConfig[src];
          return (
            <Link
              key={src}
              to={`/detections?sources=${src}&mitre_techniques=${actor.techniques.map((t) => t.technique_id).join(',')}`}
              className={`relative block border px-3 py-1.5 transition-colors ${
                covered > 0 ? 'bg-void-850 border-void-700 hover:border-matrix-500/50' : 'bg-void-900/60 border-void-800 hover:border-void-600'
              }`}
              style={clipSm}
              title={covered > 0 ? `${cfg?.name || src}: ${cov!.rule_count} rule(s) across ${covered} technique(s) -- open in catalog` : `${cfg?.name || src}: no rules for any of this actor's techniques`}
              data-testid={`cov-${src}`}
            >
              <div className={`absolute inset-y-0 left-0 ${cfg?.bg || 'bg-matrix-500/20'}`} style={{ width: `${pct}%` }} />
              <div className="relative flex items-center gap-2 text-xs">
                <span className={`w-2 h-2 rounded-full shrink-0 ${cfg?.dot || 'bg-gray-500'}`} />
                <span className={`font-mono uppercase tracking-wider shrink-0 ${covered > 0 ? cfg?.text || 'text-gray-300' : 'text-gray-600'}`}>
                  {cfg?.name || src}
                </span>
                <span className="flex-1" />
                <span className={`font-mono tabular-nums ${covered > 0 ? 'text-white' : 'text-gray-700'}`}>
                  {covered > 0 ? `${covered}/${actor.technique_count} · ${cov!.rule_count} rules` : 'gap'}
                </span>
              </div>
            </Link>
          );
        })}
      </div>
    </section>
  );
}
