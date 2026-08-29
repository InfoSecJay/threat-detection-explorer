/**
 * Gap spotlight: the actors with the most uncovered, distinctive TTPs.
 * Same ranking as /actors (weighted_gap desc) -- this is the top of
 * that list, not a different metric.
 */

import { Link } from 'react-router-dom';
import { useActorsQuery } from '../../hooks/useActors';
import { clipSm } from '../../constants/style';
import { countryFlag } from '../../utils/actorDisplay';
import { SkeletonRow, EmptyLabel } from '../intel/Section';

export function GapSpotlight() {
  const { data, isLoading, error } = useActorsQuery({
    kind: 'groups', sort: 'weighted_gap', order: 'desc', page: 1, per_page: 6,
  });

  if (isLoading) return <div className="space-y-1">{[...Array(6)].map((_, i) => <SkeletonRow key={i} height="h-10" />)}</div>;
  if (error || !data?.items?.length) return <EmptyLabel label="ACTOR_RANKING_UNAVAILABLE" />;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
      {data.items.map((a, i) => {
        const pct = a.weighted_coverage === null ? null : Math.round(a.weighted_coverage * 100);
        return (
          <Link
            key={a.id}
            to={`/actors/${a.id}`}
            className="group relative bg-void-850 border border-void-700 hover:border-breach-500/40 px-3 py-2.5 transition-colors"
            style={clipSm}
            data-testid={`gap-${a.id}`}
          >
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono text-gray-600 w-4 shrink-0">{i + 1}</span>
              <span className="text-sm font-display font-semibold text-white truncate min-w-0 flex-1 group-hover:text-breach-300 transition-colors">
                {a.origin_country ? `${countryFlag(a.origin_country)} ` : ''}{a.name}
              </span>
              <span className="text-[10px] font-mono text-gray-600">{a.id}</span>
            </div>
            <div className="mt-1.5 flex items-center gap-3 text-[11px] font-mono">
              <span className="text-breach-400 tabular-nums">{a.gap_count} <span className="text-gray-600">/ {a.technique_count} uncovered</span></span>
              <span className="text-gray-500 tabular-nums" title="Distinctiveness-weighted coverage">
                {pct === null ? '—' : `${pct}%`} <span className="text-gray-600">weighted</span>
              </span>
            </div>
            <div className="mt-1.5 h-0.5 bg-void-800">
              <div className="h-full bg-breach-500/60" style={{ width: `${a.technique_count ? Math.round((a.gap_count / a.technique_count) * 100) : 0}%` }} />
            </div>
          </Link>
        );
      })}
    </div>
  );
}
