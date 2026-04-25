/**
 * Trending lists at the bottom of the Intel page — MITRE techniques
 * and platforms most-touched in the selected window. Compact rows
 * with an inline coverage bar.
 */

import { Link } from 'react-router-dom';
import { useTrendingTechniques, useTrendingPlatforms } from '../../hooks/useTrending';
import { useMitre } from '../../contexts/MitreContext';
import { sourceTheme as sourceConfig } from '../../constants/style';
import type { ActivityFilters } from '../../services/api';
import { SkeletonRow, EmptyLabel } from './Section';

function TrendingRow({
  rank, primary, secondary, count, maxCount, sources, href, accent,
}: {
  rank: number;
  primary: string;
  secondary?: string;
  count: number;
  maxCount: number;
  sources: string[];
  href: string;
  accent: 'matrix' | 'cyan';
}) {
  const pct = (count / maxCount) * 100;
  const primaryCls = accent === 'matrix' ? 'text-matrix-500' : 'text-cyan-400';
  const barCls = accent === 'matrix' ? 'bg-matrix-500/10' : 'bg-cyan-500/10';
  return (
    <Link to={href} className="block group">
      <div className="relative bg-void-800/60 border border-void-700 hover:border-void-600 px-2.5 py-1.5 transition-colors">
        <div className={`absolute inset-y-0 left-0 ${barCls}`} style={{ width: `${pct}%` }} />
        <div className="relative flex items-center gap-2">
          <span className="text-[10px] font-mono text-gray-600 w-5 shrink-0">{rank}.</span>
          <span className={`font-mono text-xs ${primaryCls} shrink-0`}>{primary}</span>
          {secondary && <span className="text-xs text-gray-400 truncate min-w-0 flex-1">{secondary}</span>}
          {!secondary && <span className="flex-1" />}
          <div className="flex gap-0.5 shrink-0">
            {sources.slice(0, 4).map((src) => (
              <span key={src} className={`w-1.5 h-1.5 rounded-full ${sourceConfig[src]?.dot || 'bg-gray-500'}`} title={src} />
            ))}
          </div>
          <span className="text-xs font-mono text-white tabular-nums w-10 text-right shrink-0">{count}</span>
        </div>
      </div>
    </Link>
  );
}

export function TrendingTechniquesList({ days, filters }: { days: number; filters: ActivityFilters }) {
  const { data, isLoading, error } = useTrendingTechniques(days, 8, filters);
  const { getTechniqueName } = useMitre();

  if (isLoading) return <div className="space-y-1">{[...Array(8)].map((_, i) => <SkeletonRow key={i} />)}</div>;
  if (error || !data?.techniques?.length) return <EmptyLabel label="NO_TRENDING_DATA" />;

  const max = Math.max(...data.techniques.map((t) => t.count));
  return (
    <div className="space-y-1">
      {data.techniques.map((t, i) => (
        <TrendingRow
          key={t.technique_id}
          rank={i + 1}
          primary={t.technique_id}
          secondary={getTechniqueName(t.technique_id) || 'Unknown Technique'}
          count={t.count}
          maxCount={max}
          sources={t.sources}
          href={`/mitre/${t.technique_id}`}
          accent="matrix"
        />
      ))}
    </div>
  );
}

export function TrendingPlatformsList({
  days,
  filters,
}: {
  days: number;
  filters: Omit<ActivityFilters, 'platforms'>;
}) {
  const { data, isLoading, error } = useTrendingPlatforms(days, 8, filters);

  if (isLoading) return <div className="space-y-1">{[...Array(8)].map((_, i) => <SkeletonRow key={i} />)}</div>;
  if (error || !data?.platforms?.length) return <EmptyLabel label="NO_TRENDING_DATA" />;

  const max = Math.max(...data.platforms.map((p) => p.count));
  return (
    <div className="space-y-1">
      {data.platforms.map((p, i) => (
        <TrendingRow
          key={p.platform}
          rank={i + 1}
          primary={p.platform.replace(/_/g, ' ').toUpperCase()}
          count={p.count}
          maxCount={max}
          sources={p.sources}
          href={`/detections?platforms=${p.platform}`}
          accent="cyan"
        />
      ))}
    </div>
  );
}
