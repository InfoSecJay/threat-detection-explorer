/**
 * Trending lists at the bottom of the Intel page — MITRE techniques
 * and platforms most-touched in the selected window. Compact rows
 * with an inline coverage bar.
 */

import { Link } from 'react-router-dom';
import {
  useTrendingTechniques,
  useTrendingPlatforms,
  useTrendingDataSources,
  useTechniqueDeltas,
} from '../../hooks/useTrending';
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
  accent: 'matrix' | 'cyan' | 'amber';
}) {
  const pct = (count / maxCount) * 100;
  const primaryCls =
    accent === 'matrix' ? 'text-matrix-500' : accent === 'cyan' ? 'text-cyan-400' : 'text-amber-300';
  const barCls =
    accent === 'matrix' ? 'bg-matrix-500/10' : accent === 'cyan' ? 'bg-cyan-500/10' : 'bg-amber-500/10';
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

/** Emerging data sources (#17): where NEW detection content is being
 * written, by canonical data source. Keyed on created date upstream so
 * a hygiene pass over old rules does not read as a trend. */
export function TrendingDataSourcesList({
  days,
  filters,
}: {
  days: number;
  filters: Omit<ActivityFilters, 'platforms'>;
}) {
  const { data, isLoading, error } = useTrendingDataSources(days, 8, filters);

  if (isLoading) return <div className="space-y-1">{[...Array(8)].map((_, i) => <SkeletonRow key={i} />)}</div>;
  if (error || !data?.data_sources?.length) return <EmptyLabel label="NO_NEW_RULES_IN_WINDOW" />;

  const max = Math.max(...data.data_sources.map((d) => d.count));
  return (
    <div className="space-y-1">
      {data.data_sources.map((d, i) => (
        <TrendingRow
          key={d.data_source}
          rank={i + 1}
          primary={d.data_source}
          count={d.count}
          maxCount={max}
          sources={d.sources}
          href={`/detections?data_sources_normalized=${encodeURIComponent(d.data_source)}`}
          accent="cyan"
        />
      ))}
    </div>
  );
}

/** Technique momentum (#19): which ATT&CK techniques gained or lost
 * rules catalog-wide between coverage snapshots. Not windowed by the
 * page toggle -- snapshots are daily, so this is always "vs 7 days ago". */
export function TechniqueMomentumList() {
  const { data, isLoading, error } = useTechniqueDeltas(7, 6);
  const { getTechniqueName } = useMitre();

  if (isLoading) return <div className="space-y-1">{[...Array(6)].map((_, i) => <SkeletonRow key={i} />)}</div>;
  if (error || !data) return <EmptyLabel label="NO_MOMENTUM_DATA" />;
  if (data.method !== 'snapshot') {
    return <EmptyLabel label={data.method === 'no_data' ? 'NO_SNAPSHOTS_YET' : 'NEEDS_7_DAYS_OF_SNAPSHOTS'} />;
  }
  const rows = [...data.gainers, ...data.losers];
  if (!rows.length) return <EmptyLabel label="NO_CHANGE_THIS_WEEK" />;
  const max = Math.max(...rows.map((r) => Math.abs(r.delta)));

  return (
    <div className="space-y-1">
      {rows.map((r) => {
        const up = r.delta > 0;
        const changed = up ? r.sources_added : r.sources_removed;
        return (
          <Link key={r.technique_id} to={`/mitre/${r.technique_id}`} className="block group">
            <div className="relative bg-void-800/60 border border-void-700 hover:border-void-600 px-2.5 py-1.5 transition-colors">
              <div
                className={`absolute inset-y-0 left-0 ${up ? 'bg-pulse-500/10' : 'bg-breach-500/10'}`}
                style={{ width: `${(Math.abs(r.delta) / max) * 100}%` }}
              />
              <div className="relative flex items-center gap-2">
                <span className={`font-mono text-xs shrink-0 ${up ? 'text-pulse-400' : 'text-breach-400'}`}>{r.technique_id}</span>
                <span className="text-xs text-gray-400 truncate min-w-0 flex-1">{getTechniqueName(r.technique_id) || 'Unknown Technique'}</span>
                {changed.length > 0 && (
                  <span
                    className="text-[9px] font-mono text-gray-600 uppercase shrink-0"
                    title={`${up ? 'newly covered by' : 'dropped by'}: ${changed.join(', ')}`}
                  >
                    {up ? '+' : '-'}{changed.length} src
                  </span>
                )}
                <span className={`text-xs font-mono tabular-nums w-10 text-right shrink-0 ${up ? 'text-pulse-400' : 'text-breach-400'}`}>
                  {up ? '+' : ''}{r.delta}
                </span>
              </div>
            </div>
          </Link>
        );
      })}
      <div className="text-[9px] font-mono text-gray-600 text-right pt-1" title="technique x source rule counts from the nightly coverage snapshot">
        vs {data.baseline_date}
      </div>
    </div>
  );
}
