/**
 * Detection Pulse banner — total created + modified in window, plus a
 * per-source bar of *new* rules only. The split matters: a week with
 * huge `modified` and near-zero `created` is a hygiene pass, not new
 * coverage, and the DE should be able to tell at a glance.
 */

import { useTrendingSummary } from '../../hooks/useTrending';
import { sourceTheme as sourceConfig, clipMd } from '../../constants/style';
import { SkeletonRow } from './Section';

export function PulseBanner({ days }: { days: number }) {
  const { data, isLoading, error, refetch } = useTrendingSummary(days);

  if (isLoading) return <SkeletonRow height="h-20" />;
  if (!data) {
    // A failed /trending/summary used to make the banner vanish with
    // no explanation (#51).
    return (
      <div
        className="border border-breach-500/30 bg-void-850 px-5 py-3 flex items-center justify-between gap-4 flex-wrap"
        style={clipMd}
        role="alert"
      >
        <div className="text-xs font-mono text-gray-400">
          <span className="text-breach-400 uppercase tracking-[0.2em] mr-2">Detection Pulse</span>
          unavailable{error ? `: ${error.message}` : ''}
        </div>
        <button
          onClick={() => refetch()}
          className="text-[10px] font-mono uppercase tracking-wider text-breach-400 hover:text-breach-300"
        >
          [ retry ]
        </button>
      </div>
    );
  }

  // Sort by (created desc, modified desc) so "who is publishing the
  // most new content" wins the leftmost bar. Bars are scaled to the
  // largest CREATED count so hygiene-heavy repos don't visually
  // dominate.
  const entries = Object.entries(data.by_source).sort(
    ([, a], [, b]) => b.created - a.created || b.modified - a.modified,
  );
  const activeSources = entries.length;
  const maxCreated = entries.reduce((m, [, v]) => Math.max(m, v.created), 1);

  return (
    <div
      className="bg-gradient-to-r from-matrix-500/10 via-cyan-500/5 to-transparent border border-matrix-500/30 px-5 py-4"
      style={clipMd}
    >
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <div className="text-[10px] font-mono text-matrix-400 uppercase tracking-[0.2em] mb-1">
            Detection Pulse
          </div>
          <div className="flex items-baseline gap-3 flex-wrap">
            <span className="text-3xl font-display font-bold text-matrix-400 tabular-nums">
              {data.total_created.toLocaleString()}
            </span>
            <span className="text-sm text-gray-400 font-mono">new</span>
            <span className="text-xs text-gray-600 font-mono">·</span>
            <span className="text-2xl font-display font-bold text-white tabular-nums">
              {data.total_modified.toLocaleString()}
            </span>
            <span className="text-sm text-gray-400 font-mono">modified</span>
            <span className="text-xs text-gray-600 font-mono">·</span>
            <span className="text-sm text-cyan-400 font-mono">{activeSources} active repos</span>
          </div>
        </div>

        <div className="flex gap-1.5 items-end flex-wrap">
          {entries.map(([src, counts]) => {
            const cfg = sourceConfig[src] || sourceConfig.sigma;
            const pct = Math.max(10, Math.round((counts.created / maxCreated) * 100));
            return (
              <div
                key={src}
                className="flex flex-col items-center gap-0.5"
                title={`${cfg.name}: ${counts.created} new, ${counts.modified} modified`}
              >
                <div className={`w-6 ${cfg.dot} transition-all`} style={{ height: `${pct * 0.4}px` }} />
                <div className="text-[9px] font-mono text-gray-500 uppercase">{src.slice(0, 3)}</div>
                <div className={`text-[10px] font-mono ${cfg.text} tabular-nums`}>{counts.created}</div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
