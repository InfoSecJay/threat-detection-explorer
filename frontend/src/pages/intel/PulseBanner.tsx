/**
 * Detection Pulse banner — total rule updates in window + per-source bars.
 * Owns its own data via useTrendingSummary.
 */

import { useTrendingSummary } from '../../hooks/useTrending';
import { sourceTheme as sourceConfig, clipMd } from '../../constants/style';
import { SkeletonRow } from './Section';

export function PulseBanner({ days }: { days: number }) {
  const { data, isLoading } = useTrendingSummary(days);

  if (isLoading) return <SkeletonRow height="h-20" />;
  if (!data) return null;

  const entries = Object.entries(data.by_source).sort(([, a], [, b]) => b - a);
  const activeSources = entries.length;

  return (
    <div
      className="bg-gradient-to-r from-matrix-500/10 via-cyan-500/5 to-transparent border border-matrix-500/30 px-5 py-4"
      style={clipMd}
    >
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <div className="text-[10px] font-mono text-matrix-400 uppercase tracking-[0.2em] mb-1">
            Detection Pulse · last {days}d
          </div>
          <div className="flex items-baseline gap-3 flex-wrap">
            <span className="text-3xl font-display font-bold text-white tabular-nums">
              {data.total_modified.toLocaleString()}
            </span>
            <span className="text-sm text-gray-400 font-mono">rule updates</span>
            <span className="text-xs text-gray-600 font-mono">·</span>
            <span className="text-sm text-matrix-400 font-mono">{activeSources} active repos</span>
          </div>
        </div>

        <div className="flex gap-1.5 items-end flex-wrap">
          {entries.map(([src, count]) => {
            const cfg = sourceConfig[src] || sourceConfig.sigma;
            const max = entries[0]?.[1] || 1;
            const pct = Math.max(15, Math.round((count / max) * 100));
            return (
              <div key={src} className="flex flex-col items-center gap-0.5" title={`${cfg.name}: ${count}`}>
                <div className={`w-6 ${cfg.dot} transition-all`} style={{ height: `${pct * 0.4}px` }} />
                <div className="text-[9px] font-mono text-gray-500 uppercase">{src.slice(0, 3)}</div>
                <div className={`text-[10px] font-mono ${cfg.text} tabular-nums`}>{count}</div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
