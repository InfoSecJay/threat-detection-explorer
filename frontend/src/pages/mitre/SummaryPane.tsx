/** Right pane when no technique is selected: headline coverage stats,
 * per-source coverage bars, most-covered techniques and top gaps. */

import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { sourceTheme as sourceColors, clipSm as clipCornerSm, clipMd as clipCornerMd } from '../../constants/style';
import type { TechniqueCoverage } from '../../services/api';
import type { CoverageData } from './types';

// ── Summary stat card ─────────────────────────────────────────────────
function StatCard({ label, value, sublabel, accent }: { label: string; value: string; sublabel?: string; accent?: string }) {
  return (
    <div className={`bg-void-850 border ${accent || 'border-matrix-500/30'} p-4`} style={clipCornerSm}>
      <div className="text-[10px] font-mono text-gray-500 mb-1 uppercase tracking-wider">{label}</div>
      <div className={`text-2xl font-display font-bold ${accent ? 'text-white' : 'text-matrix-500'}`}>{value}</div>
      {sublabel && <div className="text-xs text-gray-500 font-mono mt-0.5">{sublabel}</div>}
    </div>
  );
}

export function SummaryPane({ data }: { data: CoverageData }) {
  const { summary, sources, tactics } = data;

  // Top gaps (parent techniques with zero detections) — cap at 12
  const gaps = useMemo(() => {
    const out: TechniqueCoverage[] = [];
    for (const t of tactics) {
      for (const tech of t.techniques) {
        if (!tech.is_subtechnique && tech.total_detections === 0) out.push(tech);
      }
    }
    return out.slice(0, 12);
  }, [tactics]);

  // Top covered (parent techniques, highest detection count)
  const topCovered = useMemo(() => {
    const out: TechniqueCoverage[] = [];
    for (const t of tactics) {
      for (const tech of t.techniques) {
        if (!tech.is_subtechnique && tech.total_detections > 0) out.push(tech);
      }
    }
    return out.sort((a, b) => b.total_detections - a.total_detections).slice(0, 10);
  }, [tactics]);

  return (
    <div className="space-y-4">
      {/* Headline stats */}
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        <StatCard
          label="Overall Coverage"
          value={`${summary.overall_coverage_percent}%`}
          sublabel={`${summary.techniques_with_any_coverage} / ${summary.total_techniques} techniques`}
        />
        <StatCard
          label="Techniques"
          value={String(summary.total_techniques)}
          sublabel={`${summary.total_tactics} tactics`}
          accent="border-void-700"
        />
        <StatCard
          label="Gaps"
          value={String(summary.total_techniques - summary.techniques_with_any_coverage)}
          sublabel="uncovered techniques"
          accent="border-breach-500/30"
        />
      </div>

      {/* Per-source coverage */}
      <div className="bg-void-850 border border-void-700 p-4" style={clipCornerMd}>
        <div className="flex items-center justify-between mb-3">
          <h3 className="font-display text-sm text-white uppercase tracking-wider">Coverage by Source</h3>
          <span className="text-[10px] font-mono text-gray-500">
            of {summary.total_techniques} techniques
          </span>
        </div>
        <div className="space-y-2">
          {sources.map((src) => {
            const sc = summary.source_coverage[src];
            const colors = sourceColors[src] || sourceColors.sigma;
            return (
              <div key={src} className="flex items-center gap-3">
                <div className="flex items-center gap-2 w-32 flex-shrink-0">
                  <span className={`w-2 h-2 ${colors.dot}`} />
                  <span className="text-xs text-gray-400">{sourceColors[src]?.name || src}</span>
                </div>
                <div className="flex-1 h-2 bg-void-900 rounded-sm overflow-hidden">
                  <div
                    className={`h-full ${colors.dot} transition-all`}
                    style={{ width: `${sc.coverage_percent}%` }}
                  />
                </div>
                <div className="flex items-baseline gap-2 w-24 justify-end">
                  <span className={`text-sm font-mono ${colors.text}`}>{sc.coverage_percent}%</span>
                  <span className="text-[10px] font-mono text-gray-500">({sc.covered_techniques})</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Top covered + gaps, side by side */}
      <div className="grid md:grid-cols-2 gap-4">
        <div className="bg-void-850 border border-void-700 p-4" style={clipCornerMd}>
          <h3 className="font-display text-sm text-white uppercase tracking-wider mb-3">Most-Covered</h3>
          <div className="space-y-1">
            {topCovered.map((t) => (
              <Link
                key={t.id}
                to={`/mitre/${t.id}`}
                className="flex items-center gap-2 px-2 py-1 text-xs hover:bg-void-800 transition-colors rounded-sm"
              >
                <span className="font-mono text-matrix-500 w-14">{t.id}</span>
                <span className="text-gray-300 flex-1 truncate">{t.name}</span>
                <span className="font-mono text-white">{t.total_detections}</span>
              </Link>
            ))}
          </div>
        </div>

        <div className="bg-void-850 border border-breach-500/20 p-4" style={clipCornerMd}>
          <h3 className="font-display text-sm text-breach-400 uppercase tracking-wider mb-3">Top Gaps</h3>
          {gaps.length === 0 ? (
            <div className="text-center py-8">
              <div className="text-matrix-500 text-3xl mb-2">✓</div>
              <p className="text-gray-400 font-display text-sm">Full coverage — no gaps.</p>
            </div>
          ) : (
            <div className="space-y-1">
              {gaps.map((t) => (
                <Link
                  key={t.id}
                  to={`/mitre/${t.id}`}
                  className="flex items-center gap-2 px-2 py-1 text-xs hover:bg-void-800 transition-colors rounded-sm"
                >
                  <span className="font-mono text-gray-500 w-14">{t.id}</span>
                  <span className="text-gray-500 flex-1 truncate">{t.name}</span>
                </Link>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
