/**
 * Notable New Rules — richer cards (source, severity, platforms, age)
 * for a small set of recently created/modified rules. Dedupes across
 * the two date fields and shows the 6 newest unique entries.
 */

import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useRecentRules } from '../../hooks/useTrending';
import { sourceTheme as sourceConfig, clipSm } from '../../constants/style';
import type { ActivityFilters, RecentRuleItem } from '../../services/api';
import { SkeletonRow, EmptyLabel } from './Section';
import { severityColor, formatRelDate } from './lib';

function NotableRuleCard({ rule }: { rule: RecentRuleItem }) {
  const cfg = sourceConfig[rule.source];
  const sev = severityColor[rule.severity] || severityColor.unknown;

  return (
    <Link
      to={`/detections/${rule.id}`}
      className="group block bg-void-850 border border-void-700 hover:border-matrix-500/40 p-3 transition-colors"
      style={clipSm}
    >
      <div className="flex items-center gap-2 mb-1.5">
        <span className={`text-[9px] font-mono uppercase tracking-wider px-1.5 py-0.5 border ${cfg?.bg || ''} ${cfg?.text || ''} ${cfg?.border || ''}`}>
          {cfg?.name || rule.source}
        </span>
        <span className={`text-[9px] font-mono uppercase tracking-wider px-1.5 py-0.5 border ${sev}`}>
          {rule.severity.slice(0, 4)}
        </span>
        <span className="text-[10px] font-mono text-gray-600 ml-auto">
          {formatRelDate(rule.date)}
        </span>
      </div>
      <div className="text-sm text-gray-200 leading-tight line-clamp-2 mb-2 min-h-[2.5rem] group-hover:text-white">
        {rule.title}
      </div>
      {(rule.platforms.length > 0 || rule.event_types.length > 0) && (
        <div className="flex items-center gap-1 flex-wrap">
          {rule.platforms.slice(0, 3).map((p) => (
            <span key={p} className="text-[9px] font-mono text-cyan-400/80 bg-cyan-500/5 border border-cyan-500/20 px-1.5 py-0.5">
              {p}
            </span>
          ))}
          {rule.event_types.slice(0, 2).map((e) => (
            <span key={e} className="text-[9px] font-mono text-gray-500 bg-void-800 border border-void-600 px-1.5 py-0.5">
              {e}
            </span>
          ))}
        </div>
      )}
    </Link>
  );
}

// How many unique rule cards to render. 15 gives 5 rows on lg (3-col),
// 8 on md (2-col) — enough to skim what's new this window without
// scrolling past the section entirely. Fetch is 2x so dedup between
// created/modified rarely under-fills.
const CARDS_TO_SHOW = 15;

export function NotableNewRulesSection({
  filters,
  days,
}: {
  filters: ActivityFilters;
  days?: number;
}) {
  const { data, isLoading, error } = useRecentRules(CARDS_TO_SHOW * 2, filters, days);

  // useMemo runs on every render — never conditionally. Guarded against
  // undefined `data` instead of being placed after early returns
  // (the Rules-of-Hooks crash on 2026-04-24 was that pattern).
  const merged = useMemo(() => {
    if (!data) return [] as RecentRuleItem[];
    const byId = new Map<string, RecentRuleItem>();
    for (const r of [...data.most_recently_created, ...data.most_recently_modified]) {
      const existing = byId.get(r.id);
      if (!existing || (r.date && existing.date && r.date > existing.date)) {
        byId.set(r.id, r);
      }
    }
    return Array.from(byId.values())
      .sort((a, b) => (b.date || '').localeCompare(a.date || ''))
      .slice(0, CARDS_TO_SHOW);
  }, [data]);

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
        {[...Array(CARDS_TO_SHOW)].map((_, i) => <SkeletonRow key={i} height="h-24" />)}
      </div>
    );
  }
  if (error || !data) return <EmptyLabel label="NO_RECENT_DATA" />;
  if (merged.length === 0) {
    return (
      <EmptyLabel
        label={days ? `NO_RULES_CREATED_OR_MODIFIED_IN_LAST_${days}D` : 'NO_RECENT_DATA'}
      />
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
      {merged.map((r) => <NotableRuleCard key={r.id} rule={r} />)}
    </div>
  );
}
