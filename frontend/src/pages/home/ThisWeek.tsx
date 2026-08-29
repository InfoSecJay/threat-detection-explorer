/**
 * "This week" -- three tiles that answer "what changed": net change per
 * source, techniques just covered, technique momentum. All against a
 * fixed 7-day window (the Intel page has the adjustable one).
 */

import { Link } from 'react-router-dom';
import { useNewlyCovered, useSourceDeltas } from '../../hooks/useTrending';
import { sourceTheme, clipSm } from '../../constants/style';
import { TechniqueMomentumList } from '../intel/Trending';
import { SkeletonRow, EmptyLabel } from '../intel/Section';

function Tile({ title, subtitle, to, children }: { title: string; subtitle: string; to: string; children: React.ReactNode }) {
  return (
    <div className="bg-void-850 border border-void-700 overflow-hidden flex flex-col" style={clipSm}>
      <div className="flex items-center justify-between gap-2 px-3 py-2 border-b border-void-700 bg-void-900/40">
        <div>
          <h3 className="font-display font-semibold text-[11px] uppercase tracking-wider text-matrix-400">{title}</h3>
          <p className="text-[10px] font-mono text-gray-600">{subtitle}</p>
        </div>
        <Link to={to} className="text-[10px] font-mono text-gray-500 hover:text-matrix-400 uppercase tracking-wider">
          [ more ]
        </Link>
      </div>
      <div className="p-2 flex-1">{children}</div>
    </div>
  );
}

export function NetChangeList() {
  const { data, isLoading } = useSourceDeltas(7);
  if (isLoading) return <div className="space-y-1">{[...Array(6)].map((_, i) => <SkeletonRow key={i} />)}</div>;
  if (!data || data.method !== 'sync_jobs') return <EmptyLabel label="NEEDS_7_DAYS_OF_SYNC_HISTORY" />;
  const rows = Object.entries(data.by_source)
    .filter(([, v]) => v.delta !== null && v.delta !== 0)
    .sort(([, a], [, b]) => Math.abs(b.delta ?? 0) - Math.abs(a.delta ?? 0))
    .slice(0, 7);
  if (!rows.length) return <EmptyLabel label="NO_CHANGE_THIS_WEEK" />;
  const max = Math.max(...rows.map(([, v]) => Math.abs(v.delta ?? 0)));
  return (
    <div className="space-y-1">
      {rows.map(([src, v]) => {
        const d = v.delta ?? 0;
        const cfg = sourceTheme[src];
        return (
          <Link key={src} to={`/detections?sources=${src}&sort_by=rule_created_date&sort_order=desc`} className="block group">
            <div className="relative bg-void-800/60 border border-void-700 hover:border-void-600 px-2.5 py-1.5 transition-colors">
              <div className={`absolute inset-y-0 left-0 ${d > 0 ? 'bg-pulse-500/10' : 'bg-breach-500/10'}`} style={{ width: `${(Math.abs(d) / max) * 100}%` }} />
              <div className="relative flex items-center gap-2 text-xs">
                <span className={`w-2 h-2 rounded-full shrink-0 ${cfg?.dot || 'bg-gray-500'}`} />
                <span className={`font-mono ${cfg?.text || 'text-gray-300'}`}>{cfg?.name || src}</span>
                <span className="flex-1" />
                <span className="font-mono text-gray-600 tabular-nums">{v.current?.toLocaleString()}</span>
                <span className={`font-mono tabular-nums w-12 text-right ${d > 0 ? 'text-pulse-400' : 'text-breach-400'}`}>
                  {d > 0 ? '+' : ''}{d}
                </span>
              </div>
            </div>
          </Link>
        );
      })}
    </div>
  );
}

export function JustCoveredList() {
  const { data, isLoading } = useNewlyCovered(7, 6);
  if (isLoading) return <div className="space-y-1">{[...Array(6)].map((_, i) => <SkeletonRow key={i} />)}</div>;
  const rows = data
    ? [
        ...data.catalog_newly_covered.map((e) => ({ id: e.technique_id, name: e.technique_name, note: 'first rule anywhere', srcs: Object.keys(e.sources) })),
        ...data.source_newly_covered.map((e) => ({ id: e.technique_id, name: e.technique_name, note: `new for ${sourceTheme[e.source]?.name || e.source}`, srcs: [e.source] })),
      ].slice(0, 6)
    : [];
  if (!rows.length) return <EmptyLabel label="NOTHING_NEWLY_COVERED_THIS_WEEK" />;
  return (
    <div className="space-y-1">
      {rows.map((r, i) => (
        <Link key={`${r.id}-${i}`} to={`/mitre/${r.id}`} className="block group">
          <div className="bg-void-800/60 border border-void-700 hover:border-void-600 px-2.5 py-1.5 transition-colors flex items-center gap-2 text-xs">
            <span className="font-mono text-amber-300 shrink-0">{r.id}</span>
            <span className="text-gray-400 truncate min-w-0 flex-1">{r.name || 'Unknown technique'}</span>
            <div className="flex gap-0.5 shrink-0">
              {r.srcs.slice(0, 4).map((s) => <span key={s} className={`w-1.5 h-1.5 rounded-full ${sourceTheme[s]?.dot || 'bg-gray-500'}`} title={s} />)}
            </div>
            <span className="text-[9px] font-mono text-gray-600 uppercase shrink-0">{r.note}</span>
          </div>
        </Link>
      ))}
    </div>
  );
}

export function ThisWeek() {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
      <Tile title="Net change by source" subtitle="rules added minus removed, vs 7 days ago" to="/intel">
        <NetChangeList />
      </Tile>
      <Tile title="Just covered" subtitle="techniques that gained their first rule" to="/intel">
        <JustCoveredList />
      </Tile>
      <Tile title="Technique momentum" subtitle="catalog-wide rule count change" to="/intel">
        <TechniqueMomentumList />
      </Tile>
    </div>
  );
}
