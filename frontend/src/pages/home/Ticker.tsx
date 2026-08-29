/**
 * Status ticker under the hero -- the page's signature element. One
 * monospace line of live cells, the way a console status bar reads:
 * corpus size, net change this week, techniques newly covered, the
 * technique with the most momentum, and when the last sync landed.
 * Every cell links to the surface that explains it.
 */

import { Link } from 'react-router-dom';
import { useStatistics } from '../../hooks/useDetections';
import { useNewlyCovered, useSourceDeltas, useTechniqueDeltas } from '../../hooks/useTrending';
import { useRepositories } from '../../hooks/useRepositories';
import { useMitre } from '../../contexts/MitreContext';
import { formatRelDate } from '../intel/lib';
import { parseApiDate } from '../../utils/dates';

function Cell({ to, label, value, tone = 'text-white', title }: {
  to: string; label: string; value: string; tone?: string; title?: string;
}) {
  return (
    <Link
      to={to}
      className="flex items-baseline gap-2 px-4 py-2 border-r border-void-700 last:border-r-0 hover:bg-void-800/60 transition-colors whitespace-nowrap"
      title={title}
    >
      <span className="text-[10px] font-mono text-gray-500 uppercase tracking-[0.18em]">{label}</span>
      <span className={`font-mono text-sm tabular-nums ${tone}`} data-testid={`ticker-${label.replace(/\s+/g, '-').toLowerCase()}`}>{value}</span>
    </Link>
  );
}

export function Ticker() {
  const { data: stats } = useStatistics();
  const { data: deltas } = useSourceDeltas(7);
  const { data: covered } = useNewlyCovered(7, 12);
  const { data: momentum } = useTechniqueDeltas(7, 1);
  const { data: repos } = useRepositories();
  const { getTechniqueName } = useMitre();

  const net = deltas?.method === 'sync_jobs'
    ? Object.values(deltas.by_source).reduce((s, v) => s + (v.delta ?? 0), 0)
    : null;
  const newlyCovered = covered ? covered.catalog_newly_covered.length + covered.source_newly_covered.length : null;
  const top = momentum?.method === 'snapshot' ? momentum.gainers[0] ?? null : null;
  const lastSync = repos?.reduce<string | null>((latest, r) => {
    if (!r.last_sync_at) return latest;
    return !latest || parseApiDate(r.last_sync_at) > parseApiDate(latest) ? r.last_sync_at : latest;
  }, null) ?? null;

  return (
    <div
      className="flex items-stretch overflow-x-auto bg-void-900/80 border-y border-void-700 -mx-4 px-2 sm:mx-0 sm:border sm:border-void-700"
      role="status"
      aria-label="Corpus status"
    >
      <Cell to="/detections" label="rules" value={stats ? stats.total.toLocaleString() : '—'} tone="text-matrix-400" />
      <Cell
        to="/intel"
        label="7d net"
        value={net === null ? '—' : `${net > 0 ? '+' : ''}${net.toLocaleString()}`}
        tone={net === null ? 'text-gray-500' : net > 0 ? 'text-pulse-400' : net < 0 ? 'text-breach-400' : 'text-gray-300'}
        title="Rules added minus removed across all sources, vs the sync 7 days ago"
      />
      <Cell
        to="/intel"
        label="newly covered"
        value={newlyCovered === null ? '—' : String(newlyCovered)}
        title="Techniques that gained their first rule (catalog-wide or per source) in the last 7 days"
      />
      <Cell
        to={top ? `/mitre/${top.technique_id}` : '/intel'}
        label="momentum"
        value={top ? `${top.technique_id} +${top.delta}` : '—'}
        tone={top ? 'text-pulse-400' : 'text-gray-500'}
        title={top ? `${getTechniqueName(top.technique_id) || top.technique_id}: +${top.delta} rules this week` : 'Needs 7 days of coverage snapshots'}
      />
      <Cell
        to="/integrations"
        label="last sync"
        value={lastSync ? formatRelDate(lastSync) : '—'}
        tone="text-gray-300"
      />
    </div>
  );
}
