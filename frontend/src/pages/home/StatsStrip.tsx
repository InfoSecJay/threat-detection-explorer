/**
 * Four exact numbers under the search box: scale (rules), breadth
 * (sources), depth (ATT&CK techniques with a rule) and currency (last
 * sync). Every value comes from an endpoint another page already
 * uses; each is a link to where that number lives.
 */

import { Link } from 'react-router-dom';
import { useStatistics } from '../../hooks/useDetections';
import { useCoverageMatrix } from '../../hooks/useCompare';
import { useRepositories } from '../../hooks/useRepositories';
import { ALL_SOURCES } from '../../constants/sources';
import { formatRelDate } from '../intel/lib';

function Stat({ to, value, label, testId }: { to: string; value: string; label: string; testId: string }) {
  return (
    <Link to={to} className="group flex flex-col min-w-[7rem]" data-testid={testId}>
      <span className="text-2xl font-display font-bold text-white tabular-nums leading-none group-hover:text-matrix-400 transition-colors">
        {value}
      </span>
      <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider mt-1">{label}</span>
    </Link>
  );
}

export function StatsStrip() {
  const { data: stats } = useStatistics();
  const { data: coverage } = useCoverageMatrix({ include_subtechniques: false });
  const { data: repos } = useRepositories();

  const lastSync = (repos || [])
    .map((r) => r.last_sync_at)
    .filter((d): d is string => !!d)
    .sort()
    .pop();
  const covered = coverage?.summary.techniques_with_any_coverage;
  const total = coverage?.summary.total_techniques;

  return (
    <div className="flex flex-wrap gap-x-10 gap-y-4 pt-5 mt-5 border-t border-void-800">
      <Stat to="/detections" value={stats ? stats.total.toLocaleString() : '—'} label="detection rules" testId="stat-rules" />
      <Stat to="/methodology" value={String(ALL_SOURCES.length)} label="open-source repos" testId="stat-sources" />
      <Stat
        to="/mitre"
        value={covered !== undefined && total ? `${covered} / ${total}` : '—'}
        label="ATT&CK techniques covered"
        testId="stat-coverage"
      />
      <Stat to="/methodology" value={lastSync ? formatRelDate(lastSync) : '—'} label="last sync" testId="stat-sync" />
    </div>
  );
}
