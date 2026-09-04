/**
 * Four exact numbers under the search box: scale (rules), breadth
 * (sources), depth (ATT&CK techniques with a rule) and currency (last
 * sync). Every value comes from an endpoint another page already
 * uses; each is a link to where that number lives.
 *
 * Depth counts PARENT techniques only (~207), sharing the constellation's
 * query so the home page costs no extra request. The MITRE browser
 * defaults to techniques + sub-techniques (~655), so the label has to
 * say which one this is or the two pages look like they disagree.
 *
 * First paint: while the live queries are in flight the strip shows
 * the numbers baked into the bundle at build time (#82 S2.7) instead
 * of dashes. Live values replace them the moment they arrive; the
 * baked ones are only ever a fallback, never the source of truth.
 */

import { Link } from 'react-router-dom';
import { useCorpusHealth } from '../../hooks/useCorpusHealth';
import { useStatistics } from '../../hooks/useDetections';
import { useCoverageMatrix } from '../../hooks/useCompare';
import { useRepositories } from '../../hooks/useRepositories';
import { ALL_SOURCES } from '../../constants/sources';
import { BAKED_SNAPSHOT } from '../../constants/snapshot';
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
  // Lead with the gap (#124 / #95): the share of the corpus with no ATT&CK
  // mapping, from the corpus-health report (edge-cached, 15 min).
  const { data: health } = useCorpusHealth();
  const noAttack = health?.totals_pct?.no_attack ?? BAKED_SNAPSHOT?.no_attack_pct ?? undefined;

  const liveSync = (repos || [])
    .map((r) => r.last_sync_at)
    .filter((d): d is string => !!d)
    .sort()
    .pop();
  const lastSync = repos ? liveSync : BAKED_SNAPSHOT?.last_sync ?? undefined;
  const rules = stats?.total ?? BAKED_SNAPSHOT?.rules;
  const covered = coverage?.summary.techniques_with_any_coverage ?? BAKED_SNAPSHOT?.coverage.covered;
  const total = coverage?.summary.total_techniques ?? BAKED_SNAPSHOT?.coverage.total;

  return (
    <div className="flex flex-wrap gap-x-10 gap-y-4 pt-5 mt-5 border-t border-void-800">
      <Stat to="/detections" value={rules !== undefined ? rules.toLocaleString() : '—'} label="detection rules" testId="stat-rules" />
      <Stat to="/methodology" value={String(ALL_SOURCES.length)} label="open-source repos" testId="stat-sources" />
      <Stat
        to="/mitre"
        value={covered !== undefined && total ? `${covered} / ${total}` : '—'}
        label="ATT&CK parent techniques covered"
        testId="stat-coverage"
      />
      <Stat to="/methodology" value={lastSync ? formatRelDate(lastSync) : '—'} label="last sync" testId="stat-sync" />
      <Stat
        to="/methodology/corpus-health"
        value={noAttack !== undefined ? `${Math.round(noAttack)}%` : '—'}
        label="rules with no ATT&CK mapping"
        testId="stat-health"
      />
    </div>
  );
}
