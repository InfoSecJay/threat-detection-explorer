/**
 * Repo Health strip — one card per source with rule count, last-sync
 * age, freshness dot, and a 12-week rules-added sparkline. This is the
 * top-of-page "is everything working, and where is activity happening?"
 * scan for a returning DE.
 *
 * Freshness rubric (green/amber/red) is based on last_sync_at, not
 * rule_created_date — a healthy repo can go quiet legitimately; what
 * we're flagging here is *our* ingestion, not upstream activity.
 */

import { parseApiDate } from '../../utils/dates';
import { Link } from 'react-router-dom';
import { useRepositories } from '../../hooks/useRepositories';
import { useWeeklyActivity } from '../../hooks/useTrending';
import { sourceTheme as sourceConfig, clipSm } from '../../constants/style';
import { SkeletonRow } from './Section';
import { formatRelDate } from './lib';

function freshnessDot(lastSyncAt: string | null): { color: string; label: string } {
  if (!lastSyncAt) return { color: 'bg-gray-500', label: 'never synced' };
  const ageMs = Date.now() - parseApiDate(lastSyncAt).getTime();
  const ageHours = ageMs / (1000 * 60 * 60);
  if (ageHours < 24) return { color: 'bg-matrix-500', label: 'fresh' };
  if (ageHours < 72) return { color: 'bg-yellow-500', label: 'stale' };
  return { color: 'bg-red-500', label: 'very stale' };
}

/**
 * 12 tiny bars sized to a shared per-card scale. Empty weeks render
 * as barely-visible baseline ticks so the 12-week cadence is legible
 * even for quiet repos.
 */
function Sparkline({ counts, colorClass }: { counts: number[]; colorClass: string }) {
  const max = Math.max(...counts, 1);
  return (
    <div className="flex items-end gap-[2px] h-7" aria-label="12-week new-rules trend">
      {counts.map((c, i) => {
        const h = c === 0 ? 2 : Math.max(3, Math.round((c / max) * 28));
        return (
          <div
            key={i}
            title={`week ${i + 1}: ${c} new`}
            className={`flex-1 min-w-[3px] ${c === 0 ? 'bg-void-600' : colorClass} transition-all group-hover:opacity-100 ${c === 0 ? 'opacity-70' : 'opacity-90'}`}
            style={{ height: `${h}px` }}
          />
        );
      })}
    </div>
  );
}

export function RepoHealthStrip() {
  const { data: reposRaw, isLoading: reposLoading } = useRepositories();
  const { data: weekly, isLoading: weeklyLoading } = useWeeklyActivity(12);

  if (reposLoading || weeklyLoading) return <SkeletonRow height="h-28" />;
  if (!reposRaw) return null;

  // Filter out stale repo rows that predate a rename (e.g.
  // `okta_custom_detections` before it became `okta`). Any repo whose
  // name isn't a canonical source in `sourceConfig` is orphaned and
  // shouldn't render — otherwise it falls through to the default theme
  // and shows a phantom "0 rules" card with the wrong colors.
  const repos = reposRaw.filter((r) => r.name in sourceConfig);

  // "Hot" threshold: a repo whose 12-week new-rules total is >= 2x
  // the median non-zero repo gets a subtle accent border to signal
  // "look here first." Median avoids one outlier repo dominating.
  const totals = repos.map((r) => (weekly?.by_source[r.name] || []).reduce((a, b) => a + b, 0));
  const nonZero = totals.filter((t) => t > 0).sort((a, b) => a - b);
  const median = nonZero.length ? nonZero[Math.floor(nonZero.length / 2)] : 0;
  const hotThreshold = median * 2;

  return (
    <div
      className="grid gap-2"
      style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))' }}
    >
      {repos.map((repo, i) => {
        const cfg = sourceConfig[repo.name] || sourceConfig.sigma;
        const fresh = freshnessDot(repo.last_sync_at);
        const sparkCounts = weekly?.by_source[repo.name] || Array(12).fill(0);
        const weekTotal = totals[i];
        const isHot = weekTotal > 0 && weekTotal >= hotThreshold;

        return (
          <Link
            key={repo.name}
            to={`/detections?sources=${repo.name}`}
            title={isHot ? 'High activity this quarter — click to filter catalog' : 'Filter catalog to this source'}
            className={`group relative block bg-void-850 border p-2.5 transition-all hover:bg-void-800 ${
              isHot ? `${cfg.border} shadow-[0_0_12px_rgba(0,0,0,0.4)]` : 'border-void-700 hover:border-void-600'
            }`}
            style={clipSm}
          >
            <div className="flex items-center gap-1.5 mb-2">
              <span className={`w-2 h-2 rounded-full ${cfg.dot} shrink-0`} />
              <span className={`text-[10px] font-mono uppercase tracking-wider truncate font-semibold ${cfg.text}`}>
                {cfg.name}
              </span>
              <span
                className={`w-1.5 h-1.5 rounded-full ${fresh.color} ml-auto shrink-0`}
                title={`${fresh.label} · last sync ${formatRelDate(repo.last_sync_at)}`}
              />
            </div>
            <div className="flex items-baseline gap-1 mb-2">
              <span className="text-xl font-display font-bold text-white tabular-nums leading-none">
                {repo.rule_count.toLocaleString()}
              </span>
              <span className="text-[9px] font-mono text-gray-500">rules</span>
              {weekTotal > 0 && (
                <span className={`ml-auto text-[10px] font-mono ${cfg.text} tabular-nums`} title="new rules in last 12 weeks">
                  +{weekTotal}
                </span>
              )}
            </div>
            <Sparkline counts={sparkCounts} colorClass={cfg.dot} />
            <div className="text-[9px] font-mono text-gray-600 mt-2 text-right" title={`last sync ${formatRelDate(repo.last_sync_at)}`}>
              synced {formatRelDate(repo.last_sync_at)}
            </div>
          </Link>
        );
      })}
    </div>
  );
}
