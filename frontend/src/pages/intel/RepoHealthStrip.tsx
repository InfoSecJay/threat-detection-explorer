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

import { Link } from 'react-router-dom';
import { useRepositories } from '../../hooks/useRepositories';
import { useWeeklyActivity } from '../../hooks/useTrending';
import { sourceTheme as sourceConfig, clipSm } from '../../constants/style';
import { SkeletonRow } from './Section';
import { formatRelDate } from './lib';

function freshnessDot(lastSyncAt: string | null): { color: string; label: string } {
  if (!lastSyncAt) return { color: 'bg-gray-500', label: 'never synced' };
  const ageMs = Date.now() - new Date(lastSyncAt).getTime();
  const ageHours = ageMs / (1000 * 60 * 60);
  if (ageHours < 24) return { color: 'bg-matrix-500', label: 'fresh' };
  if (ageHours < 72) return { color: 'bg-yellow-500', label: 'stale' };
  return { color: 'bg-red-500', label: 'very stale' };
}

function Sparkline({ counts, colorClass }: { counts: number[]; colorClass: string }) {
  const max = Math.max(...counts, 1);
  return (
    <div className="flex items-end gap-[1px] h-6" aria-label="12-week new-rules trend">
      {counts.map((c, i) => {
        const h = c === 0 ? 1 : Math.max(2, Math.round((c / max) * 24));
        return (
          <div
            key={i}
            title={`week ${i + 1}: ${c}`}
            className={`w-1 ${c === 0 ? 'bg-void-700' : colorClass} transition-all`}
            style={{ height: `${h}px` }}
          />
        );
      })}
    </div>
  );
}

export function RepoHealthStrip() {
  const { data: repos, isLoading: reposLoading } = useRepositories();
  const { data: weekly, isLoading: weeklyLoading } = useWeeklyActivity(12);

  if (reposLoading || weeklyLoading) return <SkeletonRow height="h-24" />;
  if (!repos) return null;

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 xl:grid-cols-11 gap-2">
      {repos.map((repo) => {
        const cfg = sourceConfig[repo.name] || sourceConfig.sigma;
        const fresh = freshnessDot(repo.last_sync_at);
        const sparkCounts = weekly?.by_source[repo.name] || Array(12).fill(0);
        const weekTotal = sparkCounts.reduce((a, b) => a + b, 0);

        return (
          <Link
            key={repo.name}
            to={`/detections?sources=${repo.name}`}
            className="group block bg-void-850 border border-void-700 hover:border-matrix-500/40 p-2.5 transition-colors"
            style={clipSm}
          >
            <div className="flex items-center gap-1.5 mb-1.5">
              <span className={`w-2 h-2 rounded-full ${cfg.dot} shrink-0`} />
              <span className={`text-[10px] font-mono uppercase tracking-wider truncate ${cfg.text} group-hover:text-white`}>
                {cfg.name}
              </span>
              <span
                className={`w-1.5 h-1.5 rounded-full ${fresh.color} ml-auto shrink-0`}
                title={`${fresh.label} · last sync ${formatRelDate(repo.last_sync_at)}`}
              />
            </div>
            <div className="flex items-baseline gap-1 mb-1.5">
              <span className="text-lg font-display font-bold text-white tabular-nums leading-none">
                {repo.rule_count.toLocaleString()}
              </span>
              <span className="text-[9px] font-mono text-gray-600">rules</span>
            </div>
            <Sparkline counts={sparkCounts} colorClass={cfg.dot} />
            <div className="flex items-center justify-between mt-1.5">
              <span className="text-[9px] font-mono text-gray-600" title="new rules in 12 weeks">
                +{weekTotal} · 12wk
              </span>
              <span className="text-[9px] font-mono text-gray-600" title={`last sync ${formatRelDate(repo.last_sync_at)}`}>
                {formatRelDate(repo.last_sync_at)}
              </span>
            </div>
          </Link>
        );
      })}
    </div>
  );
}
