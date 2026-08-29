/**
 * Source grid: one card per upstream repo with the live numbers the
 * old stat tiles and source list carried separately -- rule count,
 * net change this week, hygiene average, last sync -- plus the repo
 * link. Clicking the card opens the catalog filtered to the source.
 */

import { Link } from 'react-router-dom';
import { DataSourceIcon } from '../../components/graphics/DataSourceIcon';
import { useStatistics } from '../../hooks/useDetections';
import { useSourceDeltas } from '../../hooks/useTrending';
import { useRepositories } from '../../hooks/useRepositories';
import { clipMd } from '../../constants/style';
import { formatRelDate } from '../intel/lib';
import { HOME_SOURCES } from './sources';

export function SourceGrid() {
  const { data: stats } = useStatistics();
  const { data: deltas } = useSourceDeltas(7);
  const { data: repos } = useRepositories();
  const repoByName = new Map((repos || []).map((r) => [r.name, r]));

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
      {HOME_SOURCES.map((source, index) => {
        const count = stats?.by_source?.[source.id] ?? null;
        const delta = deltas?.by_source?.[source.id]?.delta ?? null;
        const hygiene = stats?.quality_by_source?.[source.id]?.avg ?? null;
        const repo = repoByName.get(source.id);
        return (
          <div
            key={source.id}
            className="group relative bg-void-850 border border-void-700 p-4 transition-all duration-300 card-lift"
            style={{ ...clipMd, borderColor: `${source.color}30`, animationDelay: `${index * 40}ms` }}
            data-testid={`source-${source.id}`}
          >
            <div className="absolute left-0 top-4 bottom-4 w-0.5 opacity-60" style={{ backgroundColor: source.color }} />
            <div className="flex items-start gap-3">
              <Link to={`/detections?sources=${source.id}`} className="shrink-0" aria-label={`Browse ${source.name} rules`}>
                <DataSourceIcon source={source.id} size={40} />
              </Link>
              <div className="flex-1 min-w-0">
                <div className="flex items-baseline justify-between gap-2">
                  <Link
                    to={`/detections?sources=${source.id}`}
                    className="font-display font-semibold tracking-wide text-sm truncate hover:brightness-125 transition-all"
                    style={{ color: source.color }}
                  >
                    {source.name}
                  </Link>
                  <a
                    href={source.repoUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[10px] font-mono text-gray-600 hover:text-matrix-400 shrink-0"
                    title="Upstream repository"
                  >
                    repo &#8599;
                  </a>
                </div>
                <div className="mt-1 flex items-baseline gap-2">
                  <span className="text-2xl font-display font-bold text-white tabular-nums leading-none">
                    {count === null ? '—' : count.toLocaleString()}
                  </span>
                  <span className="text-[10px] font-mono text-gray-600">rules</span>
                  {delta !== null && (
                    <span
                      className={`text-[11px] font-mono tabular-nums ${delta > 0 ? 'text-pulse-400' : delta < 0 ? 'text-breach-400' : 'text-gray-600'}`}
                      title="Net change vs 7 days ago"
                    >
                      {delta > 0 ? '+' : ''}{delta} / 7d
                    </span>
                  )}
                </div>
                <p className="text-xs text-gray-500 mt-1.5 line-clamp-2">{source.description}</p>
                <div className="mt-2 flex items-center justify-between text-[10px] font-mono text-gray-600">
                  <span title="Average hygiene score of scored rules (metadata, ATT&CK mapping, docs, testability)">
                    {hygiene === null ? '' : `hygiene ${hygiene}`}
                  </span>
                  <span>{repo?.last_sync_at ? `synced ${formatRelDate(repo.last_sync_at)}` : ''}</span>
                </div>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
