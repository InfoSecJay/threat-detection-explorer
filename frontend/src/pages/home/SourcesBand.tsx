/**
 * The breadth proof: every repository we ingest, with its live rule
 * count and the format it arrives in. One compact tile per source;
 * click to open the catalog filtered to it. The header line says what
 * normalization means so the tiles do not have to.
 */

import { Link } from 'react-router-dom';
import { DataSourceIcon } from '../../components/graphics/DataSourceIcon';
import { useStatistics } from '../../hooks/useDetections';
import { clipSm } from '../../constants/style';
import { HOME_SOURCES } from './sources';

export function SourcesBand() {
  const { data: stats } = useStatistics();
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-2">
      {HOME_SOURCES.map((source) => {
        const count = stats?.by_source?.[source.id] ?? null;
        return (
          <Link
            key={source.id}
            to={`/detections?sources=${source.id}`}
            className="group flex items-center gap-3 bg-void-850 border border-void-700 hover:border-matrix-500/40 px-3 py-2.5 transition-colors"
            style={clipSm}
            data-testid={`source-${source.id}`}
            title={source.description}
          >
            <DataSourceIcon source={source.id} size={28} />
            <div className="min-w-0 flex-1">
              <div className="text-sm font-display font-semibold truncate" style={{ color: source.color }}>
                {source.name}
              </div>
              <div className="text-[10px] font-mono text-gray-500 truncate">{source.format}</div>
            </div>
            <div className="text-right shrink-0">
              <div className="text-base font-display font-bold text-white tabular-nums leading-none">
                {count === null ? '—' : count.toLocaleString()}
              </div>
              <div className="text-[9px] font-mono text-gray-600 uppercase">rules</div>
            </div>
          </Link>
        );
      })}
    </div>
  );
}
