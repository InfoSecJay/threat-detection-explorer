/**
 * "Just covered" — the MITRE coverage-diff signal (issue #9).
 *
 * Two compact lists driven by /trending/newly-covered:
 *  - techniques that gained their FIRST rule anywhere in the window
 *  - techniques an individual source just picked up while other
 *    sources already covered them ("Splunk just picked up T1651 —
 *    Sigma's had it for two years")
 *
 * The endpoint reports how the diff was computed: exact daily
 * snapshots once history exists, or git-derived first-rule dates
 * during the blind window — captioned so readers can judge the
 * provenance.
 */

import { Link } from 'react-router-dom';
import { useNewlyCovered } from '../../hooks/useTrending';
import { sourceTheme as sourceConfig } from '../../constants/style';
import { SkeletonRow, EmptyLabel } from './Section';

function SourceDot({ source }: { source: string }) {
  return (
    <span
      className={`w-1.5 h-1.5 rounded-full ${sourceConfig[source]?.dot || 'bg-gray-500'}`}
      title={sourceConfig[source]?.name || source}
    />
  );
}

export function JustCoveredSection({ days, sources }: { days: number; sources: string[] }) {
  const { data, isLoading, error } = useNewlyCovered(days, 12, sources);

  if (isLoading) {
    return <div className="space-y-1">{[...Array(4)].map((_, i) => <SkeletonRow key={i} />)}</div>;
  }
  if (error || !data) return <EmptyLabel label="NO_COVERAGE_DIFF" />;

  const catalog = data.catalog_newly_covered;
  const perSource = data.source_newly_covered;
  if (!catalog.length && !perSource.length) {
    return <EmptyLabel label="NO_NEW_COVERAGE_IN_WINDOW" />;
  }

  return (
    <div className="space-y-3">
      {catalog.length > 0 && (
        <div>
          <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider mb-1">
            First rule anywhere
          </div>
          <div className="space-y-1">
            {catalog.map((e) => (
              <Link
                key={e.technique_id}
                to={`/detections?mitre_techniques=${e.technique_id}`}
                className="block bg-void-800/60 border border-void-700 hover:border-void-600 px-2.5 py-1.5 transition-colors"
              >
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs text-matrix-500 shrink-0">{e.technique_id}</span>
                  <span className="text-xs text-gray-400 truncate min-w-0 flex-1">
                    {e.technique_name || 'Unknown Technique'}
                  </span>
                  <div className="flex gap-0.5 shrink-0">
                    {Object.keys(e.sources).slice(0, 4).map((src) => (
                      <SourceDot key={src} source={src} />
                    ))}
                  </div>
                  <span className="text-xs font-mono text-white tabular-nums w-8 text-right shrink-0">
                    {e.total_rules}
                  </span>
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}

      {perSource.length > 0 && (
        <div>
          <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider mb-1">
            Source caught up
          </div>
          <div className="space-y-1">
            {perSource.map((e) => {
              const cfg = sourceConfig[e.source];
              return (
                <Link
                  key={`${e.source}-${e.technique_id}`}
                  to={`/detections?mitre_techniques=${e.technique_id}&sources=${e.source}`}
                  className="block bg-void-800/60 border border-void-700 hover:border-void-600 px-2.5 py-1.5 transition-colors"
                >
                  <div className="flex items-center gap-2">
                    <span className={`px-1.5 py-0.5 text-[10px] font-mono uppercase border shrink-0 ${cfg?.bg || ''} ${cfg?.text || 'text-gray-300'} ${cfg?.border || 'border-void-600'}`}>
                      {cfg?.name || e.source}
                    </span>
                    <span className="font-mono text-xs text-cyan-400 shrink-0">{e.technique_id}</span>
                    <span className="text-xs text-gray-400 truncate min-w-0 flex-1">
                      {e.technique_name || 'Unknown Technique'}
                    </span>
                    {e.covered_elsewhere.length > 0 && (
                      <span
                        className="text-[10px] font-mono text-gray-500 shrink-0"
                        title={`Already covered by: ${e.covered_elsewhere.join(', ')}`}
                      >
                        +{e.covered_elsewhere.length} had it
                      </span>
                    )}
                  </div>
                </Link>
              );
            })}
          </div>
        </div>
      )}

      <div className="text-[10px] font-mono text-gray-600">
        {data.method === 'snapshot'
          ? `diffed against ${data.baseline_date} snapshot`
          : 'derived from upstream rule-creation dates (snapshot history accumulating)'}
        {data.new_sources.length > 0 && (
          <> · new sources excluded: {data.new_sources.join(', ')}</>
        )}
      </div>
    </div>
  );
}
