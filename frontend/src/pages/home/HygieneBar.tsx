/**
 * Corpus hygiene at a glance: a single segmented bar of the cumulative
 * score bands (80+ / 60-79 / 40-59 / under 40) from the facet counts,
 * with the corpus average. Each segment opens the catalog at that
 * threshold. Hygiene measures rule metadata and testability, not
 * detection accuracy -- the tooltip says so.
 */

import { Link } from 'react-router-dom';
import { useFacets, useStatistics } from '../../hooks/useDetections';

export function HygieneBar() {
  const { data: facets } = useFacets({});
  const { data: stats } = useStatistics();
  const band = new Map((facets?.quality_band || []).map((b) => [b.value, b.count]));
  const total = stats?.total ?? 0;
  const at80 = band.get('80') ?? 0;
  const at60 = band.get('60') ?? 0;
  const at40 = band.get('40') ?? 0;
  const segments = [
    { key: '80', label: '80+', n: at80, cls: 'bg-matrix-500', to: '/detections?min_quality=80' },
    { key: '60', label: '60-79', n: Math.max(0, at60 - at80), cls: 'bg-lime-500', to: '/detections?min_quality=60' },
    { key: '40', label: '40-59', n: Math.max(0, at40 - at60), cls: 'bg-amber-500', to: '/detections?min_quality=40' },
    { key: '0', label: 'under 40', n: Math.max(0, total - at40), cls: 'bg-breach-500', to: '/detections?q=quality:<40' },
  ];
  if (!total || !facets) return null;

  return (
    <div className="bg-void-850 border border-void-700 px-4 py-3">
      <div className="flex items-center justify-between gap-4 flex-wrap mb-2">
        <div>
          <span className="text-[10px] font-mono text-matrix-400 uppercase tracking-[0.2em]">Corpus hygiene</span>
          <span className="text-[10px] font-mono text-gray-600 ml-2" title="Metadata, ATT&CK mapping, specificity, docs, testability -- not detection accuracy">
            metadata + mapping + docs + testability
          </span>
        </div>
        {stats?.quality_avg != null && (
          <span className="text-sm font-mono text-white tabular-nums">avg {stats.quality_avg}</span>
        )}
      </div>
      <div className="flex h-2 w-full overflow-hidden bg-void-900" role="img" aria-label="Hygiene score distribution">
        {segments.map((s) => (
          <Link
            key={s.key}
            to={s.to}
            className={`${s.cls} hover:brightness-125 transition-all`}
            style={{ width: `${(s.n / total) * 100}%` }}
            title={`${s.label}: ${s.n.toLocaleString()} rules`}
          />
        ))}
      </div>
      <div className="mt-1.5 flex gap-4 text-[10px] font-mono text-gray-500 flex-wrap">
        {segments.map((s) => (
          <Link key={s.key} to={s.to} className="hover:text-gray-300">
            <span className={`inline-block w-2 h-2 mr-1 align-middle ${s.cls}`} />
            {s.label} <span className="text-gray-600 tabular-nums">{s.n.toLocaleString()}</span>
          </Link>
        ))}
      </div>
    </div>
  );
}
