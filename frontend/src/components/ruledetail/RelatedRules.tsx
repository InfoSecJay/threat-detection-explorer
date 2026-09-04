/** "Same behaviour, other vendors": rules that key on the same
 * technique and the same process names / registry keys / API actions
 * / paths / indicators, ranked by overlap, other sources first. */

import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { detectionsApi } from '../../services/api';
import { sourceTheme } from '../../constants/style';
import { severityColor } from '../../pages/intel/lib';

// `source` is accepted for call-site stability but unused: the API
// already splits cross-vendor from same-source (F12).
export function RelatedRules({ id }: { id: string; source?: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ['related', id],
    queryFn: () => detectionsApi.related(id),
    staleTime: 1000 * 60 * 10,
  });
  const rows = data?.related ?? [];
  const sameRows = data?.same_source ?? [];
  const otherVendors = new Set(rows.map((r) => r.source));
  return (
    <section className="bg-void-850 rounded-xl border border-void-700" data-testid="related-rules">
      <div className="px-5 py-3 border-b border-void-700 flex items-baseline justify-between gap-3 flex-wrap">
        <h2 className="text-lg font-display font-bold text-white tracking-wider uppercase">Same behaviour, other vendors</h2>
        <span className="text-[10px] font-mono text-gray-500">
          {isLoading ? 'matching…' : rows.length === 0 ? '' : `${rows.length} rule${rows.length === 1 ? '' : 's'} · ${otherVendors.size} other source${otherVendors.size === 1 ? '' : 's'}`}
        </span>
      </div>
      {!isLoading && rows.length === 0 && (
        <p className="px-5 py-4 text-xs text-gray-400" data-testid="related-gap">
          <span className="text-breach-400 font-mono uppercase tracking-wider mr-2">coverage gap</span>
          No other tracked source has a rule sharing this rule&apos;s technique or observables.
        </p>
      )}
      {rows.length > 0 && (
        <ul className="divide-y divide-void-800">
          {rows.map((r) => {
            const cfg = sourceTheme[r.source];
            return (
              <li key={r.id} className="px-5 py-2 flex items-center gap-3 hover:bg-void-800/40" data-testid={`related-${r.id}`}>
                <span className={`px-1.5 py-0.5 text-[9px] font-mono uppercase tracking-wider border shrink-0 ${cfg?.text || 'text-gray-400'} ${cfg?.border || 'border-void-700'}`}>
                  {cfg?.name || r.source}
                </span>
                <Link to={`/detections/${r.id}`} className="text-sm text-gray-200 hover:text-matrix-400 truncate flex-1 min-w-0">{r.title}</Link>
                <span className={`font-mono text-[10px] uppercase shrink-0 ${severityColor[r.severity] || 'text-gray-400'}`}>{r.severity}</span>
                <span className="font-mono text-[10px] text-gray-500 shrink-0 max-w-[40%] truncate" title={r.reasons.join(' · ')}>
                  {r.reasons.slice(0, 2).join(' · ')}
                </span>
                <Link
                  to={`/compare?ids=${encodeURIComponent(id)},${encodeURIComponent(r.id)}`}
                  className="font-mono text-[10px] text-gray-500 hover:text-cyan-300 uppercase tracking-wider shrink-0"
                  title="What each rule keys on, side by side (#11)"
                  data-testid={`compare-${r.id}`}
                >
                  diff
                </Link>
              </li>
            );
          })}
        </ul>
      )}
      {sameRows.length > 0 && (
        <div data-testid="related-same-source">
          <div className="px-5 py-2 border-t border-void-700 bg-void-900/40 text-[10px] font-mono text-gray-500 uppercase tracking-wider">
            Same repository, similar behaviour
          </div>
          <ul className="divide-y divide-void-800">
            {sameRows.map((r) => (
              <li key={r.id} className="px-5 py-2 flex items-center gap-3 hover:bg-void-800/40" data-testid={`related-${r.id}`}>
                <Link to={`/detections/${r.id}`} className="text-sm text-gray-300 hover:text-matrix-400 truncate flex-1 min-w-0">{r.title}</Link>
                <span className={`font-mono text-[10px] uppercase shrink-0 ${severityColor[r.severity] || 'text-gray-400'}`}>{r.severity}</span>
                <span className="font-mono text-[10px] text-gray-500 shrink-0 max-w-[40%] truncate" title={r.reasons.join(' · ')}>
                  {r.reasons.slice(0, 2).join(' · ')}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
