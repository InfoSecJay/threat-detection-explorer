/** "Same behaviour, other vendors": rules that key on the same
 * technique and the same process names / registry keys / API actions
 * / paths / indicators, ranked by overlap, other sources first. */

import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { detectionsApi } from '../../services/api';
import { sourceTheme } from '../../constants/style';
import { severityColor } from '../../pages/intel/lib';

export function RelatedRules({ id, source }: { id: string; source: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ['related', id],
    queryFn: () => detectionsApi.related(id),
    staleTime: 1000 * 60 * 10,
  });
  const rows = data?.related ?? [];
  const otherVendors = new Set(rows.filter((r) => r.other_vendor).map((r) => r.source));
  return (
    <section className="bg-void-850 rounded-xl border border-void-700" data-testid="related-rules">
      <div className="px-5 py-3 border-b border-void-700 flex items-baseline justify-between gap-3 flex-wrap">
        <h2 className="text-lg font-display font-bold text-white tracking-wider uppercase">Same behaviour, other vendors</h2>
        <span className="text-[10px] font-mono text-gray-500">
          {isLoading ? 'matching…' : rows.length === 0 ? 'nothing shares this rule’s technique or observables' : `${rows.length} rule${rows.length === 1 ? '' : 's'} · ${otherVendors.size} other source${otherVendors.size === 1 ? '' : 's'}`}
        </span>
      </div>
      {rows.length > 0 && (
        <ul className="divide-y divide-void-800">
          {rows.map((r) => {
            const cfg = sourceTheme[r.source];
            return (
              <li key={r.id} className="px-5 py-2 flex items-center gap-3 hover:bg-void-800/40" data-testid={`related-${r.id}`}>
                <span className={`px-1.5 py-0.5 text-[9px] font-mono uppercase tracking-wider border shrink-0 ${cfg?.text || 'text-gray-400'} ${cfg?.border || 'border-void-700'} ${r.source === source ? 'opacity-60' : ''}`} title={r.source === source ? 'same repository' : 'another vendor'}>
                  {cfg?.name || r.source}
                </span>
                <Link to={`/detections/${r.id}`} className="text-sm text-gray-200 hover:text-matrix-400 truncate flex-1 min-w-0">{r.title}</Link>
                <span className={`font-mono text-[10px] uppercase shrink-0 ${severityColor[r.severity] || 'text-gray-400'}`}>{r.severity}</span>
                <span className="font-mono text-[10px] text-gray-500 shrink-0 max-w-[40%] truncate" title={r.reasons.join(' · ')}>
                  {r.reasons.slice(0, 2).join(' · ')}
                </span>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
