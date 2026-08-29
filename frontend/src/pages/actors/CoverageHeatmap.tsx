/**
 * Actors x sources gap heatmap: which vendor covers which actor's
 * techniques, and where nobody does. Cell = share of the actor's
 * techniques the source has at least one rule for; darker = more.
 */

import { useQuery } from '@tanstack/react-query';
import { Link, useSearchParams } from 'react-router-dom';
import { actorsApi } from '../../services/api';
import { sourceTheme, clipSm } from '../../constants/style';
import { sourceLabelsShort } from '../../constants/sources';
import { SkeletonRow, EmptyLabel } from '../intel/Section';

const SORTS = [
  { value: 'weighted_gap', label: 'Biggest gap' },
  { value: 'gap_count', label: 'Most uncovered' },
  { value: 'technique_count', label: 'Most techniques' },
  { value: 'name', label: 'Name' },
] as const;

function heat(pct: number): string {
  if (pct === 0) return 'bg-void-900 text-gray-700';
  if (pct < 25) return 'bg-breach-500/20 text-breach-300';
  if (pct < 50) return 'bg-amber-500/25 text-amber-200';
  if (pct < 75) return 'bg-lime-500/25 text-lime-200';
  return 'bg-matrix-500/30 text-matrix-200';
}

export function CoverageHeatmap() {
  const [params, setParams] = useSearchParams();
  const kind = params.get('kind') === 'software' ? 'software' : 'groups';
  const sort = (SORTS.find((s) => s.value === params.get('sort'))?.value ?? 'weighted_gap');
  const limit = Math.min(200, Math.max(5, Number(params.get('limit') ?? 40) || 40));
  const { data, isLoading, error } = useQuery({
    queryKey: ['actor-coverage-matrix', kind, sort, limit],
    queryFn: () => actorsApi.coverageMatrix({ kind, sort, limit }),
    staleTime: 1000 * 60 * 10,
  });

  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    next.set(k, v);
    setParams(next, { replace: true });
  };

  return (
    <div className="space-y-4">
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <Link to="/actors" className="text-xs font-mono text-gray-500 hover:text-matrix-400">&larr; Actors</Link>
          <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase mt-1">Coverage heatmap</h1>
          <p className="text-xs text-gray-500 mt-1 font-mono">
            which vendor covers which {kind === 'groups' ? 'actor' : 'software'}, and where nobody does - each cell is the share of that entity&apos;s techniques the source has a rule for
          </p>
        </div>
        <div className="flex items-center gap-3 flex-wrap text-xs font-mono">
          <div className="flex gap-1" role="radiogroup" aria-label="Entity kind">
            {(['groups', 'software'] as const).map((k) => (
              <button key={k} role="radio" aria-checked={kind === k} onClick={() => set('kind', k)}
                className={`px-3 py-1 uppercase tracking-wider border ${kind === k ? 'bg-matrix-500/20 text-matrix-400 border-matrix-500/40' : 'bg-void-900 text-gray-500 border-void-700 hover:text-white'}`}>
                {k}
              </button>
            ))}
          </div>
          <label className="flex items-center gap-1 text-gray-500">
            sort
            <select value={sort} onChange={(e) => set('sort', e.target.value)} className="bg-void-900 border border-void-700 text-gray-300 px-2 py-1">
              {SORTS.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
            </select>
          </label>
          <label className="flex items-center gap-1 text-gray-500">
            show
            <select value={limit} onChange={(e) => set('limit', e.target.value)} className="bg-void-900 border border-void-700 text-gray-300 px-2 py-1">
              {[20, 40, 80, 150].map((n) => <option key={n} value={n}>{n}</option>)}
            </select>
          </label>
        </div>
      </div>

      {isLoading && <div className="space-y-1">{[...Array(10)].map((_, i) => <SkeletonRow key={i} />)}</div>}
      {error && <EmptyLabel label="HEATMAP_UNAVAILABLE" />}

      {data && (
        <div className="bg-void-850 border border-void-700 overflow-x-auto" style={clipSm}>
          <table className="w-full text-xs border-collapse">
            <thead className="bg-void-900/60 sticky top-0">
              <tr>
                <th className="text-left px-3 py-2 text-[10px] font-display font-semibold text-gray-500 uppercase tracking-wider min-w-[220px]">
                  {kind === 'groups' ? 'Actor' : 'Software'} <span className="text-gray-700 normal-case font-mono">({data.rows.length} of {data.total_entities})</span>
                </th>
                <th className="px-2 py-2 text-[10px] font-display font-semibold text-gray-500 uppercase tracking-wider text-right" title="Techniques with at least one rule anywhere / known techniques">Any</th>
                {data.sources.map((s) => (
                  <th key={s} className="px-1 py-2 text-center" title={`${sourceTheme[s]?.name || s}: covers ${data.source_totals[s]} of the shown ${kind}`}>
                    <div className={`text-[9px] font-mono uppercase ${sourceTheme[s]?.text || 'text-gray-400'}`}>{sourceLabelsShort[s] || s}</div>
                    <div className="text-[9px] font-mono text-gray-600 tabular-nums">{data.source_totals[s]}</div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-void-800">
              {data.rows.map((r) => {
                const anyPct = r.technique_count ? Math.round((r.covered_technique_count / r.technique_count) * 100) : 0;
                return (
                  <tr key={r.id} className="hover:bg-void-800/40" data-testid={`heat-${r.id}`}>
                    <td className="px-3 py-1.5">
                      <Link to={`/actors/${r.id}`} className="text-gray-200 hover:text-matrix-400 font-display">{r.name}</Link>
                      <span className="ml-2 text-[10px] font-mono text-gray-600">{r.id} · {r.technique_count} techs · gap {r.gap_count}</span>
                    </td>
                    <td className={`px-2 py-1.5 text-right font-mono tabular-nums ${heat(anyPct)}`} title={`${r.covered_technique_count} of ${r.technique_count} techniques have a rule somewhere`}>
                      {anyPct}%
                    </td>
                    {data.sources.map((s) => {
                      const cell = r.by_source[s];
                      const pct = cell && r.technique_count ? Math.round((cell.techniques_covered / r.technique_count) * 100) : 0;
                      return (
                        <td key={s} className={`px-1 py-1.5 text-center font-mono tabular-nums ${heat(pct)}`}
                          title={cell ? `${sourceTheme[s]?.name || s}: ${cell.techniques_covered}/${r.technique_count} techniques, ${cell.rule_count} rules` : `${sourceTheme[s]?.name || s}: no rules for any of this entity's techniques`}>
                          {cell ? (
                            <Link to={`/detections?sources=${s}&mitre_groups=${r.id}`} className="block w-full h-full">{pct}%</Link>
                          ) : (
                            <span>-</span>
                          )}
                        </td>
                      );
                    })}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <div className="flex gap-3 text-[10px] font-mono text-gray-500 flex-wrap">
        {[['0%', heat(0)], ['<25%', heat(10)], ['<50%', heat(30)], ['<75%', heat(60)], ['75%+', heat(90)]].map(([l, c]) => (
          <span key={l} className="flex items-center gap-1"><span className={`inline-block w-4 h-3 ${c.split(' ')[0]}`} />{l}</span>
        ))}
        <span className="ml-auto">cells link to the catalog filtered by source; row = share of the entity&apos;s techniques covered</span>
      </div>
    </div>
  );
}
