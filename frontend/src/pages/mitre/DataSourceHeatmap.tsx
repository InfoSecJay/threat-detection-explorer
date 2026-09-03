/**
 * Techniques x data sources: how many rules detect each technique from
 * each log source. Answers "what can I detect with the telemetry I
 * have" -- read a column for a log source you collect.
 */

import { useQuery } from '@tanstack/react-query';
import { Link, useSearchParams } from 'react-router-dom';
import { mitreApi } from '../../services/api';
import { clipSm } from '../../constants/style';
import { SkeletonRow, EmptyLabel } from '../intel/Section';
import { useDocumentMeta } from '../../hooks/useDocumentMeta';
import { DataSourcePicker } from './DataSourcePicker';

function heat(n: number, max: number): string {
  if (n === 0) return 'bg-void-900 text-gray-700';
  const pct = max ? (n / max) * 100 : 0;
  if (pct < 10) return 'bg-breach-500/15 text-breach-300';
  if (pct < 30) return 'bg-amber-500/20 text-amber-200';
  if (pct < 60) return 'bg-lime-500/25 text-lime-200';
  return 'bg-matrix-500/30 text-matrix-200';
}

export function DataSourceHeatmap() {
  useDocumentMeta('Coverage by data source', 'How many detection rules cover each ATT&CK technique from each log source.');
  const [params, setParams] = useSearchParams();
  const limit = Math.min(200, Math.max(5, Number(params.get('limit') ?? 40) || 40));
  const sources = Math.min(60, Math.max(3, Number(params.get('sources') ?? 15) || 15));
  // Explicit column set (#130): `ds=a,b,c` in the URL, order preserved.
  // Absent = top N by volume. Present-but-empty is a legal "no columns".
  const dsParam = params.get('ds');
  const chosen = dsParam === null ? null : dsParam.split(',').map((d) => d.trim()).filter(Boolean);
  const { data, isLoading, error } = useQuery({
    queryKey: ['mitre-ds-matrix', limit, sources, chosen],
    queryFn: () => mitreApi.coverageByDataSource({ limit, sources, data_sources: chosen ?? undefined }),
    staleTime: 1000 * 60 * 10,
  });
  const set = (k: string, v: string | null) => {
    const next = new URLSearchParams(params);
    if (v === null) next.delete(k); else next.set(k, v);
    setParams(next, { replace: true });
  };
  // Empty explicit selection would round-trip as `ds=` -> a query with
  // no columns; keep the columns of the current answer instead so the
  // table never blanks while the user is mid-edit.
  const columns = chosen && chosen.length === 0 ? [] : data?.data_sources ?? [];

  return (
    <div className="space-y-4">
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <Link to="/mitre" className="text-xs font-mono text-gray-500 hover:text-matrix-400">&larr; ATT&amp;CK browser</Link>
          <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase mt-1">Coverage by data source</h1>
          <p className="text-xs text-gray-500 mt-1 font-mono">
            rules per technique from each log source -- read the column for the telemetry you collect; a blank cell is a gap you cannot close with that source
          </p>
        </div>
        <div className="flex items-center gap-3 flex-wrap text-xs font-mono">
          <label className="flex items-center gap-1 text-gray-500">
            techniques
            <select value={limit} onChange={(e) => set('limit', e.target.value)} className="bg-void-900 border border-void-700 text-gray-300 px-2 py-1">
              {[20, 40, 80, 150].map((n) => <option key={n} value={n}>{n}</option>)}
            </select>
          </label>
          {!chosen && (
            <label className="flex items-center gap-1 text-gray-500">
              sources
              <select value={sources} onChange={(e) => set('sources', e.target.value)} className="bg-void-900 border border-void-700 text-gray-300 px-2 py-1">
                {[10, 15, 25, 40].map((n) => <option key={n} value={n}>{n}</option>)}
              </select>
            </label>
          )}
        </div>
      </div>

      {data && (
        <DataSourcePicker
          available={data.available}
          selected={chosen}
          shown={data.data_sources}
          topN={sources}
          onChange={(next) => set('ds', next === null ? null : next.join(','))}
        />
      )}

      {isLoading && <div className="space-y-1">{[...Array(10)].map((_, i) => <SkeletonRow key={i} />)}</div>}
      {error && <EmptyLabel label="MATRIX_UNAVAILABLE" />}

      {data && (
        <div className="bg-void-850 border border-void-700 overflow-x-auto" style={clipSm}>
          <table className="w-full text-xs border-collapse">
            <thead className="bg-void-900/60 sticky top-0">
              <tr>
                <th scope="col" className="text-left px-3 py-2 text-[10px] font-display font-semibold text-gray-500 uppercase tracking-wider min-w-[240px]">
                  Technique <span className="text-gray-700 normal-case font-mono">({data.rows.length} of {data.total_techniques})</span>
                </th>
                <th scope="col" className="px-2 py-2 text-[10px] font-display font-semibold text-gray-500 uppercase tracking-wider text-right">Rules</th>
                {columns.map((ds) => (
                  <th key={ds.id} scope="col" className="px-1 py-2 text-center" title={`${ds.id}: ${ds.rules} technique-rule pairs`}>
                    <div className="text-[9px] font-mono text-cyan-300 break-all max-w-[6rem]">{ds.id}</div>
                    <div className="text-[9px] font-mono text-gray-600 tabular-nums">{ds.rules}</div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-void-800">
              {data.rows.map((r) => {
                const max = Math.max(1, ...Object.values(r.by_data_source));
                return (
                  <tr key={r.technique_id} className="hover:bg-void-800/40" data-testid={`ds-${r.technique_id}`}>
                    <td className="px-3 py-1.5">
                      <Link to={`/mitre/${r.technique_id}`} className="font-mono text-matrix-400 hover:text-matrix-300">{r.technique_id}</Link>
                      <span className="ml-2 text-gray-200">{r.technique_name}</span>
                      {r.tactic && <span className="ml-2 text-[10px] font-mono text-gray-600 uppercase">{r.tactic}</span>}
                    </td>
                    <td className="px-2 py-1.5 text-right font-mono tabular-nums text-white">{r.rules}</td>
                    {columns.map((ds) => {
                      const n = r.by_data_source[ds.id] || 0;
                      return (
                        <td key={ds.id} className={`px-1 py-1.5 text-center font-mono tabular-nums ${heat(n, max)}`}>
                          {n ? (
                            <Link to={`/detections?mitre_techniques=${r.technique_id}&data_sources_normalized=${encodeURIComponent(ds.id)}`} className="block w-full h-full" title={`${n} rule(s) for ${r.technique_id} from ${ds.id}`}>{n}</Link>
                          ) : <span>-</span>}
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
    </div>
  );
}
