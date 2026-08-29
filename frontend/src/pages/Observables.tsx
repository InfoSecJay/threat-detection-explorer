/**
 * Observables index: the extracted surfaces (process names, event IDs,
 * paths, registry keys, indicators, API actions, tables, resources)
 * and the most-referenced values on each, with rule and source counts.
 * Every value links to its profile page.
 */

import { Link, useParams, useSearchParams } from 'react-router-dom';
import { useObservableTop, useObservableTypes } from '../hooks/useObservables';
import { useFilterOptions } from '../hooks/useDetections';
import { sourceTheme, clipSm } from '../constants/style';
import { OBSERVABLE_KIND_LABEL, observableUrl, type ObservableKind } from '../utils/observableLinks';
import { SkeletonRow, EmptyLabel } from './intel/Section';

const KINDS = Object.keys(OBSERVABLE_KIND_LABEL) as ObservableKind[];

export function Observables() {
  const { kind: kindParam } = useParams<{ kind?: string }>();
  const kind = (KINDS.includes(kindParam as ObservableKind) ? kindParam : 'process') as ObservableKind;
  const [searchParams, setSearchParams] = useSearchParams();
  const source = searchParams.get('source') || undefined;
  const { data: types } = useObservableTypes();
  const { data, isLoading, error } = useObservableTop(kind, 150, source);
  const { data: options } = useFilterOptions();
  const sources = options?.sources || [];
  const max = data?.values?.[0]?.rules || 1;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">Observables</h1>
        <p className="text-xs text-gray-500 mt-1 font-mono">
          what the rules actually key on -- process names, event IDs, paths, keys, indicators, API actions -- across every source
        </p>
      </div>

      <div className="flex gap-1 flex-wrap" role="tablist" aria-label="Observable type">
        {KINDS.map((k) => {
          const meta = types?.types.find((t) => t.type === k);
          return (
            <Link
              key={k}
              to={`/observables/${k}${source ? `?source=${source}` : ''}`}
              role="tab"
              aria-selected={k === kind}
              className={`px-3 py-1.5 text-xs font-mono uppercase tracking-wider border transition-colors ${
                k === kind ? 'bg-matrix-500/20 text-matrix-400 border-matrix-500/40' : 'bg-void-900 text-gray-500 border-void-700 hover:text-white'
              }`}
              style={clipSm}
            >
              {OBSERVABLE_KIND_LABEL[k]}
              {meta && <span className="ml-1.5 text-[10px] text-gray-600 tabular-nums">{meta.distinct.toLocaleString()}</span>}
            </Link>
          );
        })}
      </div>

      {sources.length > 0 && (
        <div className="flex items-center gap-1 flex-wrap">
          <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider mr-1">src:</span>
          {sources.map((s) => {
            const cfg = sourceTheme[s];
            const active = source === s;
            return (
              <button
                key={s}
                onClick={() => {
                  const next = new URLSearchParams(searchParams);
                  if (active) next.delete('source'); else next.set('source', s);
                  setSearchParams(next, { replace: true });
                }}
                className={`px-2 py-0.5 text-[10px] font-mono uppercase transition-colors border ${
                  active ? `${cfg?.bg || 'bg-matrix-500/20'} ${cfg?.text || 'text-matrix-400'} ${cfg?.border || 'border-matrix-500/30'}` : 'bg-void-800 text-gray-400 border-void-600 hover:text-white'
                }`}
              >
                {cfg?.name || s}
              </button>
            );
          })}
        </div>
      )}

      <div className="bg-void-850 border border-void-700" style={clipSm}>
        <div className="px-3 py-2 border-b border-void-700 bg-void-900/40 flex items-baseline justify-between">
          <h2 className="font-display font-semibold text-[11px] uppercase tracking-wider text-matrix-400">
            Top {OBSERVABLE_KIND_LABEL[kind].toLowerCase()} values{source ? ` in ${sourceTheme[source]?.name || source}` : ''}
          </h2>
          {data && <span className="text-[10px] font-mono text-gray-600">{data.distinct.toLocaleString()} distinct</span>}
        </div>
        <div className="p-2">
          {isLoading && <div className="space-y-1">{[...Array(12)].map((_, i) => <SkeletonRow key={i} />)}</div>}
          {error && <EmptyLabel label="UNAVAILABLE" />}
          {data && data.values.length === 0 && <EmptyLabel label="NO_VALUES_ON_THIS_SURFACE" />}
          {data && data.values.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-1">
              {data.values.map((v, i) => (
                <Link key={v.value} to={observableUrl(kind, v.value)} className="block group" data-testid={`obs-${i}`}>
                  <div className="relative bg-void-800/60 border border-void-700 hover:border-matrix-500/40 px-2.5 py-1.5 transition-colors">
                    <div className="absolute inset-y-0 left-0 bg-matrix-500/10" style={{ width: `${(v.rules / max) * 100}%` }} />
                    <div className="relative flex items-center gap-2 text-xs">
                      <span className="text-[10px] font-mono text-gray-600 w-6 shrink-0">{i + 1}.</span>
                      <span className="font-mono text-gray-200 truncate min-w-0 flex-1 group-hover:text-matrix-400">{v.value}</span>
                      <div className="flex gap-0.5 shrink-0">
                        {v.sources.slice(0, 6).map((s) => <span key={s} className={`w-1.5 h-1.5 rounded-full ${sourceTheme[s]?.dot || 'bg-gray-500'}`} title={s} />)}
                      </div>
                      <span className="font-mono text-white tabular-nums w-12 text-right shrink-0">{v.rules.toLocaleString()}</span>
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
