/**
 * "What we count" (#32): per-source scope rendered from /api/methodology,
 * which reads the ingester's own discovery config -- so this table
 * cannot drift from what the sync actually does. Rule counts differ
 * between aggregator sites because each makes different scope choices;
 * this is ours, stated.
 */

import { useQuery } from '@tanstack/react-query';
import { methodologyApi } from '../services/api';
import { sourceLabels } from '../constants/sources';
import { sourceTheme } from '../constants/style';
import { clipLg } from '../constants/style';
import { formatRelDate } from '../pages/intel/lib';

function Globs({ items }: { items: string[] }) {
  if (!items.length) return <span className="text-gray-600">-</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {items.map((g) => (
        <code key={g} className="px-1 py-0.5 bg-void-900 border border-void-700 text-[10px] font-mono text-gray-300 whitespace-nowrap">
          {g}
        </code>
      ))}
    </div>
  );
}

export function MethodologySection() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['methodology'],
    queryFn: methodologyApi.get,
    staleTime: 1000 * 60 * 30,
  });

  return (
    <section>
      <div className="bg-void-850 border border-void-700 p-8" style={clipLg}>
        <div className="flex items-center gap-4 mb-2">
          <h2 className="text-xl font-display font-bold text-white tracking-wider uppercase">
            What We Count
          </h2>
          <div className="flex-1 h-px bg-gradient-to-r from-void-700 to-transparent" />
        </div>
        <p className="text-sm text-gray-400 mb-6">
          Rule counts differ between aggregator sites because every site makes different scope choices.
          These are ours. Every row is generated from the same discovery configuration the nightly sync
          uses, and each count is reproducible from the pinned commit alone.
        </p>

        {isLoading && <div className="text-xs font-mono text-gray-500 animate-pulse">LOADING_METHODOLOGY...</div>}
        {error && (
          <div className="text-xs font-mono text-breach-400" role="alert">
            Methodology unavailable: {(error as Error).message}
          </div>
        )}

        {data && (
          <>
            <ul className="mb-6 space-y-1.5 text-sm text-gray-300">
              {data.principles.map((p) => (
                <li key={p} className="flex gap-2">
                  <span className="text-matrix-500 shrink-0">&gt;</span>
                  <span>{p}</span>
                </li>
              ))}
            </ul>

            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead className="bg-void-900">
                  <tr className="text-left text-[10px] font-display font-semibold text-gray-500 uppercase tracking-wider">
                    <th className="px-3 py-2">Source</th>
                    <th className="px-3 py-2">Upstream</th>
                    <th className="px-3 py-2">License</th>
                    <th className="px-3 py-2">Included</th>
                    <th className="px-3 py-2">Excluded dirs</th>
                    <th className="px-3 py-2">Scope</th>
                    <th className="px-3 py-2 text-right">Rules</th>
                    <th className="px-3 py-2">Pinned</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-void-800 align-top">
                  {data.sources.map((s) => {
                    const cfg = sourceTheme[s.name];
                    const repoPath = s.url ? s.url.replace(/^https:\/\/github\.com\//, '').replace(/\.git$/, '') : null;
                    return (
                      <tr key={s.name} className="hover:bg-void-800/50">
                        <td className="px-3 py-2 whitespace-nowrap">
                          <span className="inline-flex items-center gap-1.5">
                            <span className={`w-2 h-2 rounded-full ${cfg?.dot || 'bg-gray-500'}`} />
                            <span className={`font-mono ${cfg?.text || 'text-gray-300'}`}>{sourceLabels[s.name] || s.name}</span>
                          </span>
                        </td>
                        <td className="px-3 py-2 whitespace-nowrap">
                          {s.url ? (
                            <a href={s.url} target="_blank" rel="noopener noreferrer" className="font-mono text-gray-300 hover:text-matrix-400">
                              {repoPath}
                            </a>
                          ) : (
                            <span className="text-gray-600">-</span>
                          )}
                          <span className="font-mono text-gray-600"> @{s.branch}</span>
                          {s.sparse_checkout && (
                            <span className="ml-1 text-[9px] font-mono text-gray-600 uppercase" title={`sparse checkout: ${s.sparse_checkout.join(', ')}`}>
                              sparse
                            </span>
                          )}
                        </td>
                        <td className="px-3 py-2 whitespace-nowrap">
                          {s.license ? (
                            <a href={s.license.url} target="_blank" rel="noopener noreferrer" className="font-mono text-gray-300 hover:text-matrix-400" title={s.license.note || s.license.name}>
                              {s.license.spdx}
                            </a>
                          ) : (
                            <span className="text-gray-600">-</span>
                          )}
                        </td>
                        <td className="px-3 py-2 min-w-[180px]"><Globs items={s.include_patterns} /></td>
                        <td className="px-3 py-2 min-w-[140px]"><Globs items={s.exclude_dirs.filter((d) => d !== '.git')} /></td>
                        <td className="px-3 py-2 text-gray-400 min-w-[260px]">{s.scope_notes}</td>
                        <td className="px-3 py-2 text-right font-mono text-white tabular-nums whitespace-nowrap">
                          {s.rule_count === null ? '-' : s.rule_count.toLocaleString()}
                        </td>
                        <td className="px-3 py-2 whitespace-nowrap font-mono text-gray-500">
                          {s.last_commit_hash ? (
                            <a
                              href={s.url ? `${s.url.replace(/\.git$/, '')}/tree/${s.last_commit_hash}` : undefined}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="hover:text-matrix-400"
                              title={`synced ${formatRelDate(s.last_sync_at)}`}
                            >
                              {s.last_commit_hash.slice(0, 8)}
                            </a>
                          ) : (
                            '-'
                          )}
                          <span className="text-gray-700"> · {formatRelDate(s.last_sync_at)}</span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </section>
  );
}
