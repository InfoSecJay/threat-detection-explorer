/**
 * Observables index: the extracted surfaces (process names, event IDs,
 * paths, registry keys, indicators, API actions, tables, resources)
 * and the most-referenced values on each.
 *
 * One table per surface: value, what it means where we know it, which
 * sources use it (labelled, with counts -- not anonymous dots), and
 * how many rules. Event IDs are grouped by the log they belong to
 * (Security, Sysmon, PowerShell, ...) because an ID without its
 * channel is ambiguous: Sysmon 1 and Security 1 are different events.
 */

import { useMemo } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { useObservableTop, useObservableTypes } from '../hooks/useObservables';
import { useFilterOptions } from '../hooks/useDetections';
import { sourceTheme, clipSm } from '../constants/style';
import { sourceLabelsShort } from '../constants/sources';
import { OBSERVABLE_KIND_LABEL, OBSERVABLE_FILTER_KEY, observableUrl, type ObservableKind } from '../utils/observableLinks';
import { SkeletonRow, EmptyLabel } from './intel/Section';
import type { ObservableTopValue } from '../services/api';

const KINDS = Object.keys(OBSERVABLE_KIND_LABEL) as ObservableKind[];

/** One line per surface saying what the values are, so the table needs no legend. */
const KIND_BLURB: Record<ObservableKind, string> = {
  process: 'image / process names the rule logic tests for',
  path: 'file and directory paths named in the logic',
  registry: 'registry keys and values the rule watches',
  network: 'domains, IPs, URLs and ports used as indicators',
  action: 'cloud / SaaS API actions (CloudTrail, Okta, Entra, GitHub...)',
  eventid: 'Windows event IDs the rule keys on, grouped by the log they come from',
  table: 'SIEM tables and datamodels the query reads from',
  resource: 'targets the rule watches: users, roles, buckets, mailboxes',
};

const PROVIDER_LABEL: Record<string, string> = {
  windows_security: 'Security log',
  sysmon: 'Sysmon',
  windows_defender: 'Windows Defender',
  windows_system: 'System log',
  taskscheduler: 'Task Scheduler',
  powershell: 'PowerShell',
  wmi_activity: 'WMI activity',
  codeintegrity: 'Code Integrity',
};

function SourceChips({ bySource }: { bySource: Record<string, number> }) {
  const entries = Object.entries(bySource);
  const shown = entries.slice(0, 5);
  const rest = entries.slice(5);
  return (
    <div className="flex flex-wrap gap-1">
      {shown.map(([s, n]) => {
        const cfg = sourceTheme[s];
        return (
          <span
            key={s}
            className={`inline-flex items-center gap-1 px-1.5 py-0.5 text-[9px] font-mono uppercase border ${cfg?.text || 'text-gray-400'} ${cfg?.border || 'border-void-700'} bg-void-900`}
            title={`${cfg?.name || s}: ${n} rule${n === 1 ? '' : 's'}`}
          >
            {sourceLabelsShort[s] || s}
            <span className="text-gray-500 tabular-nums">{n}</span>
          </span>
        );
      })}
      {rest.length > 0 && (
        <span className="px-1.5 py-0.5 text-[9px] font-mono text-gray-500 border border-void-700 bg-void-900" title={rest.map(([s, n]) => `${sourceTheme[s]?.name || s}: ${n}`).join(', ')}>
          +{rest.length}
        </span>
      )}
    </div>
  );
}

function ValuesTable({ kind, values, max, offset = 0 }: { kind: ObservableKind; values: ObservableTopValue[]; max: number; offset?: number }) {
  const filterKey = OBSERVABLE_FILTER_KEY[kind];
  return (
    <table className="w-full text-xs">
      <thead className="bg-void-900/60 text-[10px] font-display font-semibold text-gray-500 uppercase tracking-wider">
        <tr>
          <th className="px-3 py-2 text-left w-10">#</th>
          <th className="px-3 py-2 text-left">Value</th>
          <th className="px-3 py-2 text-left">Sources</th>
          <th className="px-3 py-2 text-right w-40">Rules</th>
          <th className="px-3 py-2 w-24" />
        </tr>
      </thead>
      <tbody className="divide-y divide-void-800">
        {values.map((v, i) => (
          <tr key={v.value} className="hover:bg-void-800/40 transition-colors" data-testid={`obs-${v.value}`}>
            <td className="px-3 py-2 font-mono text-gray-600 tabular-nums">{offset + i + 1}</td>
            <td className="px-3 py-2 min-w-0">
              <Link to={observableUrl(kind, v.value)} className="font-mono text-gray-100 hover:text-matrix-400 break-all">
                {v.value}
              </Link>
              {v.context && (
                <div className="text-[11px] text-gray-400 mt-0.5">{v.context.label}</div>
              )}
            </td>
            <td className="px-3 py-2"><SourceChips bySource={v.by_source} /></td>
            <td className="px-3 py-2">
              <div className="flex items-center gap-2 justify-end">
                <div className="w-20 h-1.5 bg-void-900 overflow-hidden">
                  <div className="h-full bg-matrix-500/60" style={{ width: `${Math.max(2, (v.rules / max) * 100)}%` }} />
                </div>
                <span className="font-mono text-white tabular-nums w-10 text-right">{v.rules.toLocaleString()}</span>
              </div>
            </td>
            <td className="px-3 py-2 text-right whitespace-nowrap">
              <Link to={`/detections?${filterKey}=${encodeURIComponent(v.value)}`} className="text-[10px] font-mono text-gray-500 hover:text-matrix-400 uppercase tracking-wider" title="Open the catalog filtered to this value">
                catalog &#8599;
              </Link>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** Event IDs grouped by the log channel they belong to, biggest first. */
function groupByChannel(values: ObservableTopValue[]) {
  const groups = new Map<string, { provider: string; channel: string; values: ObservableTopValue[]; rules: number }>();
  for (const v of values) {
    const key = v.context?.provider || 'unknown';
    const g = groups.get(key) || { provider: key, channel: v.context?.channel || 'Not in the Windows event-ID dictionary', values: [], rules: 0 };
    g.values.push(v);
    g.rules += v.rules;
    groups.set(key, g);
  }
  return [...groups.values()].sort((a, b) => (a.provider === 'unknown' ? 1 : b.provider === 'unknown' ? -1 : b.rules - a.rules));
}

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
  const grouped = useMemo(() => (kind === 'eventid' && data ? groupByChannel(data.values) : null), [kind, data]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">Observables</h1>
        <p className="text-xs text-gray-500 mt-1 font-mono">
          what the rules actually key on, extracted from the detection logic of every source -- click a value for its profile and the rules behind it
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

      <div className="flex items-start justify-between gap-4 flex-wrap">
        <p className="text-xs text-gray-400 font-mono" data-testid="kind-blurb">{KIND_BLURB[kind]}</p>
        {sources.length > 0 && (
          <div className="flex items-center gap-1 flex-wrap">
            <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider mr-1">only:</span>
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
      </div>

      {isLoading && <div className="space-y-1">{[...Array(12)].map((_, i) => <SkeletonRow key={i} />)}</div>}
      {error && <EmptyLabel label="UNAVAILABLE" />}
      {data && data.values.length === 0 && <EmptyLabel label="NO_VALUES_ON_THIS_SURFACE" />}

      {data && data.values.length > 0 && !grouped && (
        <div className="bg-void-850 border border-void-700 overflow-x-auto" style={clipSm}>
          <div className="px-3 py-2 border-b border-void-700 bg-void-900/40 flex items-baseline justify-between">
            <h2 className="font-display font-semibold text-[11px] uppercase tracking-wider text-matrix-400">
              Top {OBSERVABLE_KIND_LABEL[kind].toLowerCase()} values{source ? ` in ${sourceTheme[source]?.name || source}` : ''}
            </h2>
            <span className="text-[10px] font-mono text-gray-600">{data.distinct.toLocaleString()} distinct · showing {data.values.length}</span>
          </div>
          <ValuesTable kind={kind} values={data.values} max={max} />
        </div>
      )}

      {grouped && (
        <div className="space-y-4">
          {grouped.map((g) => (
            <div key={g.provider} className="bg-void-850 border border-void-700 overflow-x-auto" style={clipSm} data-testid={`channel-${g.provider}`}>
              <div className="px-3 py-2 border-b border-void-700 bg-void-900/40 flex items-baseline justify-between gap-3 flex-wrap">
                <div className="flex items-baseline gap-2">
                  <h2 className="font-display font-semibold text-[11px] uppercase tracking-wider text-matrix-400">
                    {PROVIDER_LABEL[g.provider] || (g.provider === 'unknown' ? 'Unrecognised IDs' : g.provider)}
                  </h2>
                  <span className="text-[10px] font-mono text-gray-500">{g.channel}</span>
                </div>
                <span className="text-[10px] font-mono text-gray-600">{g.values.length} IDs · {g.rules.toLocaleString()} rules</span>
              </div>
              <ValuesTable kind={kind} values={g.values} max={max} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
