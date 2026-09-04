/**
 * /methodology/unclassified -- the burn-down (teardown R14 / #112).
 *
 * The methodology page promises `unknown` over a guess. This page is
 * the cost of that promise made visible: one table, sources down,
 * normalized fields across, each cell the count of rules that did not
 * resolve -- and a link straight to those rules in the catalog, so a
 * cell is a work item, not a statistic. Above it, the totals trending
 * nightly so the backlog is seen to move.
 */

import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { methodologyApi, type UnclassifiedHistoryPoint } from '../services/api';
import { useDocumentMeta } from '../hooks/useDocumentMeta';
import { sourceLabels } from '../constants/sources';
import { clipMd, clipSm } from '../constants/style';

const FIELD_LABEL: Record<string, string> = {
  platforms: 'Platform',
  domains: 'Domain',
  data_sources: 'Data source',
  event_types: 'Event type',
  status: 'Status',
  severity: 'Severity',
  language: 'Language',
  mitre_techniques: 'ATT&CK',
};

const FIELD_HINT: Record<string, string> = {
  platforms: 'Rules whose vendor logsource has no platform mapping',
  domains: 'Rules whose platform and data sources place them in no attack-surface domain (#103); the application-domain candidates live here',
  data_sources: 'Rules whose vendor logsource has no canonical data-source mapping',
  event_types: 'Rules whose observed-event category could not be determined',
  status: 'Rules whose maturity is not published (sources with no lifecycle concept say not applicable, and are not counted)',
  severity: 'Rules whose vendor publishes no severity',
  language: 'Rules whose query language could not be detected',
  mitre_techniques: 'Rules with no ATT&CK technique, declared or derived',
};

function pct(n: number, of: number): string {
  if (!of) return '0%';
  const v = (100 * n) / of;
  return v < 1 && v > 0 ? '<1%' : `${Math.round(v)}%`;
}

/** Inline sparkline of one field's daily total; width scales with points. */
function Sparkline({ points, field }: { points: UnclassifiedHistoryPoint[]; field: string }) {
  const values = points.map((p) => p.fields[field] ?? 0);
  if (values.length < 2) return <span className="text-[10px] font-mono text-gray-600">history starts tonight</span>;
  const max = Math.max(...values, 1);
  const w = 120;
  const h = 24;
  const step = w / (values.length - 1);
  const d = values.map((v, i) => `${i === 0 ? 'M' : 'L'}${(i * step).toFixed(1)},${(h - (v / max) * (h - 2) - 1).toFixed(1)}`).join(' ');
  const first = values[0];
  const last = values[values.length - 1];
  const delta = last - first;
  return (
    <span className="inline-flex items-center gap-2" title={`${first} -> ${last} over ${values.length} days`}>
      <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} aria-hidden="true">
        <path d={d} fill="none" stroke={delta > 0 ? '#f87171' : '#00ffcc'} strokeWidth="1.5" />
      </svg>
      <span className={`text-[10px] font-mono tabular-nums ${delta > 0 ? 'text-breach-400' : delta < 0 ? 'text-matrix-400' : 'text-gray-500'}`}>
        {delta > 0 ? '+' : ''}{delta}
      </span>
    </span>
  );
}

export function Unclassified() {
  useDocumentMeta(
    'Unclassified rules',
    'What the normalizer could not place: unknown platform, data source, event type, status, severity, language and ATT&CK mapping, by source, trending nightly.',
  );
  const { data, isLoading, error } = useQuery({ queryKey: ['methodology', 'unclassified'], queryFn: methodologyApi.unclassified, staleTime: 15 * 60 * 1000 });

  const history = useMemo(() => data?.history ?? [], [data]);

  return (
    <div className="space-y-6 max-w-6xl mx-auto" data-testid="unclassified-page">
      <div>
        <Link to="/methodology" className="text-xs font-mono text-gray-500 hover:text-matrix-400">&larr; Methodology</Link>
        <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase mt-2">Unclassified rules</h1>
        <p className="text-sm text-gray-400 mt-2 max-w-3xl">
          Rules the normalizer could not place show <span className="font-mono">unknown</span> rather than a guess. This is
          the running cost of that rule: every cell is the number of rules in that source with no answer for that field,
          and links to them in the catalog. Counts are recomputed nightly; the trend is the backlog burning down -- or not.
        </p>
      </div>

      {error && (
        <div className="bg-breach-500/10 border border-breach-500/30 p-4" style={clipMd}>
          <p className="text-breach-400 font-mono text-sm">ERROR: could not load the unclassified report.</p>
        </div>
      )}

      {data && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3" data-testid="unclassified-totals">
            {data.fields.map((f) => (
              <div key={f} className="bg-void-850 border border-void-700 p-3" style={clipSm} title={FIELD_HINT[f]}>
                <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">{FIELD_LABEL[f] || f}</div>
                <div className="text-xl font-display font-bold text-white tabular-nums">{data.totals[f].toLocaleString()}</div>
                <div className="text-[10px] font-mono text-gray-500">{pct(data.totals[f], data.total_rules)} of {data.total_rules.toLocaleString()}</div>
                <div className="mt-1"><Sparkline points={history} field={f} /></div>
              </div>
            ))}
          </div>

          <div className="bg-void-850 border border-void-700 overflow-x-auto" style={clipMd}>
            <table className="w-full text-xs font-mono" data-testid="unclassified-table">
              <thead>
                <tr className="text-gray-500 uppercase tracking-wider text-[10px] border-b border-void-700">
                  <th className="text-left px-3 py-2">Source</th>
                  <th className="text-right px-3 py-2">Rules</th>
                  {data.fields.map((f) => (
                    <th key={f} className="text-right px-3 py-2" title={FIELD_HINT[f]}>{FIELD_LABEL[f] || f}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.sources.map((s) => (
                  <tr key={s.source} className="border-b border-void-800 hover:bg-void-800/50">
                    <td className="px-3 py-2 text-gray-200">{sourceLabels[s.source] || s.source}</td>
                    <td className="px-3 py-2 text-right text-gray-400 tabular-nums">{s.total_rules.toLocaleString()}</td>
                    {data.fields.map((f) => {
                      const n = s.fields[f] ?? 0;
                      const key = data.catalog_filter_key[f];
                      const cell = n === 0
                        ? <span className="text-gray-700">0</span>
                        : key
                          ? <Link to={`/detections?sources=${s.source}&${key}=unknown`} className="text-breach-400 hover:text-breach-300 underline decoration-dotted" title={`Open the ${n} ${sourceLabels[s.source] || s.source} rules with unknown ${FIELD_LABEL[f] || f}`}>{n.toLocaleString()}</Link>
                          : <span className="text-breach-400">{n.toLocaleString()}</span>;
                      return <td key={f} className="px-3 py-2 text-right tabular-nums">{cell}</td>;
                    })}
                  </tr>
                ))}
                <tr className="border-t border-void-600 text-gray-300">
                  <td className="px-3 py-2 uppercase tracking-wider text-[10px]">Total</td>
                  <td className="px-3 py-2 text-right tabular-nums">{data.total_rules.toLocaleString()}</td>
                  {data.fields.map((f) => (
                    <td key={f} className="px-3 py-2 text-right tabular-nums">{data.totals[f].toLocaleString()}</td>
                  ))}
                </tr>
              </tbody>
            </table>
          </div>

          <p className="text-xs font-mono text-gray-600">
            Status counts exclude sources with no lifecycle concept (<span className="text-gray-500">not applicable</span>) and
            language excludes rules with no query (<span className="text-gray-500">none</span>): those are answers, not gaps.
            Mapping files live in the repo -- a cell here is a PR waiting to happen.
          </p>
        </>
      )}

      {isLoading && <p className="text-xs font-mono text-gray-500">loading ...</p>}
    </div>
  );
}
