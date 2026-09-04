/**
 * Compare (#11): an observable-level diff of 2-6 rules.
 *
 * The old side-by-side listed metadata columns. This page answers the
 * question a detection engineer actually has when two rules claim the
 * same technique: what does each one KEY ON? One row per observable
 * value with a cell per rule -- present (and on which vendor field),
 * excluded, or absent -- then the same matrix for techniques, data
 * sources, platforms, event types, source tables and fields.
 *
 * Rules arrive as ?ids=a,b,c from the catalog's row selection or a
 * rule page's related-rules panel, so a comparison is a shareable URL.
 */

import { useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useCompareDiff } from '../hooks/useCompare';
import { useDocumentMeta } from '../hooks/useDocumentMeta';
import { useMitre } from '../contexts/MitreContext';
import { sourceTheme, clipSm, clipMd } from '../constants/style';
import { severityColor } from './intel/lib';
import { qualityBand } from '../components/rulelist/format';
import { AXIS_LABEL, diffToMarkdown } from '../utils/compareMarkdown';
import type { CompareDiffAxis, CompareDiffObservable, CompareDiffResponse } from '../services/api';

const MAX_RULES = 6;

const TYPE_LABEL: Record<string, string> = {
  process: 'Process', file: 'File', registry: 'Registry', network: 'Network', dns: 'DNS', email: 'Email',
  cloud: 'Cloud', identity: 'Identity', authentication: 'Authentication', endpoint: 'Endpoint', event: 'Event', other: 'Other',
};

const AXES: CompareDiffAxis[] = [
  'mitre_techniques', 'mitre_tactics', 'data_sources', 'platforms', 'event_types', 'source_tables', 'fields',
];

type View = 'all' | 'shared' | 'differences';

function srcName(src: string): string {
  return sourceTheme[src]?.name || src;
}

function parseIds(raw: string | null): string[] {
  return Array.from(new Set((raw || '').split(',').map((s) => s.trim()).filter(Boolean))).slice(0, MAX_RULES);
}

/** One matrix cell: present (with the vendor field), an exclusion, or absent. */
function Cell({ present, negated, fields }: { present: boolean; negated: boolean; fields?: string[] }) {
  if (!present) return <td className="px-3 py-1.5 text-center text-gray-700 font-mono text-xs">&middot;</td>;
  return (
    <td className="px-3 py-1.5 text-center align-top">
      {negated ? (
        <span className="px-1.5 py-0.5 text-[10px] font-mono font-bold uppercase bg-breach-500/20 text-breach-400 border border-breach-500/40 rounded" title="Exclusion: the rule does NOT match this value">NOT</span>
      ) : (
        <span className="text-matrix-400 font-mono text-sm" aria-label="present">{'✓'}</span>
      )}
      {fields && fields.length > 0 && (
        <div className="text-[10px] font-mono text-gray-500 mt-0.5 break-all" title="Source field the rule tests this value on">{fields.join(', ')}</div>
      )}
    </td>
  );
}

function CopyMarkdownButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      /* clipboard blocked: the textarea below is still selectable */
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <button type="button" onClick={copy} className="px-3 py-1.5 text-xs font-display font-semibold uppercase tracking-wider border bg-void-900 text-gray-300 border-void-700 hover:text-white hover:border-void-600 transition-colors" style={clipSm} data-testid="copy-markdown">
      {copied ? 'Copied' : 'Copy as Markdown'}
    </button>
  );
}

function Landing() {
  return (
    <div className="max-w-2xl space-y-4" data-testid="compare-landing">
      <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">Compare rules</h1>
      <p className="text-sm text-gray-300 leading-relaxed">
        Pick two to six rules and see what each one keys on: every process name, path, registry key,
        API action and event ID the logic tests, side by side, with the vendor field it tests it on.
        Exclusions are marked, so a rule that matches what another excludes stands out.
      </p>
      <ul className="text-sm text-gray-400 space-y-2 list-disc pl-5">
        <li>In the <Link to="/detections" className="text-matrix-500 hover:text-matrix-400">catalog</Link>, tick the rows you want and press <span className="font-mono text-gray-300">COMPARE</span>.</li>
        <li>On any rule page, the <span className="font-mono text-gray-300">diff</span> link next to a related rule compares the two.</li>
        <li>Or build the URL yourself: <span className="font-mono text-gray-300">/compare?ids=&lt;id&gt;,&lt;id&gt;</span>. The same matrix is available as JSON at <span className="font-mono text-gray-300">/api/v1/compare/diff?ids=</span>.</li>
      </ul>
    </div>
  );
}

function ObservableRows({ rows, ids }: { rows: CompareDiffObservable[]; ids: string[] }) {
  const groups = new Map<string, CompareDiffObservable[]>();
  for (const o of rows) {
    if (!groups.has(o.type)) groups.set(o.type, []);
    groups.get(o.type)!.push(o);
  }
  return (
    <>
      {Array.from(groups.entries()).map(([type, items]) => (
        <tbody key={type} data-testid={`diff-group-${type}`}>
          <tr className="bg-void-900/60">
            <th scope="rowgroup" colSpan={ids.length + 1} className="px-3 py-1 text-left text-[10px] font-display font-semibold uppercase tracking-wider text-gray-400">
              {TYPE_LABEL[type] || type} <span className="text-gray-600 font-mono normal-case">{items.length}</span>
            </th>
          </tr>
          {items.map((o) => (
            <tr key={`${o.type}|${o.subtype}|${o.value}`} className={`border-t border-void-800 ${o.shared ? '' : 'bg-void-850/40'}`} data-testid={`diff-row-${o.value}`}>
              <th scope="row" className="px-3 py-1.5 text-left font-normal">
                <span className="font-mono text-xs text-gray-100 break-all">{o.value}</span>
                <span className="ml-2 text-[10px] font-mono text-gray-600">{o.subtype.replace(/_/g, ' ')}</span>
              </th>
              {ids.map((id) => (
                <Cell key={id} present={o.present_in.includes(id)} negated={o.negated_in.includes(id)} fields={o.fields[id]} />
              ))}
            </tr>
          ))}
        </tbody>
      ))}
    </>
  );
}

function AxisRows({ d, ids, view, techniqueName }: { d: CompareDiffResponse; ids: string[]; view: View; techniqueName: (id: string) => string }) {
  return (
    <>
      {AXES.map((axis) => {
        const rows = (d.axes[axis] ?? []).filter((r) => {
          const shared = r.present_in.length === ids.length;
          return view === 'all' || (view === 'shared' ? shared : !shared);
        });
        if (rows.length === 0) return null;
        return (
          <tbody key={axis} data-testid={`diff-axis-${axis}`}>
            <tr className="bg-void-900/60">
              <th scope="rowgroup" colSpan={ids.length + 1} className="px-3 py-1 text-left text-[10px] font-display font-semibold uppercase tracking-wider text-gray-400">
                {AXIS_LABEL[axis]} <span className="text-gray-600 font-mono normal-case">{rows.length}</span>
              </th>
            </tr>
            {rows.map((r) => (
              <tr key={r.value} className="border-t border-void-800">
                <th scope="row" className="px-3 py-1.5 text-left font-normal">
                  {axis === 'mitre_techniques' ? (
                    <Link to={`/mitre/${r.value}`} className="font-mono text-xs text-matrix-400 hover:text-matrix-300">
                      {r.value}<span className="ml-2 text-gray-400 font-sans">{techniqueName(r.value)}</span>
                    </Link>
                  ) : (
                    <span className="font-mono text-xs text-gray-100 break-all">{r.value}</span>
                  )}
                </th>
                {ids.map((id) => <Cell key={id} present={r.present_in.includes(id)} negated={false} />)}
              </tr>
            ))}
          </tbody>
        );
      })}
    </>
  );
}

export function Compare() {
  const [searchParams, setSearchParams] = useSearchParams();
  const ids = useMemo(() => parseIds(searchParams.get('ids')), [searchParams]);
  const { data, isLoading, error } = useCompareDiff(ids);
  const { getTechniqueName } = useMitre();
  const [view, setView] = useState<View>('all');
  useDocumentMeta('Compare rules', 'Observable-level diff of detection rules across vendors.');

  const origin = typeof window !== 'undefined' ? window.location.origin : '';
  const markdown = useMemo(() => (data ? diffToMarkdown(data, origin, srcName) : ''), [data, origin]);

  if (ids.length < 2) return <Landing />;

  const remove = (id: string) => setSearchParams({ ids: ids.filter((i) => i !== id).join(',') });

  if (error) {
    const status = (error as { response?: { status?: number } }).response?.status;
    return (
      <div className="max-w-2xl space-y-3" data-testid="compare-error">
        <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">Compare rules</h1>
        <p className="text-sm text-breach-400 font-mono">
          {status === 404 ? 'Fewer than two of these rule ids exist any more.' : `Could not load the comparison (${(error as Error).message}).`}
        </p>
        <Link to="/compare" className="text-matrix-500 hover:text-matrix-400 text-sm">Start over</Link>
      </div>
    );
  }
  if (isLoading || !data) {
    return <p className="text-sm font-mono text-gray-500" data-testid="compare-loading">LOADING_COMPARISON...</p>;
  }

  const ruleIds = data.rules.map((r) => r.id);
  const visible = data.observables.filter((o) => view === 'all' || (view === 'shared' ? o.shared : !o.shared));

  return (
    <div className="space-y-5" data-testid="compare-page">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">Compare rules</h1>
          <p className="text-xs font-mono text-gray-500 mt-1">
            what each rule keys on, side by side &middot; {data.rules.length} rules
            {data.missing_ids && data.missing_ids.length > 0 && (
              <span className="text-amber-400 ml-2" data-testid="compare-missing">{data.missing_ids.length} id{data.missing_ids.length === 1 ? '' : 's'} not found and skipped</span>
            )}
          </p>
        </div>
        <CopyMarkdownButton text={markdown} />
      </div>

      {/* Rule cards: one column each, same order as the matrix. */}
      <div className="grid gap-3" style={{ gridTemplateColumns: `repeat(${data.rules.length}, minmax(0, 1fr))` }}>
        {data.rules.map((r, i) => {
          const cfg = sourceTheme[r.source];
          return (
            <div key={r.id} className="bg-void-850 border border-void-700 p-3 min-w-0" style={clipSm} data-testid={`compare-rule-${r.id}`}>
              <div className="flex items-center gap-2 mb-1.5">
                <span className="font-mono text-[10px] text-gray-500">R{i + 1}</span>
                <span className={`px-1.5 py-0.5 text-[9px] font-mono uppercase tracking-wider border ${cfg?.text || 'text-gray-400'} ${cfg?.border || 'border-void-700'}`}>{srcName(r.source)}</span>
                <span className={`font-mono text-[10px] uppercase ${severityColor[r.severity] || 'text-gray-400'}`}>{r.severity}</span>
                <span className="flex-1" />
                {data.rules.length > 2 && (
                  <button type="button" onClick={() => remove(r.id)} className="text-gray-600 hover:text-white font-mono text-xs" title="Remove from the comparison" aria-label={`Remove ${r.title}`}>x</button>
                )}
              </div>
              <Link to={`/detections/${r.id}`} className="text-sm text-gray-100 hover:text-matrix-400 font-medium line-clamp-2">{r.title}</Link>
              <div className="mt-1.5 flex items-center gap-2 text-[11px] font-mono text-gray-500 flex-wrap">
                <span>{r.language}</span>
                {r.query_complexity && <span>{r.query_complexity}</span>}
                {typeof r.quality_score === 'number' && <span className={`px-1 border rounded ${qualityBand(r.quality_score)}`} title="Metadata completeness">{r.quality_score}</span>}
                <span className="flex-1" />
                <span title="Observable values extracted from the logic">{r.observable_count} obs</span>
                <span title="Observables no other compared rule has" className="text-gray-400">{data.summary.unique_by_rule[r.id] ?? 0} unique</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Verdict line + contradictions: the one-glance answer. */}
      <div className="bg-void-850 border border-void-700 px-4 py-3 space-y-2" style={clipSm} data-testid="compare-summary">
        <p className="text-sm text-gray-200">
          <span className="font-mono text-white">{data.summary.observables}</span> distinct observables,{' '}
          <span className="font-mono text-matrix-400">{data.summary.shared_by_all}</span> shared by every rule.
          {data.summary.shared_techniques.length > 0 ? (
            <> All {data.rules.length} map to {data.summary.shared_techniques.map((t) => <Link key={t} to={`/mitre/${t}`} className="font-mono text-matrix-400 hover:text-matrix-300 ml-1">{t}</Link>)}.</>
          ) : (
            <span className="text-amber-300"> No technique is shared by every rule.</span>
          )}
        </p>
        {data.summary.contradictions.length > 0 && (
          <ul className="text-xs text-gray-300 space-y-1" data-testid="compare-contradictions">
            {data.summary.contradictions.map((c) => {
              const name = (id: string) => `R${ruleIds.indexOf(id) + 1}`;
              return (
                <li key={`${c.type}|${c.subtype}|${c.value}`}>
                  <span className="px-1.5 py-0.5 text-[10px] font-mono font-bold uppercase bg-breach-500/20 text-breach-400 border border-breach-500/40 rounded mr-2">contradiction</span>
                  <span className="font-mono text-gray-100">{c.value}</span> is matched by {c.matched_in.map(name).join(', ')} but excluded by {c.excluded_in.map(name).join(', ')}.
                </li>
              );
            })}
          </ul>
        )}
      </div>

      <div className="flex items-center gap-2 text-xs font-mono">
        <span className="text-gray-500 uppercase tracking-wider">show:</span>
        {(['all', 'shared', 'differences'] as View[]).map((v) => (
          <button key={v} type="button" onClick={() => setView(v)} aria-pressed={view === v}
            className={`px-2 py-1 border uppercase tracking-wider ${view === v ? 'bg-matrix-500/10 text-matrix-400 border-matrix-500/40' : 'text-gray-400 border-void-700 hover:text-white'}`} data-testid={`view-${v}`}>
            {v}
          </button>
        ))}
      </div>

      <div className="bg-void-850 border border-void-700 overflow-x-auto" style={clipMd}>
        <table className="min-w-full text-sm" data-testid="compare-matrix">
          <thead className="bg-void-900">
            <tr>
              <th scope="col" className="px-3 py-2 text-left text-[10px] font-mono uppercase tracking-wider text-gray-500 w-[40%]">Observable</th>
              {data.rules.map((r, i) => (
                <th key={r.id} scope="col" className="px-3 py-2 text-center text-[10px] font-mono uppercase tracking-wider text-gray-400" title={r.title}>
                  R{i + 1} <span className="text-gray-600 normal-case">{srcName(r.source)}</span>
                </th>
              ))}
            </tr>
          </thead>
          {visible.length === 0 ? (
            <tbody>
              <tr><td colSpan={ruleIds.length + 1} className="px-3 py-4 text-center text-xs font-mono text-gray-500" data-testid="diff-empty">
                {data.observables.length === 0 ? 'NO_OBSERVABLES_EXTRACTED_FOR_THESE_RULES' : view === 'shared' ? 'NOTHING_SHARED_BY_EVERY_RULE' : 'NO_DIFFERENCES'}
              </td></tr>
            </tbody>
          ) : (
            <ObservableRows rows={visible} ids={ruleIds} />
          )}
          <AxisRows d={data} ids={ruleIds} view={view} techniqueName={getTechniqueName} />
        </table>
      </div>

      <details className="bg-void-850 border border-void-700" style={clipSm}>
        <summary className="px-4 py-2 text-[11px] font-mono uppercase tracking-wider text-gray-400 cursor-pointer hover:text-white">Markdown</summary>
        <textarea readOnly aria-label="Comparison as Markdown" value={markdown} className="w-full h-64 bg-void-900 text-xs font-mono text-gray-300 p-3 border-t border-void-700" />
      </details>
    </div>
  );
}
