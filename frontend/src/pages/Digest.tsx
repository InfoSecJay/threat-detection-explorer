/**
 * Weekly digest -- a dated, shareable page of what changed in the
 * corpus: totals, net change per source, techniques newly covered,
 * momentum, the newest rules, and the data sources gaining rules.
 * The RSS feeds are the same queries; "Copy as Markdown" renders the
 * page for Slack / email.
 */

import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useDigest } from '../hooks/useTrending';
import { digestApi } from '../services/api';
import { sourceTheme, clipSm, clipMd } from '../constants/style';
import { severityColor } from './intel/lib';
import { parseApiDate } from '../utils/dates';
import { NetChangeList, JustCoveredList } from './home/ThisWeek';
import { TechniqueMomentumList } from './intel/Trending';
import { SkeletonRow, EmptyLabel } from './intel/Section';
import type { DigestResponse } from '../services/api';

const WINDOWS = [7, 14, 30] as const;

function fmtDate(iso: string | null): string {
  if (!iso) return '';
  const d = parseApiDate(iso);
  return isNaN(d.getTime()) ? '' : d.toISOString().slice(0, 10);
}

function toMarkdown(d: DigestResponse, origin: string): string {
  const lines: string[] = [];
  lines.push(`# Detection Explorer digest - ${fmtDate(d.period.start)} to ${fmtDate(d.period.end)}`);
  lines.push('');
  lines.push(`${d.summary.total_rules.toLocaleString()} rules tracked - ${d.summary.created} new, ${d.summary.modified} modified in ${d.period.days} days.`);
  const deltas = Object.entries(d.source_deltas.by_source).filter(([, v]) => v.delta);
  if (deltas.length) {
    lines.push('');
    lines.push('## Net change by source');
    for (const [src, v] of deltas.sort(([, a], [, b]) => Math.abs(b.delta ?? 0) - Math.abs(a.delta ?? 0))) {
      lines.push(`- ${sourceTheme[src]?.name || src}: ${(v.delta ?? 0) > 0 ? '+' : ''}${v.delta} (now ${v.current})`);
    }
  }
  const covered = [
    ...d.newly_covered.catalog_newly_covered.map((e) => `- ${e.technique_id} ${e.technique_name} - first rule anywhere (${Object.keys(e.sources).join(', ')})`),
    ...d.newly_covered.source_newly_covered.map((e) => `- ${e.technique_id} ${e.technique_name} - new for ${e.source}`),
  ];
  if (covered.length) {
    lines.push('');
    lines.push('## Techniques newly covered');
    lines.push(...covered);
  }
  if (d.momentum.method === 'snapshot' && (d.momentum.gainers.length || d.momentum.losers.length)) {
    lines.push('');
    lines.push('## Technique momentum');
    for (const g of [...d.momentum.gainers, ...d.momentum.losers]) {
      lines.push(`- ${g.technique_id}: ${g.delta > 0 ? '+' : ''}${g.delta} rules (${g.current} now)`);
    }
  }
  if (d.new_rules.length) {
    lines.push('');
    lines.push('## New rules');
    for (const r of d.new_rules) {
      lines.push(`- [${r.source}] ${r.title} (${r.severity}${r.mitre_techniques.length ? ', ' + r.mitre_techniques.join(' ') : ''}) ${origin}/detections/${r.id}`);
    }
  }
  if (d.emerging_data_sources.length) {
    lines.push('');
    lines.push('## Emerging data sources');
    for (const e of d.emerging_data_sources) lines.push(`- ${e.data_source}: ${e.count} new rules (${e.sources.join(', ')})`);
  }
  lines.push('');
  lines.push(`Generated ${fmtDate(d.generated_at)} - ${origin}/digest`);
  return lines.join('\n');
}

function Panel({ title, subtitle, children }: { title: string; subtitle?: string; children: React.ReactNode }) {
  return (
    <section className="bg-void-850 border border-void-700 overflow-hidden" style={clipSm}>
      <div className="px-3 py-2 border-b border-void-700 bg-void-900/40">
        <h2 className="font-display font-semibold text-[11px] uppercase tracking-wider text-matrix-400">{title}</h2>
        {subtitle && <p className="text-[10px] font-mono text-gray-600">{subtitle}</p>}
      </div>
      <div className="p-2">{children}</div>
    </section>
  );
}

export function Digest() {
  const [days, setDays] = useState<number>(7);
  const { data, isLoading, error, refetch } = useDigest(days, 20);
  const [copied, setCopied] = useState(false);
  const origin = typeof window !== 'undefined' ? window.location.origin : 'https://detectionexplorer.io';
  const markdown = useMemo(() => (data ? toMarkdown(data, origin) : ''), [data, origin]);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(markdown);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked: the textarea below stays available */
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">Weekly Digest</h1>
          <p className="text-xs text-gray-500 mt-1 font-mono">
            {data ? `${fmtDate(data.period.start)} to ${fmtDate(data.period.end)} · generated ${fmtDate(data.generated_at)}` : 'what changed across every tracked detection repo'}
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex items-center gap-1" role="radiogroup" aria-label="Digest window">
            {WINDOWS.map((w) => (
              <button
                key={w}
                role="radio"
                aria-checked={days === w}
                onClick={() => setDays(w)}
                className={`px-3 py-1 text-xs font-mono uppercase tracking-wider transition-colors ${
                  days === w ? 'bg-matrix-500/20 text-matrix-400 border border-matrix-500/40' : 'bg-void-900 text-gray-500 border border-void-700 hover:text-white'
                }`}
              >
                {w}d
              </button>
            ))}
          </div>
          <button
            onClick={copy}
            disabled={!data}
            className="px-3 py-1 text-xs font-mono uppercase tracking-wider border border-void-600 text-gray-300 hover:text-matrix-400 hover:border-matrix-500/40 disabled:opacity-40 transition-colors"
            style={clipSm}
            data-testid="copy-markdown"
          >
            {copied ? '[ copied ]' : '[ copy as markdown ]'}
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-void-850 border border-breach-500/30 px-4 py-3 text-xs font-mono text-breach-400 flex items-center justify-between gap-4" role="alert">
          <span>Digest unavailable: {(error as Error).message}</span>
          <button onClick={() => refetch()} className="hover:text-breach-300">[ retry ]</button>
        </div>
      )}

      {isLoading && <div className="space-y-2">{[...Array(4)].map((_, i) => <SkeletonRow key={i} height="h-16" />)}</div>}

      {data && (
        <>
          {/* Summary strip */}
          <div className="bg-gradient-to-r from-matrix-500/10 via-cyan-500/5 to-transparent border border-matrix-500/30 px-5 py-4" style={clipMd}>
            <div className="flex items-baseline gap-4 flex-wrap">
              <span className="text-3xl font-display font-bold text-matrix-400 tabular-nums" data-testid="digest-created">{data.summary.created.toLocaleString()}</span>
              <span className="text-sm text-gray-400 font-mono">new rules</span>
              <span className="text-2xl font-display font-bold text-white tabular-nums">{data.summary.modified.toLocaleString()}</span>
              <span className="text-sm text-gray-400 font-mono">modified</span>
              <span className="text-xs text-gray-600 font-mono">· {data.summary.total_rules.toLocaleString()} tracked</span>
            </div>
            <div className="mt-2 flex gap-2 flex-wrap">
              {Object.entries(data.summary.created_by_source).map(([src, n]) => (
                <Link key={src} to={`/detections?sources=${src}&sort_by=rule_created_date&sort_order=desc`} className={`text-[11px] font-mono px-2 py-0.5 border ${sourceTheme[src]?.border || 'border-void-600'} ${sourceTheme[src]?.text || 'text-gray-300'} hover:brightness-125`}>
                  {sourceTheme[src]?.name || src} +{n}
                </Link>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <Panel title="Net change by source" subtitle={`added minus removed, vs ${data.period.days} days ago`}><NetChangeList /></Panel>
            <Panel title="Just covered" subtitle="techniques that gained their first rule"><JustCoveredList /></Panel>
            <Panel title="Technique momentum" subtitle="catalog-wide rule count change"><TechniqueMomentumList /></Panel>
          </div>

          <Panel title="New rules" subtitle={`newest ${data.new_rules.length} of ${data.summary.created} created in the window`}>
            {data.new_rules.length === 0 ? (
              <EmptyLabel label="NO_NEW_RULES_IN_WINDOW" />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead className="text-[10px] font-display font-semibold text-gray-500 uppercase tracking-wider">
                    <tr>
                      <th className="text-left px-2 py-1">Rule</th>
                      <th className="text-left px-2 py-1">Source</th>
                      <th className="text-left px-2 py-1">Severity</th>
                      <th className="text-left px-2 py-1">Techniques</th>
                      <th className="text-right px-2 py-1">Hygiene</th>
                      <th className="text-left px-2 py-1">Created</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-void-800">
                    {data.new_rules.map((r) => (
                      <tr key={r.id} className="hover:bg-void-800/50" data-testid={`digest-rule-${r.id}`}>
                        <td className="px-2 py-1.5 max-w-md">
                          <Link to={`/detections/${r.id}`} className="text-gray-200 hover:text-matrix-400">{r.title}</Link>
                        </td>
                        <td className="px-2 py-1.5 whitespace-nowrap"><span className={`font-mono ${sourceTheme[r.source]?.text || 'text-gray-400'}`}>{sourceTheme[r.source]?.name || r.source}</span></td>
                        <td className="px-2 py-1.5"><span className={`font-mono ${severityColor[r.severity] || 'text-gray-400'}`}>{r.severity}</span></td>
                        <td className="px-2 py-1.5 font-mono text-gray-400">
                          {r.mitre_techniques.slice(0, 3).map((t) => (
                            <Link key={t} to={`/mitre/${t}`} className="mr-1 hover:text-matrix-400">{t}</Link>
                          ))}
                          {r.mitre_techniques.length > 3 && <span className="text-gray-600">+{r.mitre_techniques.length - 3}</span>}
                        </td>
                        <td className="px-2 py-1.5 text-right font-mono tabular-nums text-gray-400">{r.quality_score ?? '—'}</td>
                        <td className="px-2 py-1.5 font-mono text-gray-500 whitespace-nowrap">{fmtDate(r.created)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Panel title="Emerging data sources" subtitle="canonical data sources by new-rule volume">
              {data.emerging_data_sources.length === 0 ? (
                <EmptyLabel label="NO_NEW_RULES_IN_WINDOW" />
              ) : (
                <div className="space-y-1">
                  {data.emerging_data_sources.map((e, i) => (
                    <Link key={e.data_source} to={`/detections?data_sources_normalized=${encodeURIComponent(e.data_source)}`} className="flex items-center gap-2 text-xs px-2 py-1 bg-void-800/60 border border-void-700 hover:border-void-600">
                      <span className="text-[10px] font-mono text-gray-600 w-4">{i + 1}.</span>
                      <span className="font-mono text-cyan-400">{e.data_source}</span>
                      <span className="flex-1" />
                      <span className="text-gray-500 font-mono">{e.sources.join(', ')}</span>
                      <span className="font-mono text-white tabular-nums w-8 text-right">{e.count}</span>
                    </Link>
                  ))}
                </div>
              )}
            </Panel>
            <Panel title="Subscribe" subtitle="the same queries as RSS -- paste into your reader">
              <div className="space-y-2 text-xs font-mono">
                {([['New detection rules', 'feed'], ['Techniques newly covered', 'newly-covered']] as const).map(([label, name]) => (
                  <div key={name} className="flex items-center gap-2 bg-void-900 border border-void-700 px-2 py-1.5">
                    <span className="text-gray-400 shrink-0">{label}</span>
                    <a href={digestApi.feedUrl(name)} className="text-matrix-400 hover:text-matrix-300 truncate min-w-0 flex-1" target="_blank" rel="noopener noreferrer">
                      {origin}{digestApi.feedUrl(name).startsWith('/') ? '' : ''}{digestApi.feedUrl(name)}
                    </a>
                  </div>
                ))}
                <p className="text-[10px] text-gray-600">
                  Or the JSON: <code className="text-gray-400">GET /api/digest?days=7</code>
                </p>
              </div>
            </Panel>
          </div>

          <details className="bg-void-850 border border-void-700">
            <summary className="px-3 py-2 text-[11px] font-mono text-gray-500 uppercase tracking-wider cursor-pointer hover:text-gray-300">Markdown preview</summary>
            <textarea readOnly value={markdown} className="w-full h-64 bg-void-900 text-gray-300 text-xs font-mono p-3 border-t border-void-700 focus:outline-none" aria-label="Digest as Markdown" />
          </details>
        </>
      )}
    </div>
  );
}
