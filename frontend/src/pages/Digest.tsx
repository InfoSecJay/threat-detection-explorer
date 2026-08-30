/**
 * Weekly digest -- what a detection engineer needs to know this week,
 * in the order they need it:
 *
 *   header     N new / M updated across K sources, window, export
 *   contents   one chip per source with (+new ~updated), anchored
 *   themes     the techniques the new rules cluster on
 *   sources    per source: NEW rules as cards (what it detects),
 *              then UPDATED rules as a compact list
 *   context    net change / newly covered / momentum / data sources
 *   subscribe  RSS: new, updated, per source
 *
 * "Copy as Markdown" renders the same structure for Slack / email.
 * New vs updated are disjoint: a rule created in the window is new
 * even if it was also touched.
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
import { useDocumentMeta } from '../hooks/useDocumentMeta';
import type { DigestResponse, DigestRule } from '../services/api';

const WINDOWS = [7, 14, 30] as const;
const COLLAPSED = 8;

function fmtDate(iso: string | null): string {
  if (!iso) return '';
  const d = parseApiDate(iso);
  return isNaN(d.getTime()) ? '' : d.toISOString().slice(0, 10);
}

function srcName(src: string): string {
  return sourceTheme[src]?.name || src;
}

/** Sources in digest order: most new rules first, then most updated. */
function sourceOrder(d: DigestResponse): string[] {
  return Object.entries(d.summary.by_source)
    .sort(([a, x], [b, y]) => y.created - x.created || y.modified - x.modified || a.localeCompare(b))
    .map(([s]) => s);
}

/** Markdown escaping for link text: brackets and pipes would break the
 * link or a table in the target renderer. */
function mdText(t: string): string {
  return t.replace(/[[\]]/g, '\\$&').replace(/\|/g, '\\|');
}

function ruleLink(r: DigestRule, origin: string): string {
  return `[${mdText(r.title)}](${origin}/detections/${encodeURIComponent(r.id)})`;
}

function techLinks(ids: string[], origin: string): string {
  return ids.slice(0, 3).map((t) => `[${t}](${origin}/mitre/${t})`).join(', ') + (ids.length > 3 ? ` +${ids.length - 3}` : '');
}

const SEVERITY_MARK: Record<string, string> = { critical: '\u{1F534}', high: '\u{1F7E0}', medium: '\u{1F7E1}', low: '\u{1F7E2}' };

function toMarkdown(d: DigestResponse, origin: string): string {
  const L: string[] = [];
  const sources = sourceOrder(d);
  const catalog = (src: string) => `${origin}/detections?sources=${src}&sort_by=rule_created_date&sort_order=desc`;
  L.push(`# \u{1F4F0} Detection Explorer digest \u00B7 ${fmtDate(d.period.start)} \u2192 ${fmtDate(d.period.end)}`);
  L.push('');
  L.push(`**${d.summary.created} new** and **${d.summary.modified} updated** rules across ${sources.length} source${sources.length === 1 ? '' : 's'} \u00B7 ${d.summary.total_rules.toLocaleString()} rules tracked \u00B7 [open the digest](${origin}/digest)`);
  if (d.themes.length) {
    L.push('');
    L.push('## \u{1F3AF} Themes');
    L.push('');
    for (const t of d.themes) {
      const srcs = Object.entries(t.sources).map(([s, n]) => `${srcName(s)} ${n}`).join(', ');
      L.push(`- **[${t.technique_id}](${origin}/mitre/${t.technique_id}) ${mdText(t.technique_name || '')}**${t.tactic ? ` \u00B7 ${t.tactic}` : ''} \u2014 ${t.rules} new rule${t.rules === 1 ? '' : 's'} (${srcs})`);
    }
  }
  for (const src of sources) {
    const c = d.summary.by_source[src];
    const fresh = d.new_rules.filter((r) => r.source === src);
    const changed = d.modified_rules.filter((r) => r.source === src);
    L.push('');
    L.push(`## \u{1F9E9} ${srcName(src)} \u00B7 +${c.created} new \u00B7 ~${c.modified} updated`);
    if (fresh.length) {
      L.push('');
      L.push('### \u2728 New rules');
      L.push('');
      for (const r of fresh) {
        const bits = [`${SEVERITY_MARK[r.severity] || '\u26AA'} ${r.severity}`];
        if (r.mitre_techniques.length) bits.push(techLinks(r.mitre_techniques, origin));
        if (r.platforms.length) bits.push(r.platforms.slice(0, 3).join(' / '));
        L.push(`- ${ruleLink(r, origin)} \u2014 ${bits.join(' \u00B7 ')}`);
      }
      if (c.created > fresh.length) L.push(`- [\u2026 and ${c.created - fresh.length} more in the catalog](${catalog(src)})`);
    }
    if (changed.length) {
      L.push('');
      L.push('### \u{1F527} Updated rules');
      L.push('');
      for (const r of changed) L.push(`- ${ruleLink(r, origin)} \u2014 ${fmtDate(r.modified)}${r.mitre_techniques.length ? ` \u00B7 ${techLinks(r.mitre_techniques, origin)}` : ''}`);
      if (c.modified > changed.length) L.push(`- [\u2026 and ${c.modified - changed.length} more in the catalog](${catalog(src)})`);
    }
  }
  const covered = [
    ...d.newly_covered.catalog_newly_covered.map((e) => `- [${e.technique_id} ${mdText(e.technique_name)}](${origin}/mitre/${e.technique_id}) \u2014 first rule anywhere (${Object.keys(e.sources).map(srcName).join(', ')})`),
    ...d.newly_covered.source_newly_covered.map((e) => `- [${e.technique_id} ${mdText(e.technique_name)}](${origin}/mitre/${e.technique_id}) \u2014 new for ${srcName(e.source)}`),
  ];
  if (covered.length) {
    L.push('');
    L.push('## \u{1F195} Techniques newly covered');
    L.push('');
    L.push(...covered);
  }
  const deltas = Object.entries(d.source_deltas.by_source).filter(([, v]) => v.delta);
  if (deltas.length) {
    L.push('');
    L.push('## \u{1F4C8} Net change by source');
    L.push('');
    for (const [src, v] of deltas.sort(([, a], [, b]) => Math.abs(b.delta ?? 0) - Math.abs(a.delta ?? 0))) {
      L.push(`- [${srcName(src)}](${catalog(src)}): ${(v.delta ?? 0) > 0 ? '+' : ''}${v.delta} (now ${v.current})`);
    }
  }
  L.push('');
  L.push(`_Generated ${fmtDate(d.generated_at)} \u00B7 [${origin.replace(/^https?:\/\//, '')}/digest](${origin}/digest)_`);
  return L.join('\n');
}


function Panel({ title, subtitle, children, right }: { title: string; subtitle?: string; children: React.ReactNode; right?: React.ReactNode }) {
  return (
    <section className="bg-void-850 border border-void-700 overflow-hidden" style={clipSm}>
      <div className="px-3 py-2 border-b border-void-700 bg-void-900/40 flex items-baseline justify-between gap-3 flex-wrap">
        <div>
          <h2 className="font-display font-semibold text-[11px] uppercase tracking-wider text-matrix-400">{title}</h2>
          {subtitle && <p className="text-[10px] font-mono text-gray-600">{subtitle}</p>}
        </div>
        {right}
      </div>
      <div className="p-2">{children}</div>
    </section>
  );
}

function Techniques({ ids }: { ids: string[] }) {
  return (
    <span className="font-mono text-gray-400">
      {ids.slice(0, 3).map((t) => (
        <Link key={t} to={`/mitre/${t}`} className="mr-1 hover:text-matrix-400">{t}</Link>
      ))}
      {ids.length > 3 && <span className="text-gray-600">+{ids.length - 3}</span>}
    </span>
  );
}

function NewRuleCard({ r }: { r: DigestRule }) {
  return (
    <article className="bg-void-900/60 border border-void-700 hover:border-matrix-500/40 px-3 py-2.5 transition-colors" data-testid={`digest-rule-${r.id}`}>
      <div className="flex items-start gap-2">
        <Link to={`/detections/${r.id}`} className="text-sm text-gray-100 hover:text-matrix-400 font-medium flex-1 min-w-0">{r.title}</Link>
        <span className={`font-mono text-[10px] uppercase shrink-0 ${severityColor[r.severity] || 'text-gray-400'}`}>{r.severity}</span>
      </div>
      {r.description && <p className="text-xs text-gray-400 mt-1 line-clamp-2">{r.description}</p>}
      <div className="mt-1.5 flex items-center gap-3 text-[11px] flex-wrap">
        <Techniques ids={r.mitre_techniques} />
        {r.platforms.length > 0 && <span className="font-mono text-cyan-400/80">{r.platforms.slice(0, 3).join(' · ')}</span>}
        {r.quality_score !== null && <span className="font-mono text-gray-600" title="Metadata completeness">meta {r.quality_score}</span>}
        <span className="flex-1" />
        <span className="font-mono text-gray-600">{fmtDate(r.created)}</span>
        {r.source_rule_url && (
          <a href={r.source_rule_url} target="_blank" rel="noopener noreferrer" className="font-mono text-gray-500 hover:text-matrix-400" title="Upstream file">upstream &#8599;</a>
        )}
      </div>
    </article>
  );
}

function UpdatedRuleRow({ r }: { r: DigestRule }) {
  return (
    <li className="flex items-center gap-3 px-2 py-1 text-xs hover:bg-void-800/50" data-testid={`digest-updated-${r.id}`}>
      <Link to={`/detections/${r.id}`} className="text-gray-300 hover:text-matrix-400 truncate flex-1 min-w-0">{r.title}</Link>
      <Techniques ids={r.mitre_techniques} />
      <span className="font-mono text-gray-600 whitespace-nowrap">{fmtDate(r.modified)}</span>
      {r.source_rule_url && (
        <a href={r.source_rule_url} target="_blank" rel="noopener noreferrer" className="font-mono text-[10px] text-gray-600 hover:text-matrix-400" title="Upstream file">&#8599;</a>
      )}
    </li>
  );
}

function Expandable<T>({ items, total, render, label }: { items: T[]; total: number; render: (t: T) => React.ReactNode; label: string }) {
  const [all, setAll] = useState(false);
  const shown = all ? items : items.slice(0, COLLAPSED);
  const hidden = items.length - shown.length;
  return (
    <>
      {shown.map(render)}
      {(hidden > 0 || total > items.length) && (
        <div className="px-2 pt-1 text-[11px] font-mono flex items-center gap-3">
          {hidden > 0 && (
            <button onClick={() => setAll(true)} className="text-matrix-500 hover:text-matrix-400 uppercase tracking-wider">
              show all {items.length} {label}
            </button>
          )}
          {all && hidden === 0 && items.length > COLLAPSED && (
            <button onClick={() => setAll(false)} className="text-gray-500 hover:text-white uppercase tracking-wider">collapse</button>
          )}
          {total > items.length && <span className="text-gray-600">{total - items.length} more not listed (window cap)</span>}
        </div>
      )}
    </>
  );
}

function SourceSection({ src, d }: { src: string; d: DigestResponse }) {
  const c = d.summary.by_source[src];
  const fresh = d.new_rules.filter((r) => r.source === src);
  const changed = d.modified_rules.filter((r) => r.source === src);
  const cfg = sourceTheme[src];
  return (
    <section id={`src-${src}`} className="bg-void-850 border border-void-700 overflow-hidden scroll-mt-20" style={clipSm} data-testid={`digest-source-${src}`}>
      <div className="px-3 py-2 border-b border-void-700 bg-void-900/40 flex items-baseline justify-between gap-3 flex-wrap">
        <h2 className={`font-display font-semibold text-sm uppercase tracking-wider ${cfg?.text || 'text-gray-200'}`}>{srcName(src)}</h2>
        <div className="flex items-center gap-3 text-[11px] font-mono">
          <span className="text-matrix-400">+{c.created} new</span>
          <span className="text-amber-300">~{c.modified} updated</span>
          <Link to={`/detections?sources=${src}&sort_by=rule_created_date&sort_order=desc`} className="text-gray-500 hover:text-matrix-400 uppercase tracking-wider">catalog &#8599;</Link>
          <a href={digestApi.feedUrl('feed', src)} className="text-gray-500 hover:text-matrix-400 uppercase tracking-wider" title="RSS: new rules from this source">rss</a>
        </div>
      </div>
      <div className="p-2 space-y-3">
        {fresh.length > 0 && (
          <div>
            <div className="text-[10px] font-display font-semibold text-gray-500 uppercase tracking-wider px-1 mb-1.5">New rules</div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              <Expandable items={fresh} total={c.created} label="new rules" render={(r) => <NewRuleCard key={r.id} r={r} />} />
            </div>
          </div>
        )}
        {changed.length > 0 && (
          <div>
            <div className="text-[10px] font-display font-semibold text-gray-500 uppercase tracking-wider px-1 mb-1">Updated rules</div>
            <ul className="divide-y divide-void-800">
              <Expandable items={changed} total={c.modified} label="updated rules" render={(r) => <UpdatedRuleRow key={r.id} r={r} />} />
            </ul>
          </div>
        )}
        {fresh.length === 0 && changed.length === 0 && <EmptyLabel label="NO_CHANGES" />}
      </div>
    </section>
  );
}

export function Digest() {
  const [days, setDays] = useState<number>(7);
  const { data, isLoading, error, refetch } = useDigest(days, 20);
  useDocumentMeta('Digest', data ? `${data.summary.created} new and ${data.summary.modified} updated detection rules in the last ${data.period.days} days.` : null);
  const [copied, setCopied] = useState(false);
  const origin = typeof window !== 'undefined' ? window.location.origin : 'https://detectionexplorer.io';
  const markdown = useMemo(() => (data ? toMarkdown(data, origin) : ''), [data, origin]);
  const sources = useMemo(() => (data ? sourceOrder(data) : []), [data]);

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
          <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">Digest</h1>
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
          {/* Headline + table of contents */}
          <div className="bg-gradient-to-r from-matrix-500/10 via-cyan-500/5 to-transparent border border-matrix-500/30 px-5 py-4" style={clipMd}>
            <div className="flex items-baseline gap-4 flex-wrap">
              <span className="text-3xl font-display font-bold text-matrix-400 tabular-nums" data-testid="digest-created">{data.summary.created.toLocaleString()}</span>
              <span className="text-sm text-gray-400 font-mono">new rules</span>
              <span className="text-2xl font-display font-bold text-amber-300 tabular-nums" data-testid="digest-modified">{data.summary.modified.toLocaleString()}</span>
              <span className="text-sm text-gray-400 font-mono">updated</span>
              <span className="text-xs text-gray-600 font-mono">· across {sources.length} source{sources.length === 1 ? '' : 's'} · {data.summary.total_rules.toLocaleString()} tracked</span>
            </div>
            <nav className="mt-3 flex gap-1.5 flex-wrap" aria-label="Sources in this digest">
              {sources.map((src) => {
                const c = data.summary.by_source[src];
                return (
                  <a key={src} href={`#src-${src}`} className={`text-[11px] font-mono px-2 py-0.5 border ${sourceTheme[src]?.border || 'border-void-600'} ${sourceTheme[src]?.text || 'text-gray-300'} hover:brightness-125`} data-testid={`toc-${src}`}>
                    {srcName(src)} <span className="text-gray-400">+{c.created}</span>{c.modified > 0 && <span className="text-gray-500"> ~{c.modified}</span>}
                  </a>
                );
              })}
            </nav>
          </div>

          {data.themes.length > 0 && (
            <Panel title="Themes" subtitle="the techniques this week's new rules cluster on">
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-2">
                {data.themes.map((t) => (
                  <Link key={t.technique_id} to={`/mitre/${t.technique_id}`} className="block bg-void-900/60 border border-void-700 hover:border-matrix-500/40 px-3 py-2 transition-colors" data-testid={`theme-${t.technique_id}`}>
                    <div className="flex items-baseline gap-2">
                      <span className="font-mono text-matrix-400 text-xs">{t.technique_id}</span>
                      <span className="text-sm text-gray-100 truncate flex-1 min-w-0">{t.technique_name || 'Unknown technique'}</span>
                      <span className="font-mono text-white tabular-nums text-sm">{t.rules}</span>
                    </div>
                    <div className="text-[10px] font-mono text-gray-500 mt-0.5 truncate">
                      {t.tactic && <span className="uppercase tracking-wider mr-2">{t.tactic}</span>}
                      {Object.entries(t.sources).map(([s, n]) => `${srcName(s)} ${n}`).join(' · ')}
                    </div>
                    <div className="text-[11px] text-gray-400 mt-1 truncate">{t.samples.map((s) => s.title).join(' · ')}</div>
                  </Link>
                ))}
              </div>
            </Panel>
          )}

          {sources.length === 0 ? (
            <Panel title="Rules"><EmptyLabel label="NO_NEW_OR_UPDATED_RULES_IN_WINDOW" /></Panel>
          ) : (
            <div className="space-y-4">
              {sources.map((src) => <SourceSection key={src} src={src} d={data} />)}
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <Panel title="Net change by source" subtitle={`added minus removed, vs ${data.period.days} days ago`}><NetChangeList /></Panel>
            <Panel title="Just covered" subtitle="techniques that gained their first rule"><JustCoveredList /></Panel>
            <Panel title="Technique momentum" subtitle="catalog-wide rule count change"><TechniqueMomentumList /></Panel>
          </div>

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
            <Panel title="Subscribe" subtitle="the same queries as RSS -- paste into your reader; add ?source=sigma to scope a feed">
              <div className="space-y-2 text-xs font-mono">
                {([['New rules', 'feed'], ['Updated rules', 'modified'], ['Techniques newly covered', 'newly-covered']] as const).map(([label, name]) => (
                  <div key={name} className="flex items-center gap-2 bg-void-900 border border-void-700 px-2 py-1.5">
                    <span className="text-gray-400 shrink-0 w-44">{label}</span>
                    <a href={digestApi.feedUrl(name)} className="text-matrix-400 hover:text-matrix-300 truncate min-w-0 flex-1" target="_blank" rel="noopener noreferrer">
                      {digestApi.feedUrl(name)}
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
