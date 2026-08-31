/**
 * One observable value, across the corpus: how many rules key on it,
 * which vendors, which techniques and tactics, which source fields
 * name it, what it co-occurs with, and the rules themselves.
 */

import { Link, useParams } from 'react-router-dom';
import { useObservableProfile } from '../hooks/useObservables';
import { useMitre } from '../contexts/MitreContext';
import { useEventIds } from '../hooks/useEventIds';
import { sourceTheme, clipSm, clipMd } from '../constants/style';
import { severityColor } from './intel/lib';
import { OBSERVABLE_FILTER_KEY, OBSERVABLE_KIND_LABEL, observableUrl, type ObservableKind } from '../utils/observableLinks';
import { SkeletonRow } from './intel/Section';

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

function Bars({ entries, max, render }: { entries: [string, number][]; max: number; render: (key: string) => React.ReactNode }) {
  return (
    <div className="space-y-1">
      {entries.map(([k, n]) => (
        <div key={k} className="relative bg-void-800/60 border border-void-700 px-2.5 py-1 text-xs">
          <div className="absolute inset-y-0 left-0 bg-matrix-500/10" style={{ width: `${(n / max) * 100}%` }} />
          <div className="relative flex items-center gap-2">
            <span className="min-w-0 flex-1 truncate">{render(k)}</span>
            <span className="font-mono text-white tabular-nums">{n}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

export function ObservableDetail() {
  const params = useParams<{ kind: string; '*': string }>();
  const kind = params.kind as ObservableKind;
  const value = decodeURIComponent(params['*'] || '');
  const { data, isLoading, error } = useObservableProfile(kind, value);
  const { getTechniqueName, getTacticName } = useMitre();
  const { entries: eventIdEntries } = useEventIds();
  const label = OBSERVABLE_KIND_LABEL[kind] || kind;

  if (isLoading) return <div className="space-y-2">{[...Array(5)].map((_, i) => <SkeletonRow key={i} height="h-12" />)}</div>;
  if (error || !data) {
    return (
      <div className="space-y-4">
        <Link to={`/observables/${kind}`} className="text-xs font-mono text-gray-500 hover:text-matrix-400">&larr; {label} index</Link>
        <div className="bg-void-850 border border-void-700 p-8 text-center" style={clipMd} role="alert">
          <p className="text-gray-400 font-mono text-sm">No rules reference {label.toLowerCase()} <span className="text-white">{value}</span>.</p>
          <Link to={`/detections?search=${encodeURIComponent(value)}`} className="inline-block mt-3 text-matrix-500 hover:text-matrix-400 text-xs font-mono">[ FULL_TEXT_SEARCH ]</Link>
        </div>
      </div>
    );
  }

  const srcMax = Math.max(...Object.values(data.by_source), 1);
  const eventEntry = kind === 'eventid' ? eventIdEntries?.[value] : undefined;
  const catalogHref = `/detections?${OBSERVABLE_FILTER_KEY[kind]}=${encodeURIComponent(value)}`;

  return (
    <div className="space-y-6">
      <div>
        <Link to={`/observables/${kind}`} className="text-xs font-mono text-gray-500 hover:text-matrix-400">&larr; {label} index</Link>
        <div className="mt-2 flex items-end justify-between gap-4 flex-wrap">
          <div className="min-w-0">
            <div className="text-[10px] font-mono text-matrix-400 uppercase tracking-[0.2em]">{label}</div>
            <h1 className="text-2xl font-mono font-bold text-white break-all" data-testid="observable-value">{data.value}</h1>
            {eventEntry && (
              <p className="text-sm text-gray-400 flex items-center gap-2 flex-wrap" data-testid="event-context">
                <span>{eventEntry.label}</span>
                <span className="text-[10px] font-mono uppercase tracking-wider text-cyan-300 bg-cyan-500/10 border border-cyan-500/30 px-1.5 py-0.5" title={`Log channel: ${eventEntry.channel}`}>
                  {eventEntry.channel}
                </span>
              </p>
            )}
          </div>
          <Link to={catalogHref} className="btn-primary text-xs inline-flex items-center gap-2 shrink-0">
            Open {data.total_rules.toLocaleString()} rule{data.total_rules === 1 ? '' : 's'} in catalog
          </Link>
        </div>
      </div>

      {/* Stat strip */}
      <div className="bg-gradient-to-r from-matrix-500/10 via-cyan-500/5 to-transparent border border-matrix-500/30 px-5 py-3 flex items-baseline gap-6 flex-wrap" style={clipMd}>
        <div><span className="text-3xl font-display font-bold text-matrix-400 tabular-nums" data-testid="observable-total">{data.total_rules.toLocaleString()}</span><span className="text-sm text-gray-400 font-mono ml-2">rules</span></div>
        <div><span className="text-2xl font-display font-bold text-white tabular-nums">{Object.keys(data.by_source).length}</span><span className="text-sm text-gray-400 font-mono ml-2">sources</span></div>
        <div><span className="text-2xl font-display font-bold text-white tabular-nums">{data.by_technique.length}</span><span className="text-sm text-gray-400 font-mono ml-2">techniques</span></div>
        {data.negated_in > 0 && (
          <div title="Rules that use this value as an exclusion (NOT)"><span className="text-2xl font-display font-bold text-breach-400 tabular-nums">{data.negated_in}</span><span className="text-sm text-gray-400 font-mono ml-2">as exclusion</span></div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Panel title="By source" subtitle="who has rules keyed on this value">
          <Bars
            entries={Object.entries(data.by_source)}
            max={srcMax}
            render={(s) => (
              <Link to={`${catalogHref}&sources=${s}`} className={`font-mono ${sourceTheme[s]?.text || 'text-gray-300'} hover:brightness-125`}>
                <span className={`inline-block w-2 h-2 rounded-full mr-1.5 ${sourceTheme[s]?.dot || 'bg-gray-500'}`} />{sourceTheme[s]?.name || s}
              </Link>
            )}
          />
        </Panel>
        <Panel title="Techniques" subtitle="ATT&CK techniques these rules are tagged with">
          {data.by_technique.length === 0 ? <p className="text-xs font-mono text-gray-600 px-1">no ATT&CK tags</p> : (
            <Bars
              entries={data.by_technique.map((t) => [t.technique_id, t.rules])}
              max={data.by_technique[0].rules}
              render={(t) => (
                <Link to={`/mitre/${t}`} className="hover:text-matrix-400">
                  <span className="font-mono text-matrix-500 mr-2">{t}</span><span className="text-gray-400">{getTechniqueName(t) || ''}</span>
                </Link>
              )}
            />
          )}
          {data.by_tactic.length > 0 && (
            <div className="mt-2 flex gap-1 flex-wrap">
              {data.by_tactic.map((t) => (
                <Link key={t.tactic_id} to={`/detections?mitre_tactics=${t.tactic_id}`} className="px-1.5 py-0.5 text-[10px] font-mono border border-void-600 text-gray-400 hover:text-matrix-400" title={`${t.rules} rule(s)`}>
                  {getTacticName(t.tactic_id) || t.tactic_id}
                </Link>
              ))}
            </div>
          )}
        </Panel>
        <Panel title="Fields and severity" subtitle="which source fields name it; how severe the rules are">
          <div className="space-y-1 mb-3">
            {data.fields.map((f) => (
              <div key={f.field} className="flex items-center justify-between text-xs px-2 py-1 bg-void-800/60 border border-void-700">
                <span className="font-mono text-gray-300 truncate">{f.field}</span>
                <span className="font-mono text-gray-500 tabular-nums">{f.rules}</span>
              </div>
            ))}
          </div>
          <div className="flex gap-2 flex-wrap">
            {Object.entries(data.by_severity).map(([sev, n]) => (
              <Link key={sev} to={`${catalogHref}&severities=${sev}`} className={`px-2 py-0.5 text-[11px] font-mono border border-void-600 ${severityColor[sev] || 'text-gray-400'}`}>
                {sev} <span className="text-gray-500">{n}</span>
              </Link>
            ))}
            {Object.entries(data.by_platform).map(([p, n]) => (
              <Link key={p} to={`${catalogHref}&platforms=${p}`} className="px-2 py-0.5 text-[11px] font-mono border border-void-600 text-gray-400">
                {p} <span className="text-gray-500">{n}</span>
              </Link>
            ))}
          </div>
        </Panel>
      </div>

      {Object.keys(data.co_occurring).length > 0 && (
        <Panel title="Seen alongside" subtitle="other observables in the same rules -- the detection context this value lives in">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            {Object.entries(data.co_occurring).map(([k, items]) => (
              <div key={k}>
                <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider mb-1">{OBSERVABLE_KIND_LABEL[k as ObservableKind] || k}</div>
                <div className="flex flex-wrap gap-1">
                  {items.map((it) => (
                    <Link key={it.value} to={observableUrl(k as ObservableKind, it.value)} className="px-1.5 py-0.5 text-[11px] font-mono bg-void-900 border border-void-700 text-gray-300 hover:text-matrix-400 hover:border-matrix-500/40 break-all" title={`${it.rules} shared rule(s)`}>
                      {it.value} <span className="text-gray-600">{it.rules}</span>
                    </Link>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </Panel>
      )}

      <Panel title="Rules" subtitle={data.total_rules > data.rules.length ? `first ${data.rules.length} of ${data.total_rules} -- open the catalog for all` : `${data.rules.length} rule(s)`}>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="text-[10px] font-display font-semibold text-gray-500 uppercase tracking-wider">
              <tr>
                <th scope="col" className="text-left px-2 py-1">Rule</th>
                <th scope="col" className="text-left px-2 py-1">Source</th>
                <th scope="col" className="text-left px-2 py-1">Severity</th>
                <th scope="col" className="text-left px-2 py-1">Techniques</th>
                <th scope="col" className="text-right px-2 py-1">Completeness</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-void-800">
              {data.rules.map((r) => (
                <tr key={r.id} className="hover:bg-void-800/50" data-testid={`obs-rule-${r.id}`}>
                  <td className="px-2 py-1.5 max-w-md"><Link to={`/detections/${r.id}`} className="text-gray-200 hover:text-matrix-400">{r.title}</Link></td>
                  <td className="px-2 py-1.5 whitespace-nowrap"><span className={`font-mono ${sourceTheme[r.source]?.text || 'text-gray-400'}`}>{sourceTheme[r.source]?.name || r.source}</span></td>
                  <td className="px-2 py-1.5"><span className={`font-mono ${severityColor[r.severity] || 'text-gray-400'}`}>{r.severity}</span></td>
                  <td className="px-2 py-1.5 font-mono text-gray-400">
                    {r.mitre_techniques.slice(0, 3).map((t) => <Link key={t} to={`/mitre/${t}`} className="mr-1 hover:text-matrix-400">{t}</Link>)}
                    {r.mitre_techniques.length > 3 && <span className="text-gray-600">+{r.mitre_techniques.length - 3}</span>}
                  </td>
                  <td className="px-2 py-1.5 text-right font-mono tabular-nums text-gray-400">{r.quality_score ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
