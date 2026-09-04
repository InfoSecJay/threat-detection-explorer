/**
 * /methodology/corpus-health -- the corpus-health report (teardown F2 / #124).
 *
 * The numbers nobody else publishes: across the whole corpus, how many
 * rules ship with no ATT&CK mapping, no references, no false-positive
 * notes (or only a placeholder), and no description -- per source and
 * in total. Every number is recomputed from the live corpus after each
 * nightly sync, is defined in one sentence on this page, and is
 * downloadable as CSV so it can be cited as data rather than a screenshot.
 */

import { Link } from 'react-router-dom';
import { CORPUS_HEALTH_CSV_URL } from '../services/api';
import { useCorpusHealth } from '../hooks/useCorpusHealth';
import { useDocumentMeta } from '../hooks/useDocumentMeta';
import { sourceLabels } from '../constants/sources';
import { clipMd, clipSm } from '../constants/style';

function pct(v: number): string {
  if (v === 0) return '0%';
  return v < 1 ? '<1%' : `${Math.round(v)}%`;
}

function asOf(updatedAt: string | null): string {
  if (!updatedAt) return 'latest sync';
  const d = new Date(updatedAt.replace(' ', 'T'));
  return Number.isNaN(d.getTime()) ? updatedAt.slice(0, 10) : d.toISOString().slice(0, 10);
}

export function CorpusHealth() {
  useDocumentMeta(
    'Corpus health',
    'How much of the open detection corpus is documented well enough to use: rules with no ATT&CK mapping, no references, no false-positive notes and no description, per source, recomputed nightly, downloadable as CSV.',
  );
  const { data, isLoading, error } = useCorpusHealth();

  return (
    <div className="space-y-8 max-w-6xl mx-auto" data-testid="corpus-health-page">
      <div>
        <Link to="/methodology" className="text-xs font-mono text-gray-500 hover:text-matrix-400">&larr; Methodology</Link>
        <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase mt-2">Corpus health</h1>
        <p className="text-sm text-gray-400 mt-2 max-w-3xl">
          Fifteen thousand open-source detection rules is a headline. How many of them say what they detect, why,
          and when they are wrong is the finding. This report counts, per source and across the whole corpus, the rules
          that ship with no ATT&amp;CK mapping, no references, no false-positive notes and no description. It is
          recomputed from the live corpus after every nightly sync
          {data ? <> and is current as of <span className="font-mono text-gray-300">{asOf(data.corpus.updated_at)}</span></> : null}.
        </p>
        <div className="mt-3 flex flex-wrap items-center gap-4 text-xs font-mono">
          <a
            href={CORPUS_HEALTH_CSV_URL}
            className="text-matrix-500 hover:text-matrix-400 underline"
            data-testid="corpus-health-csv"
          >
            download the data (CSV)
          </a>
          <a href="#definitions" className="text-gray-500 hover:text-matrix-400">how each number is counted</a>
        </div>
      </div>

      {error && (
        <div className="bg-breach-500/10 border border-breach-500/30 p-4" style={clipMd}>
          <p className="text-breach-400 font-mono text-sm">ERROR: could not load the corpus-health report.</p>
        </div>
      )}

      {data && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3" data-testid="corpus-health-totals">
            {data.fields.map((f) => (
              <a
                key={f}
                href={`#def-${f}`}
                className="bg-void-850 border border-void-700 p-3 hover:border-matrix-500/40 transition-colors"
                style={clipSm}
                title={data.field_meta[f]?.definition}
              >
                <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">{data.field_meta[f]?.label ?? f}</div>
                <div className="text-2xl font-display font-bold text-white tabular-nums">{pct(data.totals_pct[f] ?? 0)}</div>
                <div className="text-[10px] font-mono text-gray-500">
                  {(data.totals[f] ?? 0).toLocaleString()} of {data.total_rules.toLocaleString()} rules
                </div>
              </a>
            ))}
          </div>

          <div className="bg-void-850 border border-void-700 overflow-x-auto" style={clipMd}>
            <table className="w-full text-xs font-mono" data-testid="corpus-health-table">
              <thead>
                <tr className="text-gray-500 uppercase tracking-wider text-[10px] border-b border-void-700">
                  <th className="text-left px-3 py-2">Source</th>
                  <th className="text-right px-3 py-2">Rules</th>
                  {data.fields.map((f) => (
                    <th key={f} className="text-right px-3 py-2">
                      <a href={`#def-${f}`} title={data.field_meta[f]?.definition} className="hover:text-matrix-400">
                        {data.field_meta[f]?.label ?? f}
                      </a>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.sources.map((s) => (
                  <tr key={s.source} className="border-b border-void-800 hover:bg-void-800/50">
                    <td className="px-3 py-2 text-gray-200">
                      <Link to={`/detections?sources=${s.source}`} className="hover:text-matrix-400">{sourceLabels[s.source] || s.source}</Link>
                    </td>
                    <td className="px-3 py-2 text-right text-gray-400 tabular-nums">{s.total_rules.toLocaleString()}</td>
                    {data.fields.map((f) => {
                      const n = s.fields[f] ?? 0;
                      const p = s.pct[f] ?? 0;
                      return (
                        <td
                          key={f}
                          className="px-3 py-2 text-right tabular-nums"
                          title={`${n.toLocaleString()} of ${s.total_rules.toLocaleString()} ${sourceLabels[s.source] || s.source} rules: ${data.field_meta[f]?.label ?? f}`}
                        >
                          {n === 0
                            ? <span className="text-gray-700">0</span>
                            : <><span className={p >= 50 ? 'text-breach-400' : p >= 20 ? 'text-pulse-400' : 'text-gray-300'}>{pct(p)}</span> <span className="text-gray-600">{n.toLocaleString()}</span></>}
                        </td>
                      );
                    })}
                  </tr>
                ))}
                <tr className="border-t border-void-600 text-gray-300">
                  <td className="px-3 py-2 uppercase tracking-wider text-[10px]">All sources</td>
                  <td className="px-3 py-2 text-right tabular-nums">{data.total_rules.toLocaleString()}</td>
                  {data.fields.map((f) => (
                    <td key={f} className="px-3 py-2 text-right tabular-nums">
                      <span className="text-white">{pct(data.totals_pct[f] ?? 0)}</span> <span className="text-gray-600">{(data.totals[f] ?? 0).toLocaleString()}</span>
                    </td>
                  ))}
                </tr>
              </tbody>
            </table>
          </div>

          <div id="definitions" className="bg-void-850 border border-void-700 p-5 space-y-4" style={clipMd} data-testid="corpus-health-definitions">
            <h2 className="text-sm font-display font-bold text-white uppercase tracking-wider">How each number is counted</h2>
            <p className="text-xs text-gray-400 max-w-3xl">
              Each count is a literal test on the normalized field named below, applied to every rule in the corpus. A rule
              can trip several at once. These are the raw inputs behind the{' '}
              <Link to="/methodology" className="text-matrix-500 hover:text-matrix-400 underline">metadata completeness score</Link>
              , which additionally weighs what each rule format can express; the numbers here do not.
            </p>
            <dl className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-3">
              {data.fields.map((f) => (
                <div key={f} id={`def-${f}`} className="scroll-mt-24">
                  <dt className="text-xs font-mono text-gray-200 uppercase tracking-wider">{data.field_meta[f]?.label ?? f}</dt>
                  <dd className="text-xs text-gray-400 mt-1">{data.field_meta[f]?.definition}</dd>
                </div>
              ))}
            </dl>
            <p className="text-[11px] font-mono text-gray-600">
              Cite as: Detection Explorer, Corpus health as of {asOf(data.corpus.updated_at)} ({data.total_rules.toLocaleString()} rules,{' '}
              {data.sources.length} sources), https://detectionexplorer.io/methodology/corpus-health
            </p>
          </div>
        </>
      )}

      {isLoading && <p className="text-xs font-mono text-gray-500">loading ...</p>}
    </div>
  );
}
