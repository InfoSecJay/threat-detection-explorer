import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism';
import type { Detection } from '../types';
import { useMitre } from '../contexts/MitreContext';
import { resolveGroup, resolveSoftware } from '../services/mitreLookup';
import { ObservablesPanel } from './ObservablesPanel';
import { useEventIds } from '../hooks/useEventIds';

// Map detection languages to Prism language identifiers
const languageMap: Record<string, string> = {
  sigma: 'yaml',
  yaml: 'yaml',
  eql: 'sql',
  kql: 'sql',
  esql: 'sql',
  spl: 'sql',
  splunk: 'sql',
  mql: 'javascript',
  yara: 'c',
  lucene: 'javascript',
  json: 'json',
  unknown: 'yaml',
};

interface RuleDetailProps {
  detection: Detection;
}

const severityColors: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-green-500/20 text-green-400 border-green-500/30',
  unknown: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};

const statusColors: Record<string, string> = {
  stable: 'bg-green-500/20 text-green-400 border-green-500/30',
  test: 'bg-sky-500/20 text-sky-400 border-sky-500/30',
  experimental: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  deprecated: 'bg-red-500/20 text-red-400 border-red-500/30',
  unsupported: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  unknown: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};

const sourceGradients: Record<string, string> = {
  sigma: 'from-purple-500 to-purple-600',
  elastic: 'from-blue-500 to-blue-600',
  splunk: 'from-orange-500 to-orange-600',
  sublime: 'from-pink-500 to-pink-600',
  elastic_protections: 'from-cyan-500 to-cyan-600',
  lolrmm: 'from-green-500 to-green-600',
};

function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <button
      onClick={handleCopy}
      className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
        copied
          ? 'bg-green-500/20 text-green-400 border border-green-500/30'
          : 'bg-cyber-700 text-gray-300 hover:bg-cyber-600 hover:text-white border border-transparent'
      }`}
      title={copied ? 'Copied!' : `Copy ${label.toLowerCase()}`}
    >
      {copied ? (
        <>
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
          Copied!
        </>
      ) : (
        <>
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
          </svg>
          {label}
        </>
      )}
    </button>
  );
}

export function RuleDetail({ detection }: RuleDetailProps) {
  const { getTacticName, getTechniqueName, getTacticUrl, getTechniqueUrl } = useMitre();
  const { labels: eventIdLabels } = useEventIds();
  const [activeTab, setActiveTab] = useState<'normalized' | 'raw'>('normalized');

  return (
    <div className="bg-cyber-850 rounded-xl border border-cyber-700 overflow-hidden">
      {/* Color bar */}
      <div className={`h-1.5 bg-gradient-to-r ${sourceGradients[detection.source] || 'from-gray-500 to-gray-600'}`} />

      {/* Header */}
      <div className="px-6 py-4 border-b border-cyber-700">
        <div className="flex items-center justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2 py-0.5 bg-cyber-700 text-gray-300 rounded text-xs font-semibold uppercase">
                {detection.source.replace('_', ' ')}
              </span>
              <span className="px-2 py-0.5 bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 rounded text-xs font-semibold uppercase">
                {detection.language || 'unknown'}
              </span>
              <span className={`px-2 py-0.5 rounded text-xs font-semibold capitalize border ${severityColors[detection.severity]}`}>
                {detection.severity}
              </span>
              <span className={`px-2 py-0.5 rounded text-xs font-semibold capitalize border ${statusColors[detection.status] || statusColors.unknown}`}>
                {detection.status}
              </span>
              {detection.is_building_block && (
                <span
                  className="px-2 py-0.5 rounded text-xs font-semibold border bg-fuchsia-500/20 text-fuchsia-300 border-fuchsia-500/30"
                  title="Building block: emits signal for other rules to correlate on; does not alert on its own"
                >
                  Building block
                </span>
              )}
            </div>
            <h1 className="text-xl font-bold text-white">{detection.title}</h1>
          </div>
          {detection.source_rule_url && (
            <a
              href={detection.source_rule_url}
              target="_blank"
              rel="noopener noreferrer"
              className="flex-shrink-0 px-3 py-1.5 bg-cyber-700 hover:bg-cyber-600 text-gray-300 hover:text-white rounded-lg text-sm font-medium transition-colors"
            >
              View Source
            </a>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-cyber-700 bg-cyber-900">
        <nav className="flex px-6">
          <button
            onClick={() => setActiveTab('normalized')}
            className={`px-4 py-3 text-sm font-medium border-b-2 -mb-px transition-colors ${
              activeTab === 'normalized'
                ? 'border-cyan-500 text-cyan-400 bg-cyber-850'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            Normalized View
          </button>
          <button
            onClick={() => setActiveTab('raw')}
            className={`px-4 py-3 text-sm font-medium border-b-2 -mb-px transition-colors ${
              activeTab === 'raw'
                ? 'border-cyan-500 text-cyan-400 bg-cyber-850'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            Raw Rule
          </button>
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === 'normalized' ? (
        <div className="p-6 space-y-6">
          {/* Description */}
          {detection.description && (
            <div>
              <p className="text-gray-300">{detection.description}</p>
            </div>
          )}

          {/* MITRE ATT&CK */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">
                MITRE Techniques
              </label>
              <div className="flex flex-wrap gap-2">
                {detection.mitre_techniques.length > 0 ? (
                  detection.mitre_techniques.map((tech) => {
                    const techniqueName = getTechniqueName(tech);
                    return (
                      <a
                        key={tech}
                        href={getTechniqueUrl(tech)}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center px-2.5 py-1 bg-blue-500/20 text-blue-400 rounded-lg text-sm hover:bg-blue-500/30 transition-colors border border-blue-500/30"
                      >
                        <span className="font-semibold">{tech}</span>
                        {techniqueName && <span className="ml-1.5 text-blue-300">· {techniqueName}</span>}
                      </a>
                    );
                  })
                ) : (
                  <span className="text-gray-500 italic text-sm">None mapped</span>
                )}
              </div>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">
                MITRE Tactics
              </label>
              <div className="flex flex-wrap gap-2">
                {detection.mitre_tactics.length > 0 ? (
                  detection.mitre_tactics.map((tactic) => (
                    <a
                      key={tactic}
                      href={getTacticUrl(tactic)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center px-2.5 py-1 bg-purple-500/20 text-purple-400 rounded-lg text-sm hover:bg-purple-500/30 transition-colors border border-purple-500/30"
                    >
                      <span className="font-semibold">{tactic}</span>
                      <span className="ml-1.5 text-purple-300">· {getTacticName(tactic)}</span>
                    </a>
                  ))
                ) : (
                  <span className="text-gray-500 italic text-sm">None mapped</span>
                )}
              </div>
            </div>
          </div>

          {/* Threat Actors + Software — only render when a rule has any.
              Populated from Sigma/LOLRMM `attack.g*` / `attack.s*` tags.
              Names resolve via mitreLookup; unknown IDs show the raw
              G-/S- form (still useful, never a fake name). */}
          {((detection.mitre_groups?.length || 0) > 0 || (detection.mitre_software?.length || 0) > 0) && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {(detection.mitre_groups?.length || 0) > 0 && (
                <div>
                  <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">
                    Threat Actors
                  </label>
                  <div className="flex flex-wrap gap-2">
                    {detection.mitre_groups!.map((gid) => {
                      const g = resolveGroup(gid);
                      const isKnown = g.name !== g.id;
                      return (
                        <Link
                          key={gid}
                          to={`/detections?mitre_groups=${g.id}`}
                          title={g.aliases.length ? `aka ${g.aliases.join(', ')}` : g.name}
                          className="inline-flex items-center px-2.5 py-1 bg-breach-500/15 text-breach-400 rounded-lg text-sm hover:bg-breach-500/25 transition-colors border border-breach-500/30"
                        >
                          <span className="font-semibold">{g.id}</span>
                          {isKnown && <span className="ml-1.5 text-breach-300">· {g.name}</span>}
                        </Link>
                      );
                    })}
                  </div>
                </div>
              )}
              {(detection.mitre_software?.length || 0) > 0 && (
                <div>
                  <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">
                    Software / Malware
                  </label>
                  <div className="flex flex-wrap gap-2">
                    {detection.mitre_software!.map((sid) => {
                      const s = resolveSoftware(sid);
                      const isKnown = s.name !== s.id;
                      const tone =
                        s.type === 'malware'
                          ? 'bg-orange-500/15 text-orange-400 border-orange-500/30 hover:bg-orange-500/25'
                          : 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30 hover:bg-cyan-500/25';
                      return (
                        <Link
                          key={sid}
                          to={`/detections?mitre_software=${s.id}`}
                          className={`inline-flex items-center px-2.5 py-1 rounded-lg text-sm transition-colors border ${tone}`}
                        >
                          <span className="font-semibold">{s.id}</span>
                          {isKnown && <span className="ml-1.5 opacity-80">· {s.name}</span>}
                        </Link>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Metadata Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-4 border-t border-cyber-700">
            <div>
              <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-1">Rule ID</label>
              <p className="font-mono text-sm text-gray-300 bg-cyber-900 px-2 py-1 rounded truncate" title={detection.rule_id || 'N/A'}>
                {detection.rule_id || 'N/A'}
              </p>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-1">Author</label>
              <p className="text-sm text-gray-300 truncate" title={detection.author || 'Unknown'}>
                {detection.author || 'Unknown'}
              </p>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-1">Created</label>
              <p className="text-sm text-gray-300">
                {detection.rule_created_date ? new Date(detection.rule_created_date).toLocaleDateString() : 'N/A'}
              </p>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-1">Modified</label>
              <p className="text-sm text-gray-300">
                {detection.rule_modified_date ? new Date(detection.rule_modified_date).toLocaleDateString() : 'N/A'}
              </p>
            </div>
          </div>

          {/* Canonical taxonomy -- the official platforms /
              data_sources / event_types fields. Multi-value because a
              single rule can legitimately span multiple OSes, data
              feeds, or event categories. */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div>
                <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">
                  Platforms
                </label>
                {detection.platforms && detection.platforms.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {detection.platforms.map((p) => (
                      <span
                        key={p}
                        className={`inline-flex px-2.5 py-1 rounded text-xs font-medium border ${
                          p === 'unknown'
                            ? 'bg-gray-500/20 text-gray-400 border-gray-500/30 italic'
                            : 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30'
                        }`}
                      >
                        {p}
                      </span>
                    ))}
                  </div>
                ) : (
                  <span className="text-gray-500 text-xs italic">(not populated)</span>
                )}
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">
                  Data Sources
                </label>
                {detection.data_sources && detection.data_sources.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {detection.data_sources.map((d) => (
                      <span
                        key={d}
                        className={`inline-flex px-2.5 py-1 rounded text-xs font-medium border ${
                          d === 'unknown'
                            ? 'bg-gray-500/20 text-gray-400 border-gray-500/30 italic'
                            : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                        }`}
                      >
                        {d}
                      </span>
                    ))}
                  </div>
                ) : (
                  <span className="text-gray-500 text-xs italic">(not populated)</span>
                )}
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">
                  Event Types
                </label>
                {detection.event_types && detection.event_types.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {detection.event_types.map((e) => (
                      <span
                        key={e}
                        className={`inline-flex px-2.5 py-1 rounded text-xs font-medium border ${
                          e === 'unknown'
                            ? 'bg-gray-500/20 text-gray-400 border-gray-500/30 italic'
                            : 'bg-orange-500/15 text-orange-300 border-orange-500/30'
                        }`}
                      >
                        {e}
                      </span>
                    ))}
                  </div>
                ) : (
                  <span className="text-gray-500 text-xs italic">(not populated)</span>
                )}
              </div>
          </div>

          {/* Extracted Observables: typed view (observables v2) */}
          {((detection.extracted_observables?.length ?? 0) > 0 ||
            (detection.extracted_source_tables?.length ?? 0) > 0) && (
            <div className="pt-4 border-t border-cyber-700">
              <ObservablesPanel
                observables={detection.extracted_observables || []}
                sourceTables={detection.extracted_source_tables || []}
                complexity={detection.query_complexity}
                eventIdLabels={eventIdLabels}
              />
            </div>
          )}

          {/* Tags */}
          <div className="grid grid-cols-1 gap-6">
            <div>
              <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">Tags</label>
              <div className="flex flex-wrap gap-1.5">
                {detection.tags.length > 0 ? (
                  detection.tags.slice(0, 10).map((tag) => (
                    <span key={tag} className="px-2 py-0.5 bg-cyber-700 text-gray-400 rounded text-sm">
                      {tag}
                    </span>
                  ))
                ) : (
                  <span className="text-gray-500 text-sm italic">None</span>
                )}
                {detection.tags.length > 10 && (
                  <span className="px-2 py-0.5 text-gray-500 text-sm">+{detection.tags.length - 10} more</span>
                )}
              </div>
            </div>
          </div>

          {/* References */}
          {detection.references && detection.references.length > 0 && (
            <div>
              <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">References</label>
              <ul className="space-y-1">
                {detection.references.map((ref, index) => (
                  <li key={index}>
                    {ref.startsWith('http') ? (
                      <a
                        href={ref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-cyan-400 hover:text-cyan-300 hover:underline break-all"
                      >
                        {ref}
                      </a>
                    ) : (
                      <span className="text-sm text-gray-400">{ref}</span>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* False Positives */}
          {detection.false_positives && detection.false_positives.length > 0 && (
            <div>
              <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">False Positives</label>
              <ul className="space-y-1">
                {detection.false_positives.map((fp, index) => (
                  <li key={index} className="text-sm text-gray-400">• {fp}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Hygiene score (issue #10) — five-dimension rubric bars */}
          {detection.quality_details && (
            <div>
              <div className="flex items-center gap-2 mb-2">
                <label className="text-xs font-medium text-gray-500 uppercase tracking-wide">
                  Hygiene Score
                </label>
                <span
                  className="text-sm font-mono text-white tabular-nums"
                  title="Deterministic 0-100 rubric over metadata, ATT&CK mapping, specificity, documentation, testability"
                >
                  {detection.quality_details.total}/100
                </span>
                <span className="text-[10px] font-mono text-gray-600">
                  measures rule hygiene, not detection accuracy
                </span>
              </div>
              <div className="space-y-1.5">
                {Object.entries(detection.quality_details.dimensions).map(([name, dim]) => (
                  <div key={name} className="flex items-center gap-2">
                    <span className="text-[11px] font-mono text-gray-500 uppercase w-32 shrink-0">
                      {name}
                    </span>
                    <div className="flex-1 h-1.5 bg-cyber-800 rounded overflow-hidden">
                      <div
                        className={`h-full ${
                          dim.score >= dim.of * 0.75
                            ? 'bg-green-500'
                            : dim.score >= dim.of * 0.4
                              ? 'bg-amber-500'
                              : 'bg-red-500'
                        }`}
                        style={{ width: `${(dim.score / dim.of) * 100}%` }}
                      />
                    </div>
                    <span className="text-[11px] font-mono text-gray-400 tabular-nums w-10 text-right shrink-0">
                      {dim.score}/{dim.of}
                    </span>
                    {dim.issues.length > 0 && (
                      <span
                        className="text-[10px] font-mono text-gray-600 shrink-0 cursor-help"
                        title={dim.issues.join('\n')}
                      >
                        {dim.issues.length} issue{dim.issues.length > 1 ? 's' : ''}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Detection Logic */}
          <div className="pt-4 border-t border-cyber-700">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <label className="text-xs font-medium text-gray-500 uppercase tracking-wide">Detection Logic</label>
                <span className="px-1.5 py-0.5 bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 rounded text-xs font-semibold uppercase">
                  {detection.language || 'unknown'}
                </span>
              </div>
              {detection.detection_logic && (
                <CopyButton text={detection.detection_logic} label="Copy Logic" />
              )}
            </div>
            <div className="rounded-lg overflow-hidden border border-cyber-700">
              <SyntaxHighlighter
                language={languageMap[detection.language?.toLowerCase() || 'unknown'] || 'yaml'}
                style={oneDark}
                customStyle={{
                  margin: 0,
                  padding: '1rem',
                  fontSize: '0.875rem',
                  lineHeight: '1.625',
                  background: 'rgb(17, 24, 39)',
                }}
                showLineNumbers
                lineNumberStyle={{
                  minWidth: '2.5em',
                  paddingRight: '1em',
                  color: '#4b5563',
                  borderRight: '1px solid #374151',
                  marginRight: '1em',
                }}
              >
                {detection.detection_logic || 'No detection logic available'}
              </SyntaxHighlighter>
            </div>
          </div>

          {/* Find Related Detections Button */}
          <div className="flex justify-center pt-4">
            <Link
              to={detection.mitre_techniques.length > 0
                ? `/compare?technique=${detection.mitre_techniques[0]}`
                : `/compare?keyword=${encodeURIComponent(detection.title.split(' ').slice(0, 3).join(' '))}`
              }
              className="inline-flex items-center gap-2 px-6 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-400 hover:to-blue-400 text-white rounded-lg font-medium transition-all shadow-glow-cyan"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              Find Related Detections
            </Link>
          </div>

          {/* Footer */}
          <div className="pt-4 border-t border-cyber-700 flex items-center justify-between text-sm">
            <span className="text-gray-500">
              Source: <span className="font-mono text-gray-400">{detection.source_file}</span>
            </span>
            <span className="text-gray-600">Synced: {new Date(detection.updated_at).toLocaleString()}</span>
          </div>
        </div>
      ) : (
        <div className="p-6">
          <div className="flex items-center justify-between mb-2">
            <label className="text-xs font-medium text-gray-500 uppercase tracking-wide">Raw Rule Content</label>
            {detection.raw_content && (
              <CopyButton text={detection.raw_content} label="Copy Raw" />
            )}
          </div>
          <div className="rounded-lg overflow-hidden border border-cyber-700">
            <SyntaxHighlighter
              language={languageMap[detection.language?.toLowerCase() || 'unknown'] || 'yaml'}
              style={oneDark}
              customStyle={{
                margin: 0,
                padding: '1rem',
                fontSize: '0.875rem',
                lineHeight: '1.625',
                background: 'rgb(17, 24, 39)',
              }}
              showLineNumbers
              lineNumberStyle={{
                minWidth: '2.5em',
                paddingRight: '1em',
                color: '#4b5563',
                borderRight: '1px solid #374151',
                marginRight: '1em',
              }}
            >
              {detection.raw_content || 'No raw content available'}
            </SyntaxHighlighter>
          </div>
        </div>
      )}
    </div>
  );
}
