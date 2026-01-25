import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism';
import type { Detection } from '../types';
import { useMitre } from '../contexts/MitreContext';

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
  experimental: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  deprecated: 'bg-red-500/20 text-red-400 border-red-500/30',
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

export function RuleDetail({ detection }: RuleDetailProps) {
  const { getTacticName, getTechniqueName, getTacticUrl, getTechniqueUrl } = useMitre();
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
              <span className={`px-2 py-0.5 rounded text-xs font-semibold capitalize border ${statusColors[detection.status]}`}>
                {detection.status}
              </span>
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

          {/* Platform & Event Category */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div>
              <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">Platform</label>
              {detection.platform ? (
                <span className="inline-flex px-3 py-1.5 bg-cyan-500/20 text-cyan-400 rounded-lg text-sm font-medium border border-cyan-500/30">
                  {detection.platform.replace(/_/g, ' ').toUpperCase()}
                </span>
              ) : (
                <span className="text-gray-500 text-sm italic">Not specified</span>
              )}
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">Event Category</label>
              {detection.event_category ? (
                <span className="inline-flex px-3 py-1.5 bg-orange-500/20 text-orange-400 rounded-lg text-sm font-medium border border-orange-500/30">
                  {detection.event_category.replace(/_/g, ' ').toUpperCase()}
                </span>
              ) : (
                <span className="text-gray-500 text-sm italic">Not specified</span>
              )}
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">Data Source</label>
              {detection.data_source_normalized ? (
                <span className="inline-flex px-3 py-1.5 bg-emerald-500/20 text-emerald-400 rounded-lg text-sm font-medium border border-emerald-500/30">
                  {detection.data_source_normalized.replace(/_/g, ' ').toUpperCase()}
                </span>
              ) : (
                <span className="text-gray-500 text-sm italic">Not specified</span>
              )}
            </div>
          </div>

          {/* Log Sources & Tags */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">Log Sources</label>
              <div className="flex flex-wrap gap-1.5">
                {detection.log_sources.length > 0 ? (
                  detection.log_sources.map((source) => (
                    <span key={source} className="px-2 py-0.5 bg-cyber-700 text-gray-300 rounded text-sm">
                      {source}
                    </span>
                  ))
                ) : (
                  <span className="text-gray-500 text-sm italic">None specified</span>
                )}
              </div>
            </div>
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

          {/* Detection Logic */}
          <div className="pt-4 border-t border-cyber-700">
            <div className="flex items-center gap-2 mb-2">
              <label className="text-xs font-medium text-gray-500 uppercase tracking-wide">Detection Logic</label>
              <span className="px-1.5 py-0.5 bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 rounded text-xs font-semibold uppercase">
                {detection.language || 'unknown'}
              </span>
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
