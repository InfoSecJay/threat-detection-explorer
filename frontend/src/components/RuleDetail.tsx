import { useState } from 'react';
import { Link } from 'react-router-dom';
import type { Detection } from '../types';
import { useMitre } from '../contexts/MitreContext';

interface RuleDetailProps {
  detection: Detection;
}

const severityColors: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 border-red-200',
  high: 'bg-orange-100 text-orange-800 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  low: 'bg-green-100 text-green-800 border-green-200',
  unknown: 'bg-gray-100 text-gray-800 border-gray-200',
};

const statusColors: Record<string, string> = {
  stable: 'bg-green-100 text-green-800 border-green-200',
  experimental: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  deprecated: 'bg-red-100 text-red-800 border-red-200',
  unknown: 'bg-gray-100 text-gray-800 border-gray-200',
};

const sourceColors: Record<string, string> = {
  sigma: 'bg-blue-600',
  elastic: 'bg-amber-500',
  splunk: 'bg-green-600',
  sublime: 'bg-purple-600',
  elastic_protections: 'bg-amber-600',
  lolrmm: 'bg-rose-600',
};

export function RuleDetail({ detection }: RuleDetailProps) {
  const { getTacticName, getTechniqueName, getTacticUrl, getTechniqueUrl } = useMitre();
  const [activeTab, setActiveTab] = useState<'normalized' | 'raw'>('normalized');

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
      {/* Color bar */}
      <div className={`h-1.5 ${sourceColors[detection.source] || 'bg-gray-400'}`} />

      {/* Header */}
      <div className="px-6 py-4 border-b border-gray-200">
        <div className="flex items-center justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2 py-0.5 bg-gray-100 text-gray-700 rounded text-xs font-semibold uppercase">
                {detection.source.replace('_', ' ')}
              </span>
              <span className="px-2 py-0.5 bg-indigo-100 text-indigo-700 rounded text-xs font-semibold uppercase">
                {detection.language || 'unknown'}
              </span>
              <span className={`px-2 py-0.5 rounded text-xs font-semibold capitalize border ${severityColors[detection.severity]}`}>
                {detection.severity}
              </span>
              <span className={`px-2 py-0.5 rounded text-xs font-semibold capitalize border ${statusColors[detection.status]}`}>
                {detection.status}
              </span>
            </div>
            <h1 className="text-xl font-bold text-gray-900">{detection.title}</h1>
          </div>
          {detection.source_rule_url && (
            <a
              href={detection.source_rule_url}
              target="_blank"
              rel="noopener noreferrer"
              className="flex-shrink-0 px-3 py-1.5 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-lg text-sm font-medium transition-colors"
            >
              View Source
            </a>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200 bg-gray-50">
        <nav className="flex px-6">
          <button
            onClick={() => setActiveTab('normalized')}
            className={`px-4 py-3 text-sm font-medium border-b-2 -mb-px transition-colors ${
              activeTab === 'normalized'
                ? 'border-blue-500 text-blue-600 bg-white'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            Normalized View
          </button>
          <button
            onClick={() => setActiveTab('raw')}
            className={`px-4 py-3 text-sm font-medium border-b-2 -mb-px transition-colors ${
              activeTab === 'raw'
                ? 'border-blue-500 text-blue-600 bg-white'
                : 'border-transparent text-gray-500 hover:text-gray-700'
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
              <p className="text-gray-600">{detection.description}</p>
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
                        className="inline-flex items-center px-2.5 py-1 bg-blue-50 text-blue-700 rounded-lg text-sm hover:bg-blue-100 transition-colors border border-blue-200"
                      >
                        <span className="font-semibold">{tech}</span>
                        {techniqueName && <span className="ml-1.5 text-blue-600">· {techniqueName}</span>}
                      </a>
                    );
                  })
                ) : (
                  <span className="text-gray-400 italic text-sm">None mapped</span>
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
                      className="inline-flex items-center px-2.5 py-1 bg-purple-50 text-purple-700 rounded-lg text-sm hover:bg-purple-100 transition-colors border border-purple-200"
                    >
                      <span className="font-semibold">{tactic}</span>
                      <span className="ml-1.5 text-purple-600">· {getTacticName(tactic)}</span>
                    </a>
                  ))
                ) : (
                  <span className="text-gray-400 italic text-sm">None mapped</span>
                )}
              </div>
            </div>
          </div>

          {/* Metadata Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-4 border-t border-gray-100">
            <div>
              <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-1">Rule ID</label>
              <p className="font-mono text-sm text-gray-900 bg-gray-50 px-2 py-1 rounded truncate" title={detection.rule_id || 'N/A'}>
                {detection.rule_id || 'N/A'}
              </p>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-1">Author</label>
              <p className="text-sm text-gray-900 truncate" title={detection.author || 'Unknown'}>
                {detection.author || 'Unknown'}
              </p>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-1">Created</label>
              <p className="text-sm text-gray-900">
                {detection.rule_created_date ? new Date(detection.rule_created_date).toLocaleDateString() : 'N/A'}
              </p>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-1">Modified</label>
              <p className="text-sm text-gray-900">
                {detection.rule_modified_date ? new Date(detection.rule_modified_date).toLocaleDateString() : 'N/A'}
              </p>
            </div>
          </div>

          {/* Log Sources & Tags */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">Log Sources</label>
              <div className="flex flex-wrap gap-1.5">
                {detection.log_sources.length > 0 ? (
                  detection.log_sources.map((source) => (
                    <span key={source} className="px-2 py-0.5 bg-gray-100 text-gray-700 rounded text-sm">
                      {source}
                    </span>
                  ))
                ) : (
                  <span className="text-gray-400 text-sm italic">None specified</span>
                )}
              </div>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">Tags</label>
              <div className="flex flex-wrap gap-1.5">
                {detection.tags.length > 0 ? (
                  detection.tags.slice(0, 10).map((tag) => (
                    <span key={tag} className="px-2 py-0.5 bg-slate-100 text-slate-600 rounded text-sm">
                      {tag}
                    </span>
                  ))
                ) : (
                  <span className="text-gray-400 text-sm italic">None</span>
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
                        className="text-sm text-blue-600 hover:text-blue-800 hover:underline break-all"
                      >
                        {ref}
                      </a>
                    ) : (
                      <span className="text-sm text-gray-700">{ref}</span>
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
                  <li key={index} className="text-sm text-gray-700">• {fp}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Detection Logic */}
          <div className="pt-4 border-t border-gray-100">
            <div className="flex items-center gap-2 mb-2">
              <label className="text-xs font-medium text-gray-500 uppercase tracking-wide">Detection Logic</label>
              <span className="px-1.5 py-0.5 bg-indigo-100 text-indigo-700 rounded text-xs font-semibold uppercase">
                {detection.language || 'unknown'}
              </span>
            </div>
            <pre className="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-auto text-sm font-mono leading-relaxed">
              {detection.detection_logic}
            </pre>
          </div>

          {/* Compare Button */}
          <div className="flex justify-center pt-4">
            {detection.mitre_techniques.length > 0 ? (
              <Link
                to={`/compare?technique=${detection.mitre_techniques[0]}`}
                className="inline-flex items-center gap-2 px-6 py-2.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
                Compare {detection.mitre_techniques[0]} Across Vendors
              </Link>
            ) : (
              <Link
                to={`/compare?keyword=${encodeURIComponent(detection.title.split(' ').slice(0, 3).join(' '))}`}
                className="inline-flex items-center gap-2 px-6 py-2.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
                Find Similar Rules
              </Link>
            )}
          </div>

          {/* Footer */}
          <div className="pt-4 border-t border-gray-100 flex items-center justify-between text-sm">
            <span className="text-gray-500">
              Source: <span className="font-mono text-gray-700">{detection.source_file}</span>
            </span>
            <span className="text-gray-400">Synced: {new Date(detection.updated_at).toLocaleString()}</span>
          </div>
        </div>
      ) : (
        <div className="p-6">
          <pre className="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-auto text-sm font-mono leading-relaxed">
            {detection.raw_content}
          </pre>
        </div>
      )}
    </div>
  );
}
