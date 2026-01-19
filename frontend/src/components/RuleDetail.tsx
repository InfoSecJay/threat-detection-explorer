import { useState } from 'react';
import type { Detection } from '../types';

interface RuleDetailProps {
  detection: Detection;
}

const severityColors: Record<string, string> = {
  critical: 'bg-red-100 text-red-800',
  high: 'bg-orange-100 text-orange-800',
  medium: 'bg-yellow-100 text-yellow-800',
  low: 'bg-green-100 text-green-800',
  unknown: 'bg-gray-100 text-gray-800',
};

const statusColors: Record<string, string> = {
  stable: 'bg-green-100 text-green-800',
  experimental: 'bg-yellow-100 text-yellow-800',
  deprecated: 'bg-red-100 text-red-800',
  unknown: 'bg-gray-100 text-gray-800',
};

export function RuleDetail({ detection }: RuleDetailProps) {
  const [activeTab, setActiveTab] = useState<'normalized' | 'raw'>('normalized');

  return (
    <div className="bg-white rounded-lg shadow">
      {/* Header */}
      <div className="p-6 border-b">
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">{detection.title}</h1>
            <p className="text-gray-600 mt-2">{detection.description || 'No description'}</p>
          </div>
          <div className="flex gap-2">
            <span
              className={`px-3 py-1 rounded-full text-sm font-medium capitalize ${
                severityColors[detection.severity]
              }`}
            >
              {detection.severity}
            </span>
            <span
              className={`px-3 py-1 rounded-full text-sm font-medium capitalize ${
                statusColors[detection.status]
              }`}
            >
              {detection.status}
            </span>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b">
        <nav className="flex -mb-px">
          <button
            onClick={() => setActiveTab('normalized')}
            className={`px-6 py-3 text-sm font-medium border-b-2 ${
              activeTab === 'normalized'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            Normalized View
          </button>
          <button
            onClick={() => setActiveTab('raw')}
            className={`px-6 py-3 text-sm font-medium border-b-2 ${
              activeTab === 'raw'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            Raw Content
          </button>
        </nav>
      </div>

      {/* Content */}
      <div className="p-6">
        {activeTab === 'normalized' ? (
          <div className="space-y-6">
            {/* Metadata */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-500">Source</label>
                <p className="mt-1 capitalize">{detection.source.replace('_', ' ')}</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-500">Rule ID</label>
                <p className="mt-1 font-mono text-sm">{detection.rule_id || 'N/A'}</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-500">Author</label>
                <p className="mt-1">{detection.author || 'Unknown'}</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-500">Source File</label>
                {detection.source_rule_url ? (
                  <a
                    href={detection.source_rule_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="mt-1 font-mono text-sm break-all text-blue-600 hover:underline block"
                  >
                    {detection.source_file}
                  </a>
                ) : (
                  <p className="mt-1 font-mono text-sm break-all">{detection.source_file}</p>
                )}
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-500">Rule Created</label>
                <p className="mt-1">
                  {detection.rule_created_date
                    ? new Date(detection.rule_created_date).toLocaleDateString()
                    : 'N/A'}
                </p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-500">Rule Modified</label>
                <p className="mt-1">
                  {detection.rule_modified_date
                    ? new Date(detection.rule_modified_date).toLocaleDateString()
                    : 'N/A'}
                </p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-500">Last Sync Update</label>
                <p className="mt-1">{new Date(detection.updated_at).toLocaleString()}</p>
              </div>
            </div>

            {/* MITRE ATT&CK */}
            <div>
              <label className="block text-sm font-medium text-gray-500 mb-2">
                MITRE ATT&CK Techniques
              </label>
              <div className="flex flex-wrap gap-2">
                {detection.mitre_techniques.length > 0 ? (
                  detection.mitre_techniques.map((tech) => (
                    <a
                      key={tech}
                      href={`https://attack.mitre.org/techniques/${tech.replace('.', '/')}/`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-3 py-1 bg-blue-100 text-blue-800 rounded-full text-sm hover:bg-blue-200"
                    >
                      {tech}
                    </a>
                  ))
                ) : (
                  <span className="text-gray-500">None mapped</span>
                )}
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-500 mb-2">
                MITRE ATT&CK Tactics
              </label>
              <div className="flex flex-wrap gap-2">
                {detection.mitre_tactics.length > 0 ? (
                  detection.mitre_tactics.map((tactic) => (
                    <span
                      key={tactic}
                      className="px-3 py-1 bg-purple-100 text-purple-800 rounded-full text-sm"
                    >
                      {tactic}
                    </span>
                  ))
                ) : (
                  <span className="text-gray-500">None mapped</span>
                )}
              </div>
            </div>

            {/* Log Sources */}
            <div>
              <label className="block text-sm font-medium text-gray-500 mb-2">
                Log Sources
              </label>
              <div className="flex flex-wrap gap-2">
                {detection.log_sources.length > 0 ? (
                  detection.log_sources.map((source) => (
                    <span
                      key={source}
                      className="px-3 py-1 bg-gray-100 text-gray-700 rounded-full text-sm"
                    >
                      {source}
                    </span>
                  ))
                ) : (
                  <span className="text-gray-500">None specified</span>
                )}
              </div>
            </div>

            {/* Detection Logic */}
            <div>
              <label className="block text-sm font-medium text-gray-500 mb-2">
                Detection Logic Summary
              </label>
              <div className="bg-gray-50 p-4 rounded-lg">
                <pre className="whitespace-pre-wrap text-sm font-mono">
                  {detection.detection_logic}
                </pre>
              </div>
            </div>

            {/* Tags */}
            {detection.tags.length > 0 && (
              <div>
                <label className="block text-sm font-medium text-gray-500 mb-2">Tags</label>
                <div className="flex flex-wrap gap-2">
                  {detection.tags.map((tag) => (
                    <span
                      key={tag}
                      className="px-2 py-1 bg-gray-100 text-gray-600 rounded text-sm"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* References */}
            {detection.references && detection.references.length > 0 && (
              <div>
                <label className="block text-sm font-medium text-gray-500 mb-2">References</label>
                <ul className="space-y-1">
                  {detection.references.map((ref, index) => (
                    <li key={index}>
                      {ref.startsWith('http') ? (
                        <a
                          href={ref}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 hover:underline text-sm break-all"
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
          </div>
        ) : (
          <div>
            <pre className="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto text-sm">
              {detection.raw_content}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
