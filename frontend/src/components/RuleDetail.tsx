/** Single-rule detail card. Sections live in components/ruledetail/. */

import { parseApiDate } from '../utils/dates';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import type { Detection } from '../types';
import { ObservablesPanel } from './ObservablesPanel';
import { useEventIds } from '../hooks/useEventIds';
import { CopyButton } from './ruledetail/CopyButton';
import { CodeBlock } from './ruledetail/CodeBlock';
import { AttackSection } from './ruledetail/AttackSection';
import { TaxonomyChips } from './ruledetail/TaxonomyChips';
import { RuleNotes } from './ruledetail/RuleNotes';
import { HygieneBars } from './ruledetail/HygieneBars';

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

export function RuleDetail({ detection }: RuleDetailProps) {
  const { labels: eventIdLabels } = useEventIds();
  const [activeTab, setActiveTab] = useState<'normalized' | 'raw'>('normalized');

  return (
    <div className="bg-void-850 rounded-xl border border-void-700 overflow-hidden">
      {/* Color bar */}
      <div className={`h-1.5 bg-gradient-to-r ${sourceGradients[detection.source] || 'from-gray-500 to-gray-600'}`} />

      {/* Header */}
      <div className="px-6 py-4 border-b border-void-700">
        <div className="flex items-center justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2 py-0.5 bg-void-700 text-gray-300 rounded text-xs font-semibold uppercase">
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
              className="flex-shrink-0 px-3 py-1.5 bg-void-700 hover:bg-void-600 text-gray-300 hover:text-white rounded-lg text-sm font-medium transition-colors"
            >
              View Source
            </a>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-void-700 bg-void-900">
        <nav className="flex px-6">
          <button
            onClick={() => setActiveTab('normalized')}
            className={`px-4 py-3 text-sm font-medium border-b-2 -mb-px transition-colors ${
              activeTab === 'normalized'
                ? 'border-cyan-500 text-cyan-400 bg-void-850'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            Normalized View
          </button>
          <button
            onClick={() => setActiveTab('raw')}
            className={`px-4 py-3 text-sm font-medium border-b-2 -mb-px transition-colors ${
              activeTab === 'raw'
                ? 'border-cyan-500 text-cyan-400 bg-void-850'
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

          <AttackSection detection={detection} />


          {/* Metadata Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-4 border-t border-void-700">
            <div>
              <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-1">Rule ID</label>
              <p className="font-mono text-sm text-gray-300 bg-void-900 px-2 py-1 rounded truncate" title={detection.rule_id || 'N/A'}>
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
                {detection.rule_created_date ? parseApiDate(detection.rule_created_date).toLocaleDateString() : 'N/A'}
              </p>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-1">Modified</label>
              <p className="text-sm text-gray-300">
                {detection.rule_modified_date ? parseApiDate(detection.rule_modified_date).toLocaleDateString() : 'N/A'}
              </p>
            </div>
          </div>

          <TaxonomyChips detection={detection} />


          {/* Extracted Observables: typed view (observables v2) */}
          {((detection.extracted_observables?.length ?? 0) > 0 ||
            (detection.extracted_source_tables?.length ?? 0) > 0) && (
            <div className="pt-4 border-t border-void-700">
              <ObservablesPanel
                observables={detection.extracted_observables || []}
                sourceTables={detection.extracted_source_tables || []}
                complexity={detection.query_complexity}
                eventIdLabels={eventIdLabels}
              />
            </div>
          )}

          <RuleNotes detection={detection} />

          {detection.quality_details && <HygieneBars details={detection.quality_details} />}

          {/* Detection Logic */}
          <div className="pt-4 border-t border-void-700">
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
            <CodeBlock language={detection.language} code={detection.detection_logic} fallback="No detection logic available" />
          </div>


          {/* Find Related Detections Button */}
          <div className="flex justify-center pt-4">
            <Link
              // /compare is hidden pending its rework (#11) and redirects
              // to Home, so route to the catalog filtered the same way.
              to={detection.mitre_techniques.length > 0
                ? `/detections?mitre_techniques=${detection.mitre_techniques[0]}`
                : `/detections?search=${encodeURIComponent(detection.title.split(' ').slice(0, 3).join(' '))}`
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
          <div className="pt-4 border-t border-void-700 flex items-center justify-between text-sm">
            <span className="text-gray-500">
              Source: <span className="font-mono text-gray-400">{detection.source_file}</span>
            </span>
            <span className="text-gray-600">Synced: {parseApiDate(detection.updated_at).toLocaleString()}</span>
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
          <CodeBlock language={detection.language} code={detection.raw_content} fallback="No raw content available" />
        </div>
      )}
    </div>
  );
}
