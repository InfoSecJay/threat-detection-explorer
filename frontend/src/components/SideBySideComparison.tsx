import { useState } from 'react';
import { Link } from 'react-router-dom';
import type { Detection, SideBySideResponse } from '../types';

interface SideBySideComparisonProps {
  data: SideBySideResponse;
}

const severityColors: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-green-500/20 text-green-400 border-green-500/30',
  unknown: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};

const sourceColors: Record<string, string> = {
  sigma: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  elastic: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  splunk: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  sublime: 'bg-pink-500/20 text-pink-400 border-pink-500/30',
  elastic_protections: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
  lolrmm: 'bg-green-500/20 text-green-400 border-green-500/30',
};

const sourceLabels: Record<string, string> = {
  sigma: 'Sigma',
  elastic: 'Elastic',
  splunk: 'Splunk',
  sublime: 'Sublime',
  elastic_protections: 'Elastic Protect',
  lolrmm: 'LOLRMM',
};

// Check if a field differs between detections
function fieldDiffers(detections: Detection[], field: keyof Detection): boolean {
  if (detections.length < 2) return false;
  const first = detections[0][field];
  return detections.some((d) => {
    const val = d[field];
    if (Array.isArray(first) && Array.isArray(val)) {
      return JSON.stringify(first) !== JSON.stringify(val);
    }
    return val !== first;
  });
}

interface RulePanelProps {
  detection: Detection;
  allDetections: Detection[];
}

function RulePanel({ detection, allDetections }: RulePanelProps) {
  const isDiff = (field: keyof Detection) => fieldDiffers(allDetections, field);

  const DiffBadge = ({ field }: { field: keyof Detection }) =>
    isDiff(field) ? (
      <span className="ml-2 px-1.5 py-0.5 bg-amber-500/20 text-amber-400 text-xs rounded">
        DIFF
      </span>
    ) : null;

  const MetadataRow = ({
    label,
    value,
    field,
    badge,
  }: {
    label: string;
    value: React.ReactNode;
    field: keyof Detection;
    badge?: React.ReactNode;
  }) => (
    <div
      className={`flex items-start justify-between py-2 px-3 ${
        isDiff(field) ? 'bg-amber-500/5' : ''
      }`}
    >
      <span className="text-gray-500 text-sm flex items-center">
        {label}
        <DiffBadge field={field} />
      </span>
      <div className="text-right">{badge || <span className="text-gray-300 text-sm">{value || '-'}</span>}</div>
    </div>
  );

  return (
    <div className="flex flex-col h-full bg-cyber-850 rounded-lg border border-cyber-700 overflow-hidden">
      {/* Panel Header */}
      <div className="bg-cyber-900 px-4 py-3 border-b border-cyber-700 flex-shrink-0">
        <div className="flex items-start justify-between gap-2">
          <div className="flex-1 min-w-0">
            <Link
              to={`/detections/${detection.id}`}
              className="text-cyan-400 hover:text-cyan-300 hover:underline font-medium text-sm block truncate"
              title={detection.title}
            >
              {detection.title}
            </Link>
          </div>
          <span
            className={`px-2 py-1 rounded text-xs border flex-shrink-0 ${
              sourceColors[detection.source] || ''
            }`}
          >
            {sourceLabels[detection.source] || detection.source}
          </span>
        </div>
      </div>

      {/* Scrollable Content */}
      <div className="flex-1 overflow-y-auto">
        {/* Metadata Section */}
        <div className="divide-y divide-cyber-700/50">
          <MetadataRow
            label="Severity"
            value={detection.severity}
            field="severity"
            badge={
              <span
                className={`px-2 py-1 rounded text-xs border ${
                  severityColors[detection.severity] || ''
                }`}
              >
                {detection.severity}
              </span>
            }
          />
          <MetadataRow label="Status" value={detection.status} field="status" />
          <MetadataRow label="Language" value={detection.language} field="language" />
          <MetadataRow label="Platform" value={detection.platform} field="platform" />
          <MetadataRow
            label="Event Category"
            value={detection.event_category}
            field="event_category"
          />
          <MetadataRow
            label="Data Source"
            value={detection.data_source_normalized}
            field="data_source_normalized"
          />
          <MetadataRow
            label="MITRE Tactics"
            value={detection.mitre_tactics?.join(', ')}
            field="mitre_tactics"
          />
          <MetadataRow
            label="MITRE Techniques"
            value={detection.mitre_techniques?.join(', ')}
            field="mitre_techniques"
          />
          <MetadataRow
            label="Log Sources"
            value={detection.log_sources?.join(', ')}
            field="log_sources"
          />
        </div>

        {/* Description */}
        <div className={`p-4 border-t border-cyber-700 ${isDiff('description') ? 'bg-amber-500/5' : ''}`}>
          <h4 className="text-sm font-medium text-gray-400 mb-2 flex items-center">
            Description
            <DiffBadge field="description" />
          </h4>
          <p className="text-sm text-gray-300 leading-relaxed">
            {detection.description || 'No description available'}
          </p>
        </div>

        {/* Detection Logic */}
        <div className={`p-4 border-t border-cyber-700 ${isDiff('detection_logic') ? 'bg-amber-500/5' : ''}`}>
          <h4 className="text-sm font-medium text-gray-400 mb-2 flex items-center">
            Detection Logic
            <DiffBadge field="detection_logic" />
            <span className="ml-auto text-xs text-gray-500 uppercase">
              {detection.language}
            </span>
          </h4>
          <pre className="text-xs text-gray-300 bg-cyber-900 p-4 rounded-lg overflow-x-auto whitespace-pre-wrap font-mono leading-relaxed">
            {detection.detection_logic || 'No detection logic available'}
          </pre>
        </div>
      </div>
    </div>
  );
}

export function SideBySideComparison({ data }: SideBySideComparisonProps) {
  const [syncScroll, setSyncScroll] = useState(false);
  const numPanels = data.detections.length;

  // Calculate grid columns based on number of detections
  const gridCols =
    numPanels === 2
      ? 'grid-cols-2'
      : numPanels === 3
      ? 'grid-cols-3'
      : numPanels === 4
      ? 'grid-cols-2 lg:grid-cols-4'
      : numPanels === 5
      ? 'grid-cols-2 lg:grid-cols-5'
      : 'grid-cols-2 lg:grid-cols-3';

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-white">
          Side-by-Side Comparison ({numPanels} rules)
        </h2>
        <div className="flex items-center gap-4">
          <label className="flex items-center text-gray-300 cursor-pointer">
            <input
              type="checkbox"
              checked={syncScroll}
              onChange={(e) => setSyncScroll(e.target.checked)}
              className="mr-2 rounded bg-cyber-900 border-cyber-600 text-cyan-500 focus:ring-cyan-500"
            />
            <span className="text-sm">Sync scroll</span>
          </label>
        </div>
      </div>

      {/* Diff Legend */}
      <div className="flex items-center gap-4 text-sm text-gray-400">
        <span className="flex items-center gap-1">
          <span className="px-1.5 py-0.5 bg-amber-500/20 text-amber-400 text-xs rounded">
            DIFF
          </span>
          indicates values differ between rules
        </span>
      </div>

      {/* Split Panels */}
      <div
        className={`grid ${gridCols} gap-4`}
        style={{ height: 'calc(100vh - 280px)', minHeight: '600px' }}
      >
        {data.detections.map((detection) => (
          <RulePanel
            key={detection.id}
            detection={detection}
            allDetections={data.detections}
          />
        ))}
      </div>
    </div>
  );
}
