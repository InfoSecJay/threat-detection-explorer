import { Link } from 'react-router-dom';
import type { Detection, CompareResponse } from '../types';

interface RuleComparisonProps {
  data: CompareResponse;
}

const sourceColors: Record<string, string> = {
  sigma: 'border-purple-500 bg-purple-500/10',
  elastic: 'border-blue-500 bg-blue-500/10',
  splunk: 'border-orange-500 bg-orange-500/10',
  sublime: 'border-pink-500 bg-pink-500/10',
  elastic_protections: 'border-cyan-500 bg-cyan-500/10',
  lolrmm: 'border-green-500 bg-green-500/10',
};

const sourceNames: Record<string, string> = {
  sigma: 'Sigma',
  elastic: 'Elastic',
  splunk: 'Splunk',
  sublime: 'Sublime',
  elastic_protections: 'Elastic Protections',
  lolrmm: 'LOLRMM',
};

const severityColors: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400',
  high: 'bg-orange-500/20 text-orange-400',
  medium: 'bg-yellow-500/20 text-yellow-400',
  low: 'bg-green-500/20 text-green-400',
  unknown: 'bg-gray-500/20 text-gray-400',
};

function DetectionCard({ detection }: { detection: Detection }) {
  return (
    <Link
      to={`/detections/${detection.id}`}
      className="block p-3 bg-cyber-900 rounded border border-cyber-700 hover:border-cyan-500/30 transition-all"
    >
      <h4 className="font-medium text-sm text-gray-200 truncate">{detection.title}</h4>
      <p className="text-xs text-gray-500 mt-1 line-clamp-2">
        {detection.description || 'No description'}
      </p>
      <div className="flex items-center gap-2 mt-2">
        <span
          className={`px-2 py-0.5 rounded text-xs font-medium ${
            severityColors[detection.severity]
          }`}
        >
          {detection.severity}
        </span>
        <span className="text-xs text-gray-500">{detection.status}</span>
      </div>
    </Link>
  );
}

export function RuleComparison({ data }: RuleComparisonProps) {
  const sources = ['sigma', 'elastic', 'splunk', 'sublime', 'elastic_protections', 'lolrmm'];
  const totalCount = Object.values(data.total_by_source).reduce((a, b) => a + b, 0);

  return (
    <div>
      {/* Header */}
      <div className="mb-6">
        <h2 className="text-xl font-bold text-white">
          Comparison: {data.query_type === 'technique' ? 'Technique' : 'Keyword'}{' '}
          <span className="text-cyan-400">{data.query_value}</span>
        </h2>
        <p className="text-gray-400 mt-1">
          Found {totalCount} detection{totalCount !== 1 ? 's' : ''} across{' '}
          {Object.keys(data.results).length} vendor{Object.keys(data.results).length !== 1 ? 's' : ''}
        </p>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-6 gap-3 mb-6">
        {sources.map((source) => (
          <div
            key={source}
            className={`p-3 rounded-lg border-l-4 ${sourceColors[source]}`}
          >
            <h3 className="font-semibold text-sm text-gray-300">{sourceNames[source]}</h3>
            <p className="text-2xl font-bold mt-1 text-white">
              {data.total_by_source[source] || 0}
            </p>
            <p className="text-sm text-gray-500">detections</p>
          </div>
        ))}
      </div>

      {/* Comparison grid */}
      <div className="grid grid-cols-6 gap-4">
        {sources.map((source) => (
          <div key={source} className="space-y-3">
            <h3 className="font-semibold text-gray-300 border-b border-cyber-700 pb-2">{sourceNames[source]}</h3>
            {data.results[source]?.length ? (
              data.results[source].map((detection) => (
                <DetectionCard key={detection.id} detection={detection} />
              ))
            ) : (
              <p className="text-gray-500 text-sm py-4 text-center">
                No detections found
              </p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
