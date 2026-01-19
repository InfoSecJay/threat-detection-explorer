import { Link } from 'react-router-dom';
import type { Detection, CompareResponse } from '../types';

interface RuleComparisonProps {
  data: CompareResponse;
}

const sourceColors: Record<string, string> = {
  sigma: 'border-purple-500 bg-purple-50',
  elastic: 'border-blue-500 bg-blue-50',
  splunk: 'border-orange-500 bg-orange-50',
  sublime: 'border-pink-500 bg-pink-50',
  elastic_protections: 'border-cyan-500 bg-cyan-50',
  lolrmm: 'border-green-500 bg-green-50',
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
  critical: 'bg-red-100 text-red-800',
  high: 'bg-orange-100 text-orange-800',
  medium: 'bg-yellow-100 text-yellow-800',
  low: 'bg-green-100 text-green-800',
  unknown: 'bg-gray-100 text-gray-800',
};

function DetectionCard({ detection }: { detection: Detection }) {
  return (
    <Link
      to={`/detections/${detection.id}`}
      className="block p-3 bg-white rounded border hover:shadow-md transition-shadow"
    >
      <h4 className="font-medium text-sm truncate">{detection.title}</h4>
      <p className="text-xs text-gray-600 mt-1 line-clamp-2">
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
        <h2 className="text-xl font-bold">
          Comparison: {data.query_type === 'technique' ? 'Technique' : 'Keyword'}{' '}
          <span className="text-blue-600">{data.query_value}</span>
        </h2>
        <p className="text-gray-600 mt-1">
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
            <h3 className="font-semibold text-sm">{sourceNames[source]}</h3>
            <p className="text-2xl font-bold mt-1">
              {data.total_by_source[source] || 0}
            </p>
            <p className="text-sm text-gray-600">detections</p>
          </div>
        ))}
      </div>

      {/* Comparison grid */}
      <div className="grid grid-cols-6 gap-4">
        {sources.map((source) => (
          <div key={source} className="space-y-3">
            <h3 className="font-semibold border-b pb-2">{sourceNames[source]}</h3>
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
