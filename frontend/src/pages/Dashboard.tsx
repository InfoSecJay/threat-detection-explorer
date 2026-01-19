import { Link } from 'react-router-dom';
import { SyncStatus } from '../components/SyncStatus';
import { useStatistics } from '../hooks/useDetections';

export function Dashboard() {
  const { data: stats, isLoading } = useStatistics();

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Threat Detection Explorer</h1>
        <p className="text-gray-600 mt-2">
          Compare and analyze detection rules across SigmaHQ, Elastic, Splunk, Sublime, and LOLRMM
        </p>
      </div>

      {/* Statistics */}
      {!isLoading && stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
          <div className="bg-white rounded-lg shadow p-4">
            <h3 className="text-xs font-medium text-gray-500">Total</h3>
            <p className="text-2xl font-bold text-gray-900 mt-1">
              {stats.total.toLocaleString()}
            </p>
          </div>
          <div className="bg-white rounded-lg shadow p-4">
            <h3 className="text-xs font-medium text-gray-500">Sigma</h3>
            <p className="text-2xl font-bold text-purple-600 mt-1">
              {(stats.by_source.sigma || 0).toLocaleString()}
            </p>
          </div>
          <div className="bg-white rounded-lg shadow p-4">
            <h3 className="text-xs font-medium text-gray-500">Elastic</h3>
            <p className="text-2xl font-bold text-blue-600 mt-1">
              {(stats.by_source.elastic || 0).toLocaleString()}
            </p>
          </div>
          <div className="bg-white rounded-lg shadow p-4">
            <h3 className="text-xs font-medium text-gray-500">Splunk</h3>
            <p className="text-2xl font-bold text-orange-600 mt-1">
              {(stats.by_source.splunk || 0).toLocaleString()}
            </p>
          </div>
          <div className="bg-white rounded-lg shadow p-4">
            <h3 className="text-xs font-medium text-gray-500">Sublime</h3>
            <p className="text-2xl font-bold text-pink-600 mt-1">
              {(stats.by_source.sublime || 0).toLocaleString()}
            </p>
          </div>
          <div className="bg-white rounded-lg shadow p-4">
            <h3 className="text-xs font-medium text-gray-500">Elastic Protect</h3>
            <p className="text-2xl font-bold text-cyan-600 mt-1">
              {(stats.by_source.elastic_protections || 0).toLocaleString()}
            </p>
          </div>
          <div className="bg-white rounded-lg shadow p-4">
            <h3 className="text-xs font-medium text-gray-500">LOLRMM</h3>
            <p className="text-2xl font-bold text-green-600 mt-1">
              {(stats.by_source.lolrmm || 0).toLocaleString()}
            </p>
          </div>
        </div>
      )}

      {/* Repository Status */}
      <SyncStatus />

      {/* Quick actions */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-xl font-bold mb-4">Quick Actions</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Link
            to="/detections"
            className="p-4 border rounded-lg hover:border-blue-500 hover:bg-blue-50 transition-colors"
          >
            <h3 className="font-semibold text-gray-900">Browse Detections</h3>
            <p className="text-sm text-gray-600 mt-1">
              Search and filter detection rules across all vendors
            </p>
          </Link>
          <Link
            to="/compare"
            className="p-4 border rounded-lg hover:border-blue-500 hover:bg-blue-50 transition-colors"
          >
            <h3 className="font-semibold text-gray-900">Compare Rules</h3>
            <p className="text-sm text-gray-600 mt-1">
              Compare detection coverage by technique or keyword
            </p>
          </Link>
          <Link
            to="/detections?severities=critical,high"
            className="p-4 border rounded-lg hover:border-blue-500 hover:bg-blue-50 transition-colors"
          >
            <h3 className="font-semibold text-gray-900">High Severity Rules</h3>
            <p className="text-sm text-gray-600 mt-1">
              View critical and high severity detections
            </p>
          </Link>
        </div>
      </div>

      {/* Severity breakdown */}
      {stats && stats.total > 0 && (
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-xl font-bold mb-4">Severity Distribution</h2>
          <div className="flex gap-4">
            {Object.entries(stats.by_severity)
              .filter(([_, count]) => count > 0)
              .map(([severity, count]) => {
                const percentage = ((count / stats.total) * 100).toFixed(1);
                const colors: Record<string, string> = {
                  critical: 'bg-red-500',
                  high: 'bg-orange-500',
                  medium: 'bg-yellow-500',
                  low: 'bg-green-500',
                  unknown: 'bg-gray-400',
                };
                return (
                  <div key={severity} className="flex-1">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm font-medium capitalize">{severity}</span>
                      <span className="text-sm text-gray-600">{percentage}%</span>
                    </div>
                    <div className="h-2 bg-gray-200 rounded-full">
                      <div
                        className={`h-2 rounded-full ${colors[severity]}`}
                        style={{ width: `${percentage}%` }}
                      />
                    </div>
                    <p className="text-xs text-gray-500 mt-1">{count.toLocaleString()}</p>
                  </div>
                );
              })}
          </div>
        </div>
      )}
    </div>
  );
}
