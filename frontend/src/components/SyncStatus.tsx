import { useState } from 'react';
import { useRepositories, useSyncRepository, useIngestRepository } from '../hooks/useRepositories';
import type { Repository, IngestionResponse, IngestionError as IngestionErrorType } from '../types';

function IngestionErrorList({ errors }: { errors: IngestionErrorType[] }) {
  const [expanded, setExpanded] = useState(false);
  const displayErrors = expanded ? errors : errors.slice(0, 3);

  return (
    <div className="mt-2 space-y-1">
      {displayErrors.map((error, idx) => (
        <div
          key={idx}
          className={`text-xs p-2 rounded ${
            error.severity === 'error'
              ? 'bg-red-50 text-red-700 border border-red-200'
              : 'bg-yellow-50 text-yellow-700 border border-yellow-200'
          }`}
        >
          <div className="flex items-center gap-1">
            <span className="font-medium capitalize">[{error.stage}]</span>
            <span>{error.message}</span>
          </div>
          {error.details && (
            <div className="mt-1 text-xs opacity-75 truncate" title={error.details}>
              {error.details}
            </div>
          )}
          <div className="mt-1 text-xs opacity-60 truncate" title={error.file_path}>
            {error.file_path.split('/').slice(-2).join('/')}
          </div>
        </div>
      ))}
      {errors.length > 3 && (
        <button
          onClick={() => setExpanded(!expanded)}
          className="text-xs text-blue-600 hover:text-blue-800"
        >
          {expanded ? 'Show less' : `Show ${errors.length - 3} more errors...`}
        </button>
      )}
    </div>
  );
}

function IngestionStats({ data }: { data: IngestionResponse }) {
  const { stats } = data;
  const hasErrors = stats.error_count > 0;
  const hasWarnings = stats.warning_count > 0;

  return (
    <div className="mt-3 space-y-2">
      <div className="grid grid-cols-2 gap-2 text-xs">
        <div className="bg-gray-50 p-2 rounded">
          <span className="text-gray-500">Discovered:</span>{' '}
          <span className="font-medium">{stats.discovered}</span>
        </div>
        <div className="bg-gray-50 p-2 rounded">
          <span className="text-gray-500">Stored:</span>{' '}
          <span className="font-medium">{stats.stored}</span>
        </div>
        <div className="bg-gray-50 p-2 rounded">
          <span className="text-gray-500">Parsed:</span>{' '}
          <span className="font-medium">{stats.parsed}</span>
        </div>
        <div className="bg-gray-50 p-2 rounded">
          <span className="text-gray-500">Success:</span>{' '}
          <span className="font-medium">{stats.success_rate.toFixed(1)}%</span>
        </div>
      </div>

      {(hasErrors || hasWarnings) && (
        <div className="flex gap-2 text-xs">
          {hasErrors && (
            <span className="px-2 py-1 bg-red-100 text-red-700 rounded">
              {stats.error_count} errors
            </span>
          )}
          {hasWarnings && (
            <span className="px-2 py-1 bg-yellow-100 text-yellow-700 rounded">
              {stats.warning_count} warnings
            </span>
          )}
        </div>
      )}

      {stats.duration_seconds && (
        <div className="text-xs text-gray-500">
          Duration: {stats.duration_seconds.toFixed(1)}s
        </div>
      )}

      {stats.sample_errors && stats.sample_errors.length > 0 && (
        <IngestionErrorList errors={stats.sample_errors} />
      )}
    </div>
  );
}

function RepositoryCard({ repo }: { repo: Repository }) {
  const syncMutation = useSyncRepository();
  const ingestMutation = useIngestRepository();
  const [showDetails, setShowDetails] = useState(false);

  const handleSync = () => {
    syncMutation.mutate(repo.name);
  };

  const handleIngest = () => {
    ingestMutation.mutate(repo.name);
  };

  const statusColor = {
    idle: 'bg-green-100 text-green-800',
    syncing: 'bg-yellow-100 text-yellow-800',
    error: 'bg-red-100 text-red-800',
  }[repo.status];

  const ingestionData = ingestMutation.data;
  const hasIngestionErrors = ingestionData && ingestionData.stats.error_count > 0;

  return (
    <div className="bg-white rounded-lg shadow p-4">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-lg font-semibold capitalize">{repo.name}</h3>
        <span className={`px-2 py-1 rounded-full text-xs font-medium ${statusColor}`}>
          {repo.status}
        </span>
      </div>

      <div className="text-sm text-gray-600 space-y-1">
        <p>Rules: {repo.rule_count.toLocaleString()}</p>
        <p>
          Last sync:{' '}
          {repo.last_sync_at
            ? new Date(repo.last_sync_at).toLocaleString()
            : 'Never'}
        </p>
        {repo.last_commit_hash && (
          <p className="font-mono text-xs">
            Commit: {repo.last_commit_hash.slice(0, 8)}
          </p>
        )}
        {repo.error_message && (
          <p className="text-red-600 text-xs mt-2">{repo.error_message}</p>
        )}
      </div>

      <div className="mt-4 flex gap-2">
        <button
          onClick={handleSync}
          disabled={repo.status === 'syncing' || syncMutation.isPending}
          className="px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {syncMutation.isPending ? 'Syncing...' : 'Sync'}
        </button>
        <button
          onClick={handleIngest}
          disabled={!repo.last_sync_at || ingestMutation.isPending}
          className="px-3 py-1 text-sm bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {ingestMutation.isPending ? 'Ingesting...' : 'Ingest'}
        </button>
      </div>

      {ingestMutation.isSuccess && ingestionData && (
        <div className="mt-3">
          <div className="flex items-center justify-between">
            <p className={`text-sm ${ingestionData.success ? (hasIngestionErrors ? 'text-yellow-600' : 'text-green-600') : 'text-red-600'}`}>
              {ingestionData.message}
            </p>
            <button
              onClick={() => setShowDetails(!showDetails)}
              className="text-xs text-blue-600 hover:text-blue-800"
            >
              {showDetails ? 'Hide details' : 'Show details'}
            </button>
          </div>
          {showDetails && <IngestionStats data={ingestionData} />}
        </div>
      )}
    </div>
  );
}

export function SyncStatus() {
  const { data: repos, isLoading, error } = useRepositories();

  if (isLoading) {
    return (
      <div className="text-center py-4">
        <div className="animate-spin h-8 w-8 border-4 border-blue-600 border-t-transparent rounded-full mx-auto"></div>
        <p className="mt-2 text-gray-600">Loading repositories...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-100 text-red-700 p-4 rounded-lg">
        Error loading repositories: {error.message}
      </div>
    );
  }

  return (
    <div>
      <h2 className="text-xl font-bold mb-4">Repository Status</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {repos?.map((repo) => (
          <RepositoryCard key={repo.id} repo={repo} />
        ))}
      </div>
    </div>
  );
}
