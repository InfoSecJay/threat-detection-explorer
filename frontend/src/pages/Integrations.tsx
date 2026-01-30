import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { repositoriesApi } from '../services/api';
import { DataSourceIcon } from '../components/graphics/DataSourceIcon';

interface Repository {
  id: string;
  name: string;
  url: string;
  last_commit_hash: string | null;
  last_sync_at: string | null;
  rule_count: number;
  status: string;
  error_message: string | null;
  created_at: string;
}

const sourceConfig: Record<string, { displayName: string; description: string; repoUrl: string; color: string }> = {
  sigma: {
    displayName: 'SigmaHQ',
    description: 'Community-driven detection rules covering comprehensive MITRE ATT&CK techniques using the Sigma format.',
    repoUrl: 'https://github.com/SigmaHQ/sigma',
    color: '#a855f7',
  },
  elastic: {
    displayName: 'Elastic Detection Rules',
    description: 'Detection rules for Elastic Security using KQL and EQL query formats.',
    repoUrl: 'https://github.com/elastic/detection-rules',
    color: '#3b82f6',
  },
  splunk: {
    displayName: 'Splunk Security Content',
    description: 'Analytics stories and detection searches for Splunk Enterprise Security.',
    repoUrl: 'https://github.com/splunk/security_content',
    color: '#f97316',
  },
  sublime: {
    displayName: 'Sublime Security',
    description: 'Email security detection rules using Message Query Language (MQL).',
    repoUrl: 'https://github.com/sublime-security/sublime-rules',
    color: '#ec4899',
  },
  elastic_protections: {
    displayName: 'Elastic Protections',
    description: 'Endpoint behavior rules for Elastic Endpoint Security using EQL.',
    repoUrl: 'https://github.com/elastic/protections-artifacts',
    color: '#06b6d4',
  },
  lolrmm: {
    displayName: 'LOLRMM',
    description: 'Detection rules for RMM tools commonly abused by threat actors.',
    repoUrl: 'https://github.com/magicsword-io/LOLRMM',
    color: '#22c55e',
  },
  elastic_hunting: {
    displayName: 'Elastic Hunting Queries',
    description: 'Proactive threat hunting queries using ES|QL for Elastic Security.',
    repoUrl: 'https://github.com/elastic/detection-rules/tree/main/hunting',
    color: '#8b5cf6',
  },
};

function formatDate(dateString: string | null): string {
  if (!dateString) return 'Never';
  const date = new Date(dateString);
  return date.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short',
  });
}

function getStatusColor(status: string): { text: string; bg: string; border: string } {
  switch (status) {
    case 'idle':
    case 'synced':
      return { text: 'text-pulse-400', bg: 'bg-pulse-500/10', border: 'border-pulse-500/30' };
    case 'syncing':
    case 'ingesting':
      return { text: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/30' };
    case 'error':
      return { text: 'text-threat-400', bg: 'bg-threat-500/10', border: 'border-threat-500/30' };
    default:
      return { text: 'text-gray-400', bg: 'bg-gray-500/10', border: 'border-gray-500/30' };
  }
}

function IntegrationCard({ repo }: { repo: Repository }) {
  const config = sourceConfig[repo.name];
  const statusColors = getStatusColor(repo.status);

  if (!config) return null;

  return (
    <div
      className="bg-void-850 border border-void-700 p-6 transition-all hover:border-opacity-50"
      style={{
        borderColor: `${config.color}30`,
        clipPath: 'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))',
      }}
    >
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <DataSourceIcon source={repo.name as 'sigma' | 'elastic' | 'splunk' | 'sublime' | 'elastic_protections' | 'lolrmm' | 'elastic_hunting'} size={40} />
          <div>
            <h3 className="font-display font-semibold tracking-wide" style={{ color: config.color }}>
              {config.displayName}
            </h3>
            <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 text-xs font-mono uppercase ${statusColors.text} ${statusColors.bg} border ${statusColors.border}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${repo.status === 'idle' || repo.status === 'synced' ? 'bg-pulse-500' : repo.status === 'error' ? 'bg-threat-500' : 'bg-blue-500 animate-pulse'}`} />
              {repo.status === 'idle' ? 'ONLINE' : repo.status.toUpperCase()}
            </span>
          </div>
        </div>
        <a
          href={config.repoUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="text-gray-600 hover:text-matrix-500 transition-colors"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
          </svg>
        </a>
      </div>

      {/* Description */}
      <p className="text-sm text-gray-500 mb-4">
        {config.description}
      </p>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 gap-4 pt-4 border-t border-void-700">
        <div>
          <p className="text-xs font-mono text-gray-600 mb-1">RULE_COUNT</p>
          <p className="text-lg font-display font-bold" style={{ color: config.color }}>
            {repo.rule_count.toLocaleString()}
          </p>
        </div>
        <div>
          <p className="text-xs font-mono text-gray-600 mb-1">LAST_SYNC</p>
          <p className="text-sm text-gray-400">
            {formatDate(repo.last_sync_at)}
          </p>
        </div>
      </div>

      {/* Commit hash */}
      {repo.last_commit_hash && (
        <div className="mt-3 pt-3 border-t border-void-700">
          <p className="text-xs font-mono text-gray-600 mb-1">COMMIT_HASH</p>
          <code className="text-xs font-mono text-gray-500">
            {repo.last_commit_hash.slice(0, 8)}
          </code>
        </div>
      )}

      {/* Error message if any */}
      {repo.error_message && (
        <div className="mt-3 pt-3 border-t border-threat-500/30">
          <p className="text-xs font-mono text-threat-400 mb-1">ERROR</p>
          <p className="text-xs text-threat-300/80">
            {repo.error_message}
          </p>
        </div>
      )}
    </div>
  );
}

export function Integrations() {
  const { data: repositories, isLoading, error } = useQuery<Repository[]>({
    queryKey: ['repositories'],
    queryFn: repositoriesApi.list,
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  // Calculate totals
  const totalRules = repositories?.reduce((sum, repo) => sum + repo.rule_count, 0) || 0;
  const onlineSources = repositories?.filter(r => r.status === 'idle' || r.status === 'synced').length || 0;

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">
          Integrations
        </h1>
        <p className="text-sm text-gray-500 mt-1 font-mono">
          SOURCE_FEED_STATUS // SYNC_MONITORING
        </p>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div
          className="bg-void-850 border border-void-700 p-5"
          style={{
            clipPath: 'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))',
          }}
        >
          <p className="text-xs font-mono text-gray-500 mb-1">TOTAL_SOURCES</p>
          <p className="text-3xl font-display font-bold text-matrix-500">
            {repositories?.length || 0}
          </p>
        </div>
        <div
          className="bg-void-850 border border-void-700 p-5"
          style={{
            clipPath: 'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))',
          }}
        >
          <p className="text-xs font-mono text-gray-500 mb-1">ONLINE_SOURCES</p>
          <p className="text-3xl font-display font-bold text-pulse-500">
            {onlineSources}
          </p>
        </div>
        <div
          className="bg-void-850 border border-void-700 p-5"
          style={{
            clipPath: 'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))',
          }}
        >
          <p className="text-xs font-mono text-gray-500 mb-1">TOTAL_RULES</p>
          <p className="text-3xl font-display font-bold text-white">
            {totalRules.toLocaleString()}
          </p>
        </div>
      </div>

      {/* Loading State */}
      {isLoading && (
        <div className="flex flex-col items-center justify-center py-16">
          <div className="relative w-16 h-16">
            <div className="absolute inset-0 border-2 border-matrix-500/30 rounded-full"></div>
            <div className="absolute inset-0 border-2 border-transparent border-t-matrix-500 rounded-full animate-spin"></div>
          </div>
          <p className="mt-4 text-sm font-mono text-gray-500">LOADING_INTEGRATIONS...</p>
        </div>
      )}

      {/* Error State */}
      {error && (
        <div
          className="bg-threat-500/10 border border-threat-500/30 p-6"
          style={{
            clipPath: 'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))',
          }}
        >
          <div className="flex items-center gap-3">
            <svg className="w-5 h-5 text-threat-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <span className="font-mono text-sm text-threat-400">ERROR: Failed to load integrations</span>
          </div>
        </div>
      )}

      {/* Integration Cards */}
      {repositories && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {repositories.map((repo) => (
            <IntegrationCard key={repo.id} repo={repo} />
          ))}
        </div>
      )}

      {/* Info Section */}
      <div
        className="bg-void-850 border border-void-700 p-6"
        style={{
          clipPath: 'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))',
        }}
      >
        <div className="flex items-center gap-3 mb-4">
          <svg className="w-5 h-5 text-matrix-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <h3 className="font-display font-semibold text-white tracking-wide uppercase">
            Sync Information
          </h3>
        </div>
        <div className="space-y-2 text-sm text-gray-400">
          <p>
            Source repositories are synced periodically to ensure detection rules are up-to-date.
            The sync process clones the latest changes from each repository and ingests new or updated rules.
          </p>
          <p>
            Rules are normalized to a common schema for consistent searching and comparison across different
            detection formats (Sigma, SPL, EQL, KQL, MQL).
          </p>
        </div>
      </div>

      {/* Back link */}
      <div className="pt-4">
        <Link
          to="/"
          className="text-sm font-mono text-gray-500 hover:text-matrix-500 transition-colors"
        >
          &larr; BACK_TO_HOME
        </Link>
      </div>
    </div>
  );
}
