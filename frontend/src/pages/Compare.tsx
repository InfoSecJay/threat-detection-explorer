import { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { RuleComparison } from '../components/RuleComparison';
import { ComparisonCharts } from '../components/ComparisonCharts';
import { useCompare, useCoverageGap } from '../hooks/useCompare';
import { useMitre } from '../contexts/MitreContext';

// Platform options for comparison dropdown
const platformOptions = [
  { value: 'windows', label: 'Windows' },
  { value: 'linux', label: 'Linux' },
  { value: 'macos', label: 'macOS' },
  { value: 'aws', label: 'AWS' },
  { value: 'azure', label: 'Azure' },
  { value: 'gcp', label: 'Google Cloud' },
  { value: 'microsoft_365', label: 'Microsoft 365' },
  { value: 'okta', label: 'Okta' },
  { value: 'google_workspace', label: 'Google Workspace' },
  { value: 'github', label: 'GitHub' },
  { value: 'palo_alto', label: 'Palo Alto' },
  { value: 'fortigate', label: 'FortiGate' },
  { value: 'cisco_asa', label: 'Cisco ASA' },
  { value: 'crowdstrike', label: 'CrowdStrike' },
  { value: 'defender_endpoint', label: 'Defender for Endpoint' },
  { value: 'email', label: 'Email Security' },
];

export function Compare() {
  const [searchParams, setSearchParams] = useSearchParams();
  const { getTechniqueName, getTechniqueUrl } = useMitre();

  // Determine initial query type - keyword is default
  const getInitialQueryType = (): 'keyword' | 'technique' | 'platform' => {
    if (searchParams.get('technique')) return 'technique';
    if (searchParams.get('platform')) return 'platform';
    return 'keyword'; // Default to keyword
  };

  const [queryType, setQueryType] = useState<'keyword' | 'technique' | 'platform'>(
    getInitialQueryType()
  );
  const [queryValue, setQueryValue] = useState(
    searchParams.get('keyword') || searchParams.get('technique') || searchParams.get('platform') || ''
  );
  const [submittedQuery, setSubmittedQuery] = useState({
    technique: searchParams.get('technique') || undefined,
    keyword: searchParams.get('keyword') || undefined,
    platform: searchParams.get('platform') || undefined,
  });

  const [showGapAnalysis, setShowGapAnalysis] = useState(false);
  const [gapBaseSource, setGapBaseSource] = useState('sigma');
  const [gapCompareSource, setGapCompareSource] = useState('elastic');

  const { data: compareData, isLoading: compareLoading, error: compareError } = useCompare(submittedQuery);
  const { data: gapData, isLoading: gapLoading } = useCoverageGap(
    showGapAnalysis ? gapBaseSource : '',
    showGapAnalysis ? gapCompareSource : ''
  );

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!queryValue.trim()) return;

    const newQuery = {
      technique: queryType === 'technique' ? queryValue.toUpperCase() : undefined,
      keyword: queryType === 'keyword' ? queryValue : undefined,
      platform: queryType === 'platform' ? queryValue : undefined,
    };
    setSubmittedQuery(newQuery);

    // Update URL
    const params = new URLSearchParams();
    if (newQuery.technique) params.set('technique', newQuery.technique);
    if (newQuery.keyword) params.set('keyword', newQuery.keyword);
    if (newQuery.platform) params.set('platform', newQuery.platform);
    setSearchParams(params);
  };

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">
            Cross-Vendor Comparison
          </h1>
          <p className="text-sm text-gray-500 mt-1 font-mono">
            COMPARE DETECTION COVERAGE ACROSS ALL SOURCES
          </p>
        </div>
        <Link
          to="/compare/side-by-side"
          className="px-4 py-2 bg-void-800 border border-void-600 text-gray-300 font-display text-sm uppercase tracking-wider hover:bg-void-700 hover:text-matrix-500 hover:border-matrix-500/30 transition-all"
          style={{
            clipPath: 'polygon(0 0, calc(100% - 8px) 0, 100% 8px, 100% 100%, 8px 100%, 0 calc(100% - 8px))',
          }}
        >
          Side-by-Side
        </Link>
      </div>

      {/* Search Form */}
      <div
        className="bg-void-850 border border-void-700 p-6"
        style={{
          clipPath: 'polygon(0 0, calc(100% - 16px) 0, 100% 16px, 100% 100%, 16px 100%, 0 calc(100% - 16px))',
        }}
      >
        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Query Type Selection */}
          <div className="flex gap-6">
            <label className="flex items-center gap-2 cursor-pointer group">
              <input
                type="radio"
                name="queryType"
                value="keyword"
                checked={queryType === 'keyword'}
                onChange={() => { setQueryType('keyword'); setQueryValue(''); }}
                className="w-4 h-4 text-matrix-500 bg-void-900 border-void-600 focus:ring-matrix-500/50"
              />
              <span className="text-sm text-gray-400 group-hover:text-white transition-colors font-display uppercase tracking-wide">
                Keyword
              </span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer group">
              <input
                type="radio"
                name="queryType"
                value="technique"
                checked={queryType === 'technique'}
                onChange={() => { setQueryType('technique'); setQueryValue(''); }}
                className="w-4 h-4 text-matrix-500 bg-void-900 border-void-600 focus:ring-matrix-500/50"
              />
              <span className="text-sm text-gray-400 group-hover:text-white transition-colors font-display uppercase tracking-wide">
                MITRE Technique
              </span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer group">
              <input
                type="radio"
                name="queryType"
                value="platform"
                checked={queryType === 'platform'}
                onChange={() => { setQueryType('platform'); setQueryValue(''); }}
                className="w-4 h-4 text-matrix-500 bg-void-900 border-void-600 focus:ring-matrix-500/50"
              />
              <span className="text-sm text-gray-400 group-hover:text-white transition-colors font-display uppercase tracking-wide">
                Platform
              </span>
            </label>
          </div>

          {/* Search Input */}
          <div className="flex gap-3">
            {queryType === 'platform' ? (
              <select
                value={queryValue}
                onChange={(e) => setQueryValue(e.target.value)}
                className="flex-1 px-4 py-3 bg-void-900 border border-void-700 text-white focus:ring-2 focus:ring-matrix-500/50 focus:border-matrix-500/50"
              >
                <option value="">Select a platform...</option>
                {platformOptions.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            ) : (
              <input
                type="text"
                value={queryValue}
                onChange={(e) => setQueryValue(e.target.value)}
                placeholder={
                  queryType === 'technique'
                    ? 'Enter technique ID (e.g., T1059)'
                    : 'Enter keyword (e.g., powershell, 4688)'
                }
                className="flex-1 px-4 py-3 bg-void-900 border border-void-700 text-white placeholder-gray-500 focus:ring-2 focus:ring-matrix-500/50 focus:border-matrix-500/50"
              />
            )}
            <button
              type="submit"
              disabled={!queryValue.trim()}
              className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Compare
            </button>
          </div>
        </form>

        {/* Quick Technique Suggestions */}
        <div className="mt-6 pt-4 border-t border-void-700">
          <p className="text-xs font-mono text-gray-500 mb-3">POPULAR_TECHNIQUES:</p>
          <div className="flex flex-wrap gap-2">
            {['T1059', 'T1055', 'T1027', 'T1105', 'T1053'].map((tech) => {
              const name = getTechniqueName(tech);
              return (
                <button
                  key={tech}
                  onClick={() => {
                    setQueryType('technique');
                    setQueryValue(tech);
                    setSubmittedQuery({ technique: tech, keyword: undefined, platform: undefined });
                    setSearchParams({ technique: tech });
                  }}
                  className="px-3 py-1.5 bg-void-800 text-gray-300 border border-void-600 text-sm hover:bg-void-700 hover:text-matrix-500 hover:border-matrix-500/30 transition-all flex items-center gap-2"
                >
                  <span className="font-mono text-matrix-500">{tech}</span>
                  {name && <span className="text-gray-500 text-xs">- {name}</span>}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Loading State */}
      {compareLoading && (
        <div className="flex flex-col items-center justify-center py-16">
          <div className="relative w-16 h-16">
            <div className="absolute inset-0 border-2 border-matrix-500/30 rounded-full"></div>
            <div className="absolute inset-0 border-2 border-transparent border-t-matrix-500 rounded-full animate-spin"></div>
          </div>
          <p className="mt-4 text-sm font-mono text-gray-500">COMPARING_SOURCES...</p>
        </div>
      )}

      {/* Error State */}
      {compareError && (
        <div
          className="bg-breach-500/10 border border-breach-500/30 p-6"
          style={{
            clipPath: 'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))',
          }}
        >
          <div className="flex items-center gap-3">
            <svg className="w-5 h-5 text-breach-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <span className="font-mono text-sm text-breach-400">ERROR: {compareError.message}</span>
          </div>
        </div>
      )}

      {/* Comparison Results */}
      {compareData && <RuleComparison data={compareData} />}

      {/* Comparison Charts */}
      {compareData && Object.keys(compareData.results).length > 0 && (
        <ComparisonCharts data={compareData} />
      )}

      {/* Coverage Gap Analysis */}
      <div
        className="bg-void-850 border border-void-700 p-6"
        style={{
          clipPath: 'polygon(0 0, calc(100% - 16px) 0, 100% 16px, 100% 100%, 16px 100%, 0 calc(100% - 16px))',
        }}
      >
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <svg className="w-5 h-5 text-matrix-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
            <h2 className="text-lg font-display font-bold text-white tracking-wider uppercase">
              Coverage Gap Analysis
            </h2>
          </div>
          <button
            onClick={() => setShowGapAnalysis(!showGapAnalysis)}
            className="text-sm font-mono text-matrix-500 hover:text-matrix-400 transition-colors"
          >
            {showGapAnalysis ? '[ HIDE ]' : '[ SHOW ]'}
          </button>
        </div>

        {showGapAnalysis && (
          <div className="space-y-6">
            {/* Source Selection */}
            <div className="flex items-center gap-4">
              <div>
                <label className="block text-xs font-mono text-gray-500 mb-1.5">
                  BASE_SOURCE
                </label>
                <select
                  value={gapBaseSource}
                  onChange={(e) => setGapBaseSource(e.target.value)}
                  className="px-3 py-2 bg-void-900 border border-void-700 text-white text-sm focus:ring-matrix-500/50 focus:border-matrix-500/50"
                >
                  <option value="sigma">Sigma</option>
                  <option value="elastic">Elastic</option>
                  <option value="splunk">Splunk</option>
                  <option value="sublime">Sublime</option>
                  <option value="elastic_protections">Elastic Protections</option>
                  <option value="lolrmm">LOLRMM</option>
                </select>
              </div>
              <div className="pt-5 text-gray-600 font-display">VS</div>
              <div>
                <label className="block text-xs font-mono text-gray-500 mb-1.5">
                  COMPARE_SOURCE
                </label>
                <select
                  value={gapCompareSource}
                  onChange={(e) => setGapCompareSource(e.target.value)}
                  className="px-3 py-2 bg-void-900 border border-void-700 text-white text-sm focus:ring-matrix-500/50 focus:border-matrix-500/50"
                >
                  <option value="sigma">Sigma</option>
                  <option value="elastic">Elastic</option>
                  <option value="splunk">Splunk</option>
                  <option value="sublime">Sublime</option>
                  <option value="elastic_protections">Elastic Protections</option>
                  <option value="lolrmm">LOLRMM</option>
                </select>
              </div>
            </div>

            {/* Loading */}
            {gapLoading && (
              <p className="text-sm font-mono text-gray-500">ANALYZING_COVERAGE...</p>
            )}

            {/* Gap Results */}
            {gapData && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Overlap Card */}
                <div
                  className="p-5 bg-pulse-500/5 border border-pulse-500/30"
                  style={{
                    clipPath: 'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))',
                  }}
                >
                  <div className="flex items-center gap-2 mb-2">
                    <span className="w-2 h-2 bg-pulse-500 rounded-full"></span>
                    <h4 className="font-display font-semibold text-pulse-400 text-sm uppercase tracking-wide">
                      Overlapping Coverage
                    </h4>
                  </div>
                  <p className="text-3xl font-display font-bold text-pulse-500">
                    {gapData.overlap_count}
                    <span className="text-sm font-mono text-pulse-400/60 ml-2">techniques</span>
                  </p>
                </div>

                {/* Gaps Card */}
                <div
                  className="p-5 bg-breach-500/5 border border-breach-500/30"
                  style={{
                    clipPath: 'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))',
                  }}
                >
                  <div className="flex items-center gap-2 mb-2">
                    <span className="w-2 h-2 bg-breach-500 rounded-full"></span>
                    <h4 className="font-display font-semibold text-breach-400 text-sm uppercase tracking-wide">
                      Gaps ({gapBaseSource} only)
                    </h4>
                  </div>
                  <p className="text-3xl font-display font-bold text-breach-500">
                    {gapData.gaps.length}
                    <span className="text-sm font-mono text-breach-400/60 ml-2">techniques</span>
                  </p>
                </div>

                {/* Gap Details */}
                {gapData.gaps.length > 0 && (
                  <div className="col-span-2">
                    <h4 className="font-mono text-xs text-gray-500 mb-3 uppercase">
                      Techniques in {gapBaseSource} but not in {gapCompareSource}:
                    </h4>
                    <div className="space-y-1 max-h-64 overflow-y-auto">
                      {gapData.gaps.map((tech) => {
                        const name = getTechniqueName(tech);
                        return (
                          <button
                            key={tech}
                            onClick={() => {
                              setQueryType('technique');
                              setQueryValue(tech);
                              setSubmittedQuery({ technique: tech, keyword: undefined, platform: undefined });
                            }}
                            className="w-full text-left px-4 py-2 bg-breach-500/5 text-breach-400 border border-breach-500/20 hover:bg-breach-500/10 transition-colors flex items-center gap-3"
                          >
                            <span className="font-mono text-sm bg-breach-500/20 px-2 py-0.5">
                              {tech}
                            </span>
                            {name && (
                              <span className="text-gray-400 text-sm truncate">
                                {name}
                              </span>
                            )}
                            <a
                              href={getTechniqueUrl(tech)}
                              target="_blank"
                              rel="noopener noreferrer"
                              onClick={(e) => e.stopPropagation()}
                              className="ml-auto text-gray-600 hover:text-matrix-500 text-xs font-mono"
                            >
                              MITRE
                            </a>
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
