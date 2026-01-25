import { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { RuleComparison } from '../components/RuleComparison';
import { ComparisonCharts } from '../components/ComparisonCharts';
import { useCompare, useCoverageGap } from '../hooks/useCompare';
import { useMitre } from '../contexts/MitreContext';

export function Compare() {
  const [searchParams, setSearchParams] = useSearchParams();
  const { getTechniqueName, getTechniqueUrl } = useMitre();

  const [queryType, setQueryType] = useState<'technique' | 'keyword'>(
    searchParams.get('keyword') ? 'keyword' : 'technique'
  );
  const [queryValue, setQueryValue] = useState(
    searchParams.get('technique') || searchParams.get('keyword') || ''
  );
  const [submittedQuery, setSubmittedQuery] = useState({
    technique: searchParams.get('technique') || undefined,
    keyword: searchParams.get('keyword') || undefined,
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
    };
    setSubmittedQuery(newQuery);

    // Update URL
    const params = new URLSearchParams();
    if (newQuery.technique) params.set('technique', newQuery.technique);
    if (newQuery.keyword) params.set('keyword', newQuery.keyword);
    setSearchParams(params);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Cross-Vendor Comparison</h1>
          <p className="text-gray-400 mt-1">
            Compare detection coverage across all vendors
          </p>
        </div>
        <Link
          to="/compare/side-by-side"
          className="px-4 py-2 bg-cyber-800 border border-cyber-600 text-gray-300 rounded-lg hover:bg-cyber-700 hover:text-cyan-400 hover:border-cyan-500/30 transition-all"
        >
          Side-by-Side Comparison
        </Link>
      </div>

      {/* Search form */}
      <div className="bg-cyber-850 rounded-lg border border-cyber-700 p-6">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="flex gap-4">
            <label className="flex items-center text-gray-300 cursor-pointer">
              <input
                type="radio"
                name="queryType"
                value="technique"
                checked={queryType === 'technique'}
                onChange={() => setQueryType('technique')}
                className="mr-2 text-cyan-500 bg-cyber-900 border-cyber-600 focus:ring-cyan-500"
              />
              MITRE Technique
            </label>
            <label className="flex items-center text-gray-300 cursor-pointer">
              <input
                type="radio"
                name="queryType"
                value="keyword"
                checked={queryType === 'keyword'}
                onChange={() => setQueryType('keyword')}
                className="mr-2 text-cyan-500 bg-cyber-900 border-cyber-600 focus:ring-cyan-500"
              />
              Keyword
            </label>
          </div>

          <div className="flex gap-2">
            <input
              type="text"
              value={queryValue}
              onChange={(e) => setQueryValue(e.target.value)}
              placeholder={
                queryType === 'technique'
                  ? 'Enter technique ID (e.g., T1059)'
                  : 'Enter keyword (e.g., powershell, 4688)'
              }
              className="flex-1 px-4 py-2 bg-cyber-900 border border-cyber-700 rounded-lg text-white placeholder-gray-500 focus:ring-cyan-500 focus:border-cyan-500"
            />
            <button
              type="submit"
              disabled={!queryValue.trim()}
              className="px-6 py-2 bg-gradient-to-r from-cyan-500 to-blue-500 text-white rounded-lg hover:from-cyan-400 hover:to-blue-400 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
            >
              Compare
            </button>
          </div>
        </form>

        {/* Quick technique suggestions */}
        <div className="mt-4">
          <p className="text-sm text-gray-500 mb-2">Popular techniques:</p>
          <div className="flex flex-wrap gap-2">
            {['T1059', 'T1055', 'T1027', 'T1105', 'T1053'].map((tech) => {
              const name = getTechniqueName(tech);
              return (
                <button
                  key={tech}
                  onClick={() => {
                    setQueryType('technique');
                    setQueryValue(tech);
                    setSubmittedQuery({ technique: tech, keyword: undefined });
                    setSearchParams({ technique: tech });
                  }}
                  className="px-3 py-1.5 bg-cyber-700 text-gray-300 rounded-full text-sm hover:bg-cyber-600 hover:text-cyan-400 transition-colors flex items-center gap-2"
                >
                  <span className="font-mono">{tech}</span>
                  {name && <span className="text-gray-400">- {name}</span>}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Comparison results */}
      {compareLoading && (
        <div className="text-center py-8">
          <div className="animate-spin h-8 w-8 border-4 border-cyan-500 border-t-transparent rounded-full mx-auto"></div>
          <p className="mt-2 text-gray-400">Loading comparison...</p>
        </div>
      )}

      {compareError && (
        <div className="bg-red-500/20 text-red-400 border border-red-500/30 p-4 rounded-lg">
          Error: {compareError.message}
        </div>
      )}

      {compareData && <RuleComparison data={compareData} />}

      {/* Comparison Charts */}
      {compareData && Object.keys(compareData.results).length > 0 && (
        <ComparisonCharts data={compareData} />
      )}

      {/* Coverage gap analysis */}
      <div className="bg-cyber-850 rounded-lg border border-cyber-700 p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-bold text-white">Coverage Gap Analysis</h2>
          <button
            onClick={() => setShowGapAnalysis(!showGapAnalysis)}
            className="text-cyan-400 hover:text-cyan-300 transition-colors"
          >
            {showGapAnalysis ? 'Hide' : 'Show'}
          </button>
        </div>

        {showGapAnalysis && (
          <div className="space-y-4">
            <div className="flex items-center gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">
                  Base Source
                </label>
                <select
                  value={gapBaseSource}
                  onChange={(e) => setGapBaseSource(e.target.value)}
                  className="px-3 py-2 bg-cyber-900 border border-cyber-700 rounded-md text-white"
                >
                  <option value="sigma">Sigma</option>
                  <option value="elastic">Elastic</option>
                  <option value="splunk">Splunk</option>
                  <option value="sublime">Sublime</option>
                  <option value="elastic_protections">Elastic Protections</option>
                  <option value="lolrmm">LOLRMM</option>
                </select>
              </div>
              <div className="pt-6 text-gray-500">vs</div>
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">
                  Compare Source
                </label>
                <select
                  value={gapCompareSource}
                  onChange={(e) => setGapCompareSource(e.target.value)}
                  className="px-3 py-2 bg-cyber-900 border border-cyber-700 rounded-md text-white"
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

            {gapLoading && <p className="text-gray-400">Loading gap analysis...</p>}

            {gapData && (
              <div className="grid grid-cols-2 gap-4">
                <div className="p-4 bg-green-500/10 border border-green-500/30 rounded-lg">
                  <h4 className="font-semibold text-green-400">Overlapping Coverage</h4>
                  <p className="text-2xl font-bold text-green-300">
                    {gapData.overlap_count} techniques
                  </p>
                </div>
                <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
                  <h4 className="font-semibold text-red-400">
                    Gaps ({gapBaseSource} only)
                  </h4>
                  <p className="text-2xl font-bold text-red-300">
                    {gapData.gaps.length} techniques
                  </p>
                </div>

                {gapData.gaps.length > 0 && (
                  <div className="col-span-2">
                    <h4 className="font-semibold text-gray-300 mb-2">
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
                              setSubmittedQuery({ technique: tech, keyword: undefined });
                            }}
                            className="w-full text-left px-3 py-2 bg-red-500/10 text-red-400 border border-red-500/20 rounded hover:bg-red-500/20 transition-colors flex items-center gap-2"
                          >
                            <span className="font-mono text-sm bg-red-500/20 px-2 py-0.5 rounded">
                              {tech}
                            </span>
                            {name && (
                              <span className="text-gray-300 text-sm truncate">
                                {name}
                              </span>
                            )}
                            <a
                              href={getTechniqueUrl(tech)}
                              target="_blank"
                              rel="noopener noreferrer"
                              onClick={(e) => e.stopPropagation()}
                              className="ml-auto text-gray-500 hover:text-cyan-400 text-xs"
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
