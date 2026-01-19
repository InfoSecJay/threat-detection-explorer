import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { RuleComparison } from '../components/RuleComparison';
import { useCompare, useCoverageGap } from '../hooks/useCompare';

export function Compare() {
  const [searchParams, setSearchParams] = useSearchParams();

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
      <div>
        <h1 className="text-2xl font-bold">Cross-Vendor Comparison</h1>
        <p className="text-gray-600 mt-1">
          Compare detection coverage across all vendors
        </p>
      </div>

      {/* Search form */}
      <div className="bg-white rounded-lg shadow p-6">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="flex gap-4">
            <label className="flex items-center">
              <input
                type="radio"
                name="queryType"
                value="technique"
                checked={queryType === 'technique'}
                onChange={() => setQueryType('technique')}
                className="mr-2"
              />
              MITRE Technique
            </label>
            <label className="flex items-center">
              <input
                type="radio"
                name="queryType"
                value="keyword"
                checked={queryType === 'keyword'}
                onChange={() => setQueryType('keyword')}
                className="mr-2"
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
              className="flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
            />
            <button
              type="submit"
              disabled={!queryValue.trim()}
              className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Compare
            </button>
          </div>
        </form>

        {/* Quick technique suggestions */}
        <div className="mt-4">
          <p className="text-sm text-gray-600 mb-2">Popular techniques:</p>
          <div className="flex flex-wrap gap-2">
            {['T1059', 'T1055', 'T1027', 'T1105', 'T1053'].map((tech) => (
              <button
                key={tech}
                onClick={() => {
                  setQueryType('technique');
                  setQueryValue(tech);
                  setSubmittedQuery({ technique: tech, keyword: undefined });
                  setSearchParams({ technique: tech });
                }}
                className="px-3 py-1 bg-gray-100 text-gray-700 rounded-full text-sm hover:bg-gray-200"
              >
                {tech}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Comparison results */}
      {compareLoading && (
        <div className="text-center py-8">
          <div className="animate-spin h-8 w-8 border-4 border-blue-600 border-t-transparent rounded-full mx-auto"></div>
          <p className="mt-2 text-gray-600">Loading comparison...</p>
        </div>
      )}

      {compareError && (
        <div className="bg-red-100 text-red-700 p-4 rounded-lg">
          Error: {compareError.message}
        </div>
      )}

      {compareData && <RuleComparison data={compareData} />}

      {/* Coverage gap analysis */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-bold">Coverage Gap Analysis</h2>
          <button
            onClick={() => setShowGapAnalysis(!showGapAnalysis)}
            className="text-blue-600 hover:text-blue-800"
          >
            {showGapAnalysis ? 'Hide' : 'Show'}
          </button>
        </div>

        {showGapAnalysis && (
          <div className="space-y-4">
            <div className="flex items-center gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Base Source
                </label>
                <select
                  value={gapBaseSource}
                  onChange={(e) => setGapBaseSource(e.target.value)}
                  className="mt-1 px-3 py-2 border border-gray-300 rounded-md"
                >
                  <option value="sigma">Sigma</option>
                  <option value="elastic">Elastic</option>
                  <option value="splunk">Splunk</option>
                  <option value="sublime">Sublime</option>
                  <option value="elastic_protections">Elastic Protections</option>
                  <option value="lolrmm">LOLRMM</option>
                </select>
              </div>
              <div className="pt-6">vs</div>
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Compare Source
                </label>
                <select
                  value={gapCompareSource}
                  onChange={(e) => setGapCompareSource(e.target.value)}
                  className="mt-1 px-3 py-2 border border-gray-300 rounded-md"
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

            {gapLoading && <p className="text-gray-600">Loading gap analysis...</p>}

            {gapData && (
              <div className="grid grid-cols-2 gap-4">
                <div className="p-4 bg-green-50 rounded-lg">
                  <h4 className="font-semibold text-green-800">Overlapping Coverage</h4>
                  <p className="text-2xl font-bold text-green-600">
                    {gapData.overlap_count} techniques
                  </p>
                </div>
                <div className="p-4 bg-red-50 rounded-lg">
                  <h4 className="font-semibold text-red-800">
                    Gaps ({gapBaseSource} only)
                  </h4>
                  <p className="text-2xl font-bold text-red-600">
                    {gapData.gaps.length} techniques
                  </p>
                </div>

                {gapData.gaps.length > 0 && (
                  <div className="col-span-2">
                    <h4 className="font-semibold mb-2">
                      Techniques in {gapBaseSource} but not in {gapCompareSource}:
                    </h4>
                    <div className="flex flex-wrap gap-2 max-h-32 overflow-y-auto">
                      {gapData.gaps.map((tech) => (
                        <button
                          key={tech}
                          onClick={() => {
                            setQueryType('technique');
                            setQueryValue(tech);
                            setSubmittedQuery({ technique: tech, keyword: undefined });
                          }}
                          className="px-2 py-1 bg-red-100 text-red-800 rounded text-sm hover:bg-red-200"
                        >
                          {tech}
                        </button>
                      ))}
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
