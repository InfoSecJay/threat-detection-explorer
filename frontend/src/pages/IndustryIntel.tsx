import { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import ReactMarkdown from 'react-markdown';
import { useReleases } from '../hooks/useReleases';
import { useTrendingTechniques, useTrendingPlatforms } from '../hooks/useTrending';
import { useMitre } from '../contexts/MitreContext';
import type { Release } from '../services/api';

// Source display names and colors
const sourceConfig: Record<string, { name: string; color: string; bgColor: string; borderColor: string }> = {
  sigma: { name: 'SigmaHQ', color: 'text-blue-400', bgColor: 'bg-blue-500/20', borderColor: 'border-blue-500/30' },
  elastic: { name: 'Elastic', color: 'text-amber-400', bgColor: 'bg-amber-500/20', borderColor: 'border-amber-500/30' },
  splunk: { name: 'Splunk', color: 'text-green-400', bgColor: 'bg-green-500/20', borderColor: 'border-green-500/30' },
  sublime: { name: 'Sublime', color: 'text-purple-400', bgColor: 'bg-purple-500/20', borderColor: 'border-purple-500/30' },
  elastic_protections: { name: 'Elastic Protections', color: 'text-orange-400', bgColor: 'bg-orange-500/20', borderColor: 'border-orange-500/30' },
  lolrmm: { name: 'LOLRMM', color: 'text-pink-400', bgColor: 'bg-pink-500/20', borderColor: 'border-pink-500/30' },
};

// Time period options
const periodOptions = [
  { value: 30, label: '30 Days' },
  { value: 90, label: '90 Days' },
  { value: 180, label: '6 Months' },
  { value: 365, label: '1 Year' },
];

interface ReleaseWithSource extends Release {
  source: string;
}

function UnifiedReleaseFeed() {
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [sourceFilter, setSourceFilter] = useState<string>('all');

  // Fetch releases from all sources
  const { data: sigmaReleases, isLoading: sigmaLoading } = useReleases('sigma', 5);
  const { data: elasticReleases, isLoading: elasticLoading } = useReleases('elastic', 5);
  const { data: splunkReleases, isLoading: splunkLoading } = useReleases('splunk', 5);

  const isLoading = sigmaLoading || elasticLoading || splunkLoading;

  // Combine and sort releases by date
  const allReleases = useMemo(() => {
    const releases: ReleaseWithSource[] = [];

    if (sigmaReleases) {
      releases.push(...sigmaReleases.map((r) => ({ ...r, source: 'sigma' })));
    }
    if (elasticReleases) {
      releases.push(...elasticReleases.map((r) => ({ ...r, source: 'elastic' })));
    }
    if (splunkReleases) {
      releases.push(...splunkReleases.map((r) => ({ ...r, source: 'splunk' })));
    }

    // Sort by date descending
    return releases.sort(
      (a, b) => new Date(b.published_at).getTime() - new Date(a.published_at).getTime()
    );
  }, [sigmaReleases, elasticReleases, splunkReleases]);

  // Filter releases
  const filteredReleases = useMemo(() => {
    if (sourceFilter === 'all') return allReleases;
    return allReleases.filter((r) => r.source === sourceFilter);
  }, [allReleases, sourceFilter]);

  if (isLoading) {
    return (
      <div className="space-y-3">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="bg-void-850 border border-void-700 p-4 animate-pulse">
            <div className="flex gap-3">
              <div className="h-6 w-20 bg-void-700 rounded"></div>
              <div className="h-6 w-24 bg-void-700 rounded"></div>
              <div className="h-6 flex-1 bg-void-700 rounded"></div>
            </div>
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Filter Tabs */}
      <div className="flex items-center gap-2 overflow-x-auto pb-2">
        <button
          onClick={() => setSourceFilter('all')}
          className={`px-3 py-1.5 text-xs font-mono uppercase transition-colors ${
            sourceFilter === 'all'
              ? 'bg-matrix-500/20 text-matrix-400 border border-matrix-500/30'
              : 'bg-void-800 text-gray-400 border border-void-600 hover:text-white'
          }`}
        >
          All Sources
        </button>
        {['sigma', 'elastic', 'splunk'].map((source) => {
          const config = sourceConfig[source];
          return (
            <button
              key={source}
              onClick={() => setSourceFilter(source)}
              className={`px-3 py-1.5 text-xs font-mono uppercase transition-colors ${
                sourceFilter === source
                  ? `${config.bgColor} ${config.color} border ${config.borderColor}`
                  : 'bg-void-800 text-gray-400 border border-void-600 hover:text-white'
              }`}
            >
              {config.name}
            </button>
          );
        })}
      </div>

      {/* Release List */}
      <div className="space-y-3">
        {filteredReleases.map((release) => {
          const config = sourceConfig[release.source] || sourceConfig.sigma;
          const isExpanded = expandedId === release.id;

          return (
            <div
              key={`${release.source}-${release.id}`}
              className={`bg-void-850 border transition-all ${
                isExpanded ? config.borderColor : 'border-void-700'
              }`}
              style={{
                clipPath: 'polygon(0 0, calc(100% - 10px) 0, 100% 10px, 100% 100%, 10px 100%, 0 calc(100% - 10px))',
              }}
            >
              {/* Header - Always visible */}
              <button
                onClick={() => setExpandedId(isExpanded ? null : release.id)}
                className="w-full p-4 text-left hover:bg-void-800/50 transition-colors"
              >
                <div className="flex items-start gap-3">
                  {/* Source Badge */}
                  <span
                    className={`px-2 py-0.5 text-xs font-mono uppercase ${config.bgColor} ${config.color} border ${config.borderColor} flex-shrink-0`}
                  >
                    {config.name}
                  </span>

                  {/* Tag */}
                  <a
                    href={release.html_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    onClick={(e) => e.stopPropagation()}
                    className="font-mono text-sm text-matrix-500 hover:text-matrix-400 transition-colors flex-shrink-0"
                  >
                    {release.tag_name}
                  </a>

                  {/* Title */}
                  <span className="text-sm text-white truncate flex-1">
                    {release.name}
                  </span>

                  {/* Date */}
                  <span className="text-xs text-gray-500 font-mono flex-shrink-0">
                    {new Date(release.published_at).toLocaleDateString()}
                  </span>

                  {/* Expand icon */}
                  <svg
                    className={`w-4 h-4 text-gray-500 transition-transform flex-shrink-0 ${
                      isExpanded ? 'rotate-180' : ''
                    }`}
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </div>
              </button>

              {/* Expanded Content */}
              {isExpanded && release.body && (
                <div className="px-4 pb-4 border-t border-void-700">
                  <div className="pt-4 prose prose-invert prose-sm max-w-none prose-headings:text-white prose-headings:font-display prose-headings:mt-4 prose-headings:mb-2 prose-h2:text-base prose-h3:text-sm prose-p:text-gray-300 prose-p:my-2 prose-a:text-matrix-500 prose-a:no-underline hover:prose-a:underline prose-strong:text-white prose-code:text-matrix-400 prose-code:bg-void-800 prose-code:px-1 prose-code:py-0.5 prose-code:rounded prose-code:text-xs prose-pre:bg-void-900 prose-pre:border prose-pre:border-void-600 prose-ul:my-2 prose-ul:pl-4 prose-ol:my-2 prose-ol:pl-4 prose-li:text-gray-300 prose-li:my-1 prose-li:marker:text-matrix-500">
                    <ReactMarkdown>{release.body}</ReactMarkdown>
                  </div>
                  <div className="mt-4 pt-3 border-t border-void-700 flex items-center justify-between">
                    <span className="text-xs font-mono text-gray-500">
                      {release.author && `Published by ${release.author}`}
                    </span>
                    <a
                      href={release.html_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs font-mono text-matrix-500 hover:text-matrix-400 transition-colors"
                    >
                      VIEW_ON_GITHUB &rarr;
                    </a>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function TrendingTechniquesSection({ days }: { days: number }) {
  const { data, isLoading, error } = useTrendingTechniques(days, 10);
  const { getTechniqueName } = useMitre();

  if (isLoading) {
    return (
      <div className="space-y-2">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="h-12 bg-void-700 rounded animate-pulse"></div>
        ))}
      </div>
    );
  }

  if (error || !data?.techniques?.length) {
    return (
      <div className="text-center py-8 text-gray-500">
        <p className="font-mono text-sm">NO_TRENDING_DATA_AVAILABLE</p>
      </div>
    );
  }

  const maxCount = Math.max(...data.techniques.map((t) => t.count));

  return (
    <div className="space-y-2">
      {data.techniques.map((technique, index) => {
        const name = getTechniqueName(technique.technique_id);
        const percentage = (technique.count / maxCount) * 100;

        return (
          <Link
            key={technique.technique_id}
            to={`/compare?technique=${technique.technique_id}`}
            className="block group"
          >
            <div className="relative bg-void-800 border border-void-700 p-3 hover:border-matrix-500/30 transition-all">
              {/* Background bar */}
              <div
                className="absolute inset-y-0 left-0 bg-matrix-500/10 transition-all"
                style={{ width: `${percentage}%` }}
              />

              {/* Content */}
              <div className="relative flex items-center justify-between gap-3">
                <div className="flex items-center gap-3 min-w-0">
                  <span className="text-xs font-mono text-gray-500 w-5">
                    {index + 1}.
                  </span>
                  <span className="font-mono text-sm text-matrix-500 group-hover:text-matrix-400">
                    {technique.technique_id}
                  </span>
                  <span className="text-sm text-gray-400 truncate">
                    {name || 'Unknown Technique'}
                  </span>
                </div>
                <div className="flex items-center gap-3 flex-shrink-0">
                  <div className="flex gap-1">
                    {technique.sources.slice(0, 3).map((src) => (
                      <span
                        key={src}
                        className={`w-2 h-2 rounded-full ${
                          src === 'sigma' ? 'bg-blue-500' :
                          src === 'elastic' ? 'bg-amber-500' :
                          src === 'splunk' ? 'bg-green-500' :
                          'bg-gray-500'
                        }`}
                        title={src}
                      />
                    ))}
                  </div>
                  <span className="text-sm font-mono text-white">
                    {technique.count}
                  </span>
                </div>
              </div>
            </div>
          </Link>
        );
      })}
    </div>
  );
}

function TrendingPlatformsSection({ days }: { days: number }) {
  const { data, isLoading, error } = useTrendingPlatforms(days, 10);

  if (isLoading) {
    return (
      <div className="space-y-2">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="h-12 bg-void-700 rounded animate-pulse"></div>
        ))}
      </div>
    );
  }

  if (error || !data?.platforms?.length) {
    return (
      <div className="text-center py-8 text-gray-500">
        <p className="font-mono text-sm">NO_TRENDING_DATA_AVAILABLE</p>
      </div>
    );
  }

  const maxCount = Math.max(...data.platforms.map((p) => p.count));

  return (
    <div className="space-y-2">
      {data.platforms.map((platform, index) => {
        const percentage = (platform.count / maxCount) * 100;

        return (
          <Link
            key={platform.platform}
            to={`/compare?platform=${platform.platform}`}
            className="block group"
          >
            <div className="relative bg-void-800 border border-void-700 p-3 hover:border-cyan-500/30 transition-all">
              {/* Background bar */}
              <div
                className="absolute inset-y-0 left-0 bg-cyan-500/10 transition-all"
                style={{ width: `${percentage}%` }}
              />

              {/* Content */}
              <div className="relative flex items-center justify-between gap-3">
                <div className="flex items-center gap-3 min-w-0">
                  <span className="text-xs font-mono text-gray-500 w-5">
                    {index + 1}.
                  </span>
                  <span className="font-mono text-sm text-cyan-400 group-hover:text-cyan-300 uppercase">
                    {platform.platform.replace(/_/g, ' ')}
                  </span>
                </div>
                <div className="flex items-center gap-3 flex-shrink-0">
                  <div className="flex gap-1">
                    {platform.sources.slice(0, 3).map((src) => (
                      <span
                        key={src}
                        className={`w-2 h-2 rounded-full ${
                          src === 'sigma' ? 'bg-blue-500' :
                          src === 'elastic' ? 'bg-amber-500' :
                          src === 'splunk' ? 'bg-green-500' :
                          'bg-gray-500'
                        }`}
                        title={src}
                      />
                    ))}
                  </div>
                  <span className="text-sm font-mono text-white">
                    {platform.count}
                  </span>
                </div>
              </div>
            </div>
          </Link>
        );
      })}
    </div>
  );
}

export function IndustryIntel() {
  const [trendingPeriod, setTrendingPeriod] = useState(90);

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">
          Industry Intelligence
        </h1>
        <p className="text-sm text-gray-500 mt-1 font-mono">
          RELEASE_NOTES // TRENDING_TECHNIQUES // PLATFORM_ACTIVITY
        </p>
      </div>

      {/* Trending Section */}
      <section>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <svg className="w-5 h-5 text-matrix-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
            </svg>
            <h2 className="text-lg font-display font-bold text-white tracking-wider uppercase">
              Trending
            </h2>
          </div>

          {/* Period Selector */}
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-gray-500">PERIOD:</span>
            <select
              value={trendingPeriod}
              onChange={(e) => setTrendingPeriod(Number(e.target.value))}
              className="px-3 py-1.5 bg-void-800 border border-void-600 text-white text-sm focus:ring-matrix-500/50 focus:border-matrix-500/50"
            >
              {periodOptions.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Trending Techniques */}
          <div
            className="bg-void-850 border border-void-700 p-5"
            style={{
              clipPath: 'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))',
            }}
          >
            <div className="flex items-center gap-2 mb-4">
              <span className="w-2 h-2 bg-matrix-500 rounded-full"></span>
              <h3 className="font-display font-semibold text-matrix-400 text-sm uppercase tracking-wide">
                MITRE Techniques
              </h3>
              <span className="text-xs text-gray-500 font-mono ml-auto">
                by rule activity
              </span>
            </div>
            <TrendingTechniquesSection days={trendingPeriod} />
          </div>

          {/* Trending Platforms */}
          <div
            className="bg-void-850 border border-void-700 p-5"
            style={{
              clipPath: 'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))',
            }}
          >
            <div className="flex items-center gap-2 mb-4">
              <span className="w-2 h-2 bg-cyan-500 rounded-full"></span>
              <h3 className="font-display font-semibold text-cyan-400 text-sm uppercase tracking-wide">
                Platforms & Log Sources
              </h3>
              <span className="text-xs text-gray-500 font-mono ml-auto">
                by rule activity
              </span>
            </div>
            <TrendingPlatformsSection days={trendingPeriod} />
          </div>
        </div>
      </section>

      {/* Releases Section */}
      <section>
        <div className="flex items-center gap-3 mb-4">
          <svg className="w-5 h-5 text-matrix-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z" />
          </svg>
          <h2 className="text-lg font-display font-bold text-white tracking-wider uppercase">
            Latest Releases
          </h2>
        </div>

        <UnifiedReleaseFeed />
      </section>

      {/* Legend */}
      <div className="flex items-center justify-center gap-6 text-xs font-mono text-gray-500 flex-wrap">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-blue-500"></span>
          <span>SigmaHQ</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-amber-500"></span>
          <span>Elastic</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-green-500"></span>
          <span>Splunk</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-purple-500"></span>
          <span>Sublime</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-orange-500"></span>
          <span>Elastic Protections</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-pink-500"></span>
          <span>LOLRMM</span>
        </div>
      </div>
    </div>
  );
}
