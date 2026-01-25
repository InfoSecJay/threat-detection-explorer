import { useState } from 'react';
import { Link } from 'react-router-dom';
import ReactMarkdown from 'react-markdown';
import { useReleaseSources, useReleases } from '../hooks/useReleases';
import { useTrendingTechniques, useTrendingPlatforms, useTrendingSummary } from '../hooks/useTrending';
import { useMitre } from '../contexts/MitreContext';

// Source display names and colors
const sourceConfig: Record<string, { name: string; color: string; bgColor: string }> = {
  sigma: { name: 'SigmaHQ', color: 'text-blue-400', bgColor: 'bg-blue-500/20' },
  elastic: { name: 'Elastic', color: 'text-amber-400', bgColor: 'bg-amber-500/20' },
  splunk: { name: 'Splunk', color: 'text-green-400', bgColor: 'bg-green-500/20' },
};

// Time period options
const periodOptions = [
  { value: 30, label: '30 Days' },
  { value: 90, label: '90 Days' },
  { value: 180, label: '6 Months' },
  { value: 365, label: '1 Year' },
];

function ReleaseCard({ source }: { source: string }) {
  const { data: releases, isLoading, error } = useReleases(source, 3);
  const config = sourceConfig[source] || { name: source, color: 'text-gray-400', bgColor: 'bg-gray-500/20' };

  if (isLoading) {
    return (
      <div className="bg-void-850 border border-void-700 p-4 animate-pulse">
        <div className="h-6 bg-void-700 rounded w-1/3 mb-4"></div>
        <div className="space-y-3">
          <div className="h-4 bg-void-700 rounded w-full"></div>
          <div className="h-4 bg-void-700 rounded w-2/3"></div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-void-850 border border-breach-500/30 p-4">
        <h3 className={`font-display font-semibold ${config.color} mb-2`}>{config.name}</h3>
        <p className="text-sm text-breach-400">Failed to load releases</p>
      </div>
    );
  }

  return (
    <div
      className="bg-void-850 border border-void-700 overflow-hidden"
      style={{
        clipPath: 'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))',
      }}
    >
      {/* Header */}
      <div className={`px-4 py-3 ${config.bgColor} border-b border-void-700`}>
        <h3 className={`font-display font-semibold ${config.color} uppercase tracking-wide`}>
          {config.name}
        </h3>
      </div>

      {/* Releases */}
      <div className="divide-y divide-void-700">
        {releases?.map((release) => (
          <div key={release.id} className="p-4 hover:bg-void-800/50 transition-colors">
            <div className="flex items-start justify-between gap-3 mb-2">
              <a
                href={release.html_url}
                target="_blank"
                rel="noopener noreferrer"
                className="font-mono text-sm text-matrix-500 hover:text-matrix-400 transition-colors"
              >
                {release.tag_name}
              </a>
              <span className="text-xs text-gray-500 font-mono whitespace-nowrap">
                {new Date(release.published_at).toLocaleDateString()}
              </span>
            </div>
            <h4 className="text-sm text-white font-medium mb-2 line-clamp-1">
              {release.name}
            </h4>
            {release.body && (
              <div className="text-xs text-gray-400 line-clamp-3 prose prose-invert prose-xs max-w-none">
                <ReactMarkdown>{release.body.slice(0, 300)}</ReactMarkdown>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* View all link */}
      <div className="px-4 py-2 bg-void-900 border-t border-void-700">
        <a
          href={`https://github.com/${source === 'sigma' ? 'SigmaHQ/sigma' : source === 'elastic' ? 'elastic/detection-rules' : 'splunk/security_content'}/releases`}
          target="_blank"
          rel="noopener noreferrer"
          className="text-xs font-mono text-gray-500 hover:text-matrix-500 transition-colors"
        >
          VIEW_ALL_RELEASES &rarr;
        </a>
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

function ActivitySummary({ days }: { days: number }) {
  const { data, isLoading } = useTrendingSummary(days);

  if (isLoading || !data) {
    return null;
  }

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
      {/* Total Modified */}
      <div
        className="bg-void-850 border border-void-700 p-4"
        style={{
          clipPath: 'polygon(0 0, calc(100% - 8px) 0, 100% 8px, 100% 100%, 8px 100%, 0 calc(100% - 8px))',
        }}
      >
        <div className="text-xs font-mono text-gray-500 mb-1">RULES_UPDATED</div>
        <div className="text-2xl font-display font-bold text-matrix-500">
          {data.total_modified.toLocaleString()}
        </div>
        <div className="text-xs text-gray-500">in last {days} days</div>
      </div>

      {/* By Source */}
      {Object.entries(data.by_source)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map(([source, count]) => {
          const config = sourceConfig[source] || { name: source, color: 'text-gray-400' };
          return (
            <div
              key={source}
              className="bg-void-850 border border-void-700 p-4"
              style={{
                clipPath: 'polygon(0 0, calc(100% - 8px) 0, 100% 8px, 100% 100%, 8px 100%, 0 calc(100% - 8px))',
              }}
            >
              <div className="text-xs font-mono text-gray-500 mb-1 uppercase">{config.name}</div>
              <div className={`text-2xl font-display font-bold ${config.color}`}>
                {count.toLocaleString()}
              </div>
              <div className="text-xs text-gray-500">rules updated</div>
            </div>
          );
        })}
    </div>
  );
}

export function IndustryIntel() {
  const [trendingPeriod, setTrendingPeriod] = useState(90);
  const { data: sources } = useReleaseSources();

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

      {/* Activity Summary */}
      <ActivitySummary days={trendingPeriod} />

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

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {(sources || [{ id: 'sigma' }, { id: 'elastic' }, { id: 'splunk' }]).map((source) => (
            <ReleaseCard key={source.id} source={source.id} />
          ))}
        </div>
      </section>

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

      {/* Legend */}
      <div className="flex items-center justify-center gap-6 text-xs font-mono text-gray-500">
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
      </div>
    </div>
  );
}
