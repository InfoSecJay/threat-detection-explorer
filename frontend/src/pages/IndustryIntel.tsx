import { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import ReactMarkdown from 'react-markdown';
import { useReleases } from '../hooks/useReleases';
import {
  useTrendingTechniques,
  useTrendingPlatforms,
  useRecentRules,
} from '../hooks/useTrending';
import { useFilterOptions } from '../hooks/useDetections';
import { useMitre } from '../contexts/MitreContext';
import type { Release, RecentRuleItem, ActivityFilters } from '../services/api';

// Source display names and colors
const sourceConfig: Record<
  string,
  { name: string; color: string; bgColor: string; borderColor: string; dot: string }
> = {
  sigma: {
    name: 'SigmaHQ',
    color: 'text-blue-400',
    bgColor: 'bg-blue-500/20',
    borderColor: 'border-blue-500/30',
    dot: 'bg-blue-500',
  },
  elastic: {
    name: 'Elastic',
    color: 'text-amber-400',
    bgColor: 'bg-amber-500/20',
    borderColor: 'border-amber-500/30',
    dot: 'bg-amber-500',
  },
  splunk: {
    name: 'Splunk',
    color: 'text-green-400',
    bgColor: 'bg-green-500/20',
    borderColor: 'border-green-500/30',
    dot: 'bg-green-500',
  },
  sublime: {
    name: 'Sublime',
    color: 'text-purple-400',
    bgColor: 'bg-purple-500/20',
    borderColor: 'border-purple-500/30',
    dot: 'bg-purple-500',
  },
  elastic_protections: {
    name: 'Elastic Protections',
    color: 'text-orange-400',
    bgColor: 'bg-orange-500/20',
    borderColor: 'border-orange-500/30',
    dot: 'bg-orange-500',
  },
  lolrmm: {
    name: 'LOLRMM',
    color: 'text-pink-400',
    bgColor: 'bg-pink-500/20',
    borderColor: 'border-pink-500/30',
    dot: 'bg-pink-500',
  },
  elastic_hunting: {
    name: 'Elastic Hunting',
    color: 'text-indigo-400',
    bgColor: 'bg-indigo-500/20',
    borderColor: 'border-indigo-500/30',
    dot: 'bg-indigo-500',
  },
  sentinel: {
    name: 'Sentinel',
    color: 'text-sky-400',
    bgColor: 'bg-sky-500/20',
    borderColor: 'border-sky-500/30',
    dot: 'bg-sky-500',
  },
};

const periodOptions = [
  { value: 30, label: '30d' },
  { value: 90, label: '90d' },
  { value: 180, label: '6mo' },
  { value: 365, label: '1y' },
];

interface ReleaseWithSource extends Release {
  source: string;
}

// ---------------------------------------------------------------------------
// Trending — compact row renderer shared by techniques + platforms
// ---------------------------------------------------------------------------

function TrendingRow({
  rank,
  primary,
  secondary,
  count,
  maxCount,
  sources,
  href,
  accent,
}: {
  rank: number;
  primary: string;
  secondary?: string;
  count: number;
  maxCount: number;
  sources: string[];
  href: string;
  accent: 'matrix' | 'cyan';
}) {
  const pct = (count / maxCount) * 100;
  const primaryCls = accent === 'matrix' ? 'text-matrix-500' : 'text-cyan-400';
  const barCls = accent === 'matrix' ? 'bg-matrix-500/10' : 'bg-cyan-500/10';
  return (
    <Link to={href} className="block group">
      <div className="relative bg-void-800/60 border border-void-700 hover:border-void-600 px-2.5 py-1.5 transition-colors">
        <div className={`absolute inset-y-0 left-0 ${barCls}`} style={{ width: `${pct}%` }} />
        <div className="relative flex items-center gap-2">
          <span className="text-[10px] font-mono text-gray-600 w-5 shrink-0">{rank}.</span>
          <span className={`font-mono text-xs ${primaryCls} shrink-0`}>{primary}</span>
          {secondary && (
            <span className="text-xs text-gray-400 truncate min-w-0 flex-1">{secondary}</span>
          )}
          {!secondary && <span className="flex-1" />}
          <div className="flex gap-0.5 shrink-0">
            {sources.slice(0, 4).map((src) => (
              <span
                key={src}
                className={`w-1.5 h-1.5 rounded-full ${sourceConfig[src]?.dot || 'bg-gray-500'}`}
                title={src}
              />
            ))}
          </div>
          <span className="text-xs font-mono text-white tabular-nums w-10 text-right shrink-0">
            {count}
          </span>
        </div>
      </div>
    </Link>
  );
}

function TrendingTechniquesSection({
  days,
  limit = 10,
  filters,
}: {
  days: number;
  limit?: number;
  filters: ActivityFilters;
}) {
  const { data, isLoading, error } = useTrendingTechniques(days, limit, filters);
  const { getTechniqueName } = useMitre();

  if (isLoading)
    return <SkeletonRows count={limit} />;
  if (error || !data?.techniques?.length)
    return <EmptyState label="NO_TRENDING_DATA" />;

  const maxCount = Math.max(...data.techniques.map((t) => t.count));
  return (
    <div className="space-y-1">
      {data.techniques.map((t, i) => (
        <TrendingRow
          key={t.technique_id}
          rank={i + 1}
          primary={t.technique_id}
          secondary={getTechniqueName(t.technique_id) || 'Unknown Technique'}
          count={t.count}
          maxCount={maxCount}
          sources={t.sources}
          href={`/mitre/${t.technique_id}`}
          accent="matrix"
        />
      ))}
    </div>
  );
}

function TrendingPlatformsSection({
  days,
  limit = 10,
  filters,
}: {
  days: number;
  limit?: number;
  filters: Omit<ActivityFilters, 'platforms'>;
}) {
  const { data, isLoading, error } = useTrendingPlatforms(days, limit, filters);

  if (isLoading)
    return <SkeletonRows count={limit} />;
  if (error || !data?.platforms?.length)
    return <EmptyState label="NO_TRENDING_DATA" />;

  const maxCount = Math.max(...data.platforms.map((p) => p.count));
  return (
    <div className="space-y-1">
      {data.platforms.map((p, i) => (
        <TrendingRow
          key={p.platform}
          rank={i + 1}
          primary={p.platform.replace(/_/g, ' ').toUpperCase()}
          count={p.count}
          maxCount={maxCount}
          sources={p.sources}
          href={`/detections?platforms=${p.platform}`}
          accent="cyan"
        />
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Recent rules — two columns of 20 most-created + most-modified
// ---------------------------------------------------------------------------

function formatDate(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  const now = new Date();
  const diffDays = Math.floor((now.getTime() - d.getTime()) / (1000 * 60 * 60 * 24));
  if (diffDays === 0) return 'today';
  if (diffDays === 1) return '1d ago';
  if (diffDays < 30) return `${diffDays}d ago`;
  if (diffDays < 365) return `${Math.floor(diffDays / 30)}mo ago`;
  return `${Math.floor(diffDays / 365)}y ago`;
}

const severityColor: Record<string, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-blue-400',
  informational: 'text-gray-400',
  unknown: 'text-gray-500',
};

function RecentRuleRow({ rule }: { rule: RecentRuleItem }) {
  const src = sourceConfig[rule.source];
  return (
    <Link
      to={`/detections/${rule.id}`}
      className="block px-2.5 py-1.5 hover:bg-void-800/50 border-b border-void-800 last:border-0 transition-colors group"
    >
      <div className="flex items-center gap-2">
        <span
          className={`w-1.5 h-1.5 rounded-full shrink-0 ${src?.dot || 'bg-gray-500'}`}
          title={src?.name || rule.source}
        />
        <span className={`text-[10px] font-mono uppercase shrink-0 w-10 ${severityColor[rule.severity] || 'text-gray-500'}`}>
          {rule.severity.slice(0, 4)}
        </span>
        <span className="text-xs text-gray-300 group-hover:text-white truncate min-w-0 flex-1">
          {rule.title}
        </span>
        <span className="text-[10px] font-mono text-gray-600 tabular-nums shrink-0">
          {formatDate(rule.date)}
        </span>
      </div>
    </Link>
  );
}

function RecentCreatedSection({ limit = 10, filters }: { limit?: number; filters: ActivityFilters }) {
  const { data, isLoading, error } = useRecentRules(limit, filters);
  if (isLoading) return <SkeletonRows count={limit} />;
  if (error || !data?.most_recently_created?.length)
    return <EmptyState label="NO_RECENT_DATA" />;
  return (
    <div>
      {data.most_recently_created.slice(0, limit).map((r) => (
        <RecentRuleRow key={`created-${r.id}`} rule={r} />
      ))}
    </div>
  );
}

function RecentModifiedSection({ limit = 10, filters }: { limit?: number; filters: ActivityFilters }) {
  const { data, isLoading, error } = useRecentRules(limit, filters);
  if (isLoading) return <SkeletonRows count={limit} />;
  if (error || !data?.most_recently_modified?.length)
    return <EmptyState label="NO_RECENT_DATA" />;
  return (
    <div>
      {data.most_recently_modified.slice(0, limit).map((r) => (
        <RecentRuleRow key={`modified-${r.id}`} rule={r} />
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Activity filter bar — narrows all 4 tables in the strip
// ---------------------------------------------------------------------------

function ActivityFilterBar({
  filters,
  setFilters,
}: {
  filters: ActivityFilters;
  setFilters: (f: ActivityFilters) => void;
}) {
  const { data: options } = useFilterOptions();

  const sources = options?.sources || [];
  const platforms = options?.platforms || [];

  const toggleSource = (src: string) => {
    const current = filters.sources || [];
    const next = current.includes(src) ? current.filter((s) => s !== src) : [...current, src];
    setFilters({ ...filters, sources: next.length ? next : undefined });
  };

  const setPlatform = (plat: string | null) => {
    setFilters({ ...filters, platforms: plat ? [plat] : undefined });
  };

  const activeCount =
    (filters.sources?.length || 0) + (filters.platforms?.length || 0) + (filters.event_types?.length || 0);

  return (
    <div className="bg-void-850 border border-void-700 px-3 py-2 flex items-center gap-3 flex-wrap">
      {/* Source chips */}
      <div className="flex items-center gap-1 flex-wrap">
        <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">src:</span>
        {sources.map((src) => {
          const cfg = sourceConfig[src];
          const active = filters.sources?.includes(src);
          return (
            <button
              key={src}
              onClick={() => toggleSource(src)}
              className={`px-2 py-0.5 text-[10px] font-mono uppercase transition-colors border ${
                active
                  ? `${cfg?.bgColor || 'bg-matrix-500/20'} ${cfg?.color || 'text-matrix-400'} ${cfg?.borderColor || 'border-matrix-500/30'}`
                  : 'bg-void-800 text-gray-400 border-void-600 hover:text-white'
              }`}
              title={cfg?.name || src}
            >
              {(cfg?.name || src).replace(' Protections', ' Prot').replace(' Hunting', ' Hunt')}
            </button>
          );
        })}
      </div>

      {/* Platform dropdown */}
      <div className="flex items-center gap-1">
        <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">plat:</span>
        <select
          value={filters.platforms?.[0] || ''}
          onChange={(e) => setPlatform(e.target.value || null)}
          className="bg-void-800 border border-void-600 text-xs text-gray-300 px-2 py-0.5 font-mono focus:outline-none focus:border-matrix-500/50 hover:text-white cursor-pointer"
        >
          <option value="">all platforms</option>
          {platforms.map((p) => (
            <option key={p.value} value={p.value}>
              {p.value} ({p.count})
            </option>
          ))}
        </select>
      </div>

      {activeCount > 0 && (
        <button
          onClick={() => setFilters({})}
          className="ml-auto text-[10px] font-mono text-gray-500 hover:text-breach-400 transition-colors uppercase tracking-wider"
        >
          [ clear ]
        </button>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Releases — kept the existing expandable-list shape, just tighter padding
// ---------------------------------------------------------------------------

function UnifiedReleaseFeed() {
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [sourceFilter, setSourceFilter] = useState<string>('all');

  const { data: sigmaReleases, isLoading: sigmaLoading } = useReleases('sigma', 5);
  const { data: elasticReleases, isLoading: elasticLoading } = useReleases('elastic', 5);
  const { data: splunkReleases, isLoading: splunkLoading } = useReleases('splunk', 5);
  const isLoading = sigmaLoading || elasticLoading || splunkLoading;

  const allReleases = useMemo(() => {
    const releases: ReleaseWithSource[] = [];
    if (sigmaReleases) releases.push(...sigmaReleases.map((r) => ({ ...r, source: 'sigma' })));
    if (elasticReleases) releases.push(...elasticReleases.map((r) => ({ ...r, source: 'elastic' })));
    if (splunkReleases) releases.push(...splunkReleases.map((r) => ({ ...r, source: 'splunk' })));
    return releases.sort(
      (a, b) => new Date(b.published_at).getTime() - new Date(a.published_at).getTime(),
    );
  }, [sigmaReleases, elasticReleases, splunkReleases]);

  const filtered = useMemo(
    () =>
      sourceFilter === 'all'
        ? allReleases
        : allReleases.filter((r) => r.source === sourceFilter),
    [allReleases, sourceFilter],
  );

  if (isLoading) return <SkeletonRows count={6} />;

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-1.5 overflow-x-auto pb-1">
        <button
          onClick={() => setSourceFilter('all')}
          className={`px-2 py-1 text-[10px] font-mono uppercase transition-colors ${
            sourceFilter === 'all'
              ? 'bg-matrix-500/20 text-matrix-400 border border-matrix-500/30'
              : 'bg-void-800 text-gray-400 border border-void-600 hover:text-white'
          }`}
        >
          All
        </button>
        {['sigma', 'elastic', 'splunk'].map((source) => {
          const cfg = sourceConfig[source];
          return (
            <button
              key={source}
              onClick={() => setSourceFilter(source)}
              className={`px-2 py-1 text-[10px] font-mono uppercase transition-colors ${
                sourceFilter === source
                  ? `${cfg.bgColor} ${cfg.color} border ${cfg.borderColor}`
                  : 'bg-void-800 text-gray-400 border border-void-600 hover:text-white'
              }`}
            >
              {cfg.name}
            </button>
          );
        })}
      </div>

      <div className="space-y-1.5">
        {filtered.map((release) => {
          const cfg = sourceConfig[release.source] || sourceConfig.sigma;
          const isExpanded = expandedId === release.id;
          return (
            <div
              key={`${release.source}-${release.id}`}
              className={`bg-void-850 border transition-all ${
                isExpanded ? cfg.borderColor : 'border-void-700'
              }`}
            >
              <button
                onClick={() => setExpandedId(isExpanded ? null : release.id)}
                className="w-full px-3 py-2 text-left hover:bg-void-800/50 transition-colors"
              >
                <div className="flex items-center gap-2">
                  <span
                    className={`px-1.5 py-0.5 text-[10px] font-mono uppercase ${cfg.bgColor} ${cfg.color} border ${cfg.borderColor} shrink-0`}
                  >
                    {cfg.name}
                  </span>
                  <span className="font-mono text-xs text-matrix-500 shrink-0">
                    {release.tag_name}
                  </span>
                  <span className="text-xs text-gray-300 truncate flex-1 min-w-0">
                    {release.name}
                  </span>
                  <span className="text-[10px] text-gray-500 font-mono shrink-0">
                    {new Date(release.published_at).toLocaleDateString()}
                  </span>
                  <svg
                    className={`w-3 h-3 text-gray-500 transition-transform shrink-0 ${
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
              {isExpanded && release.body && (
                <div className="px-3 pb-3 border-t border-void-700">
                  <div className="pt-3 prose prose-invert prose-sm max-w-none prose-headings:text-white prose-headings:font-display prose-headings:mt-3 prose-headings:mb-1.5 prose-h2:text-sm prose-h3:text-xs prose-p:text-gray-300 prose-p:my-1.5 prose-a:text-matrix-500 prose-a:no-underline hover:prose-a:underline prose-strong:text-white prose-code:text-matrix-400 prose-code:bg-void-800 prose-code:px-1 prose-code:py-0.5 prose-code:rounded prose-code:text-xs prose-pre:bg-void-900 prose-pre:border prose-pre:border-void-600 prose-ul:my-1.5 prose-ul:pl-4 prose-ol:my-1.5 prose-ol:pl-4 prose-li:text-gray-300 prose-li:my-0.5 prose-li:marker:text-matrix-500">
                    <ReactMarkdown>{release.body}</ReactMarkdown>
                  </div>
                  <div className="mt-2 pt-2 border-t border-void-700 flex items-center justify-between">
                    <span className="text-[10px] font-mono text-gray-500">
                      {release.author && `by ${release.author}`}
                    </span>
                    <a
                      href={release.html_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-[10px] font-mono text-matrix-500 hover:text-matrix-400 transition-colors"
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

// ---------------------------------------------------------------------------
// Shared shell components
// ---------------------------------------------------------------------------

function CompactCard({
  title,
  accent,
  action,
  children,
}: {
  title: string;
  accent: 'matrix' | 'cyan' | 'amber';
  action?: React.ReactNode;
  children: React.ReactNode;
}) {
  const dot =
    accent === 'matrix' ? 'bg-matrix-500' : accent === 'cyan' ? 'bg-cyan-500' : 'bg-amber-500';
  const text =
    accent === 'matrix' ? 'text-matrix-400' : accent === 'cyan' ? 'text-cyan-400' : 'text-amber-400';
  return (
    <div className="bg-void-850 border border-void-700">
      <div className="flex items-center gap-2 px-3 py-2 border-b border-void-800">
        <span className={`w-1.5 h-1.5 rounded-full ${dot}`} />
        <h3 className={`font-display font-semibold text-xs uppercase tracking-wider ${text}`}>
          {title}
        </h3>
        {action && <div className="ml-auto">{action}</div>}
      </div>
      <div className="p-2">{children}</div>
    </div>
  );
}

function SkeletonRows({ count }: { count: number }) {
  return (
    <div className="space-y-1">
      {[...Array(count)].map((_, i) => (
        <div key={i} className="h-7 bg-void-800 animate-pulse" />
      ))}
    </div>
  );
}

function EmptyState({ label }: { label: string }) {
  return (
    <div className="text-center py-6 text-gray-500">
      <p className="font-mono text-xs">{label}</p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function IndustryIntel() {
  const [trendingPeriod, setTrendingPeriod] = useState(90);
  const [activityFilters, setActivityFilters] = useState<ActivityFilters>({});

  // Drop `platforms` before passing filters to the platforms-trending
  // query — filtering by the grouping key would return only that key.
  const platformsTrendingFilters = useMemo(() => {
    const { platforms: _p, ...rest } = activityFilters;
    return rest;
  }, [activityFilters]);

  return (
    <div className="space-y-5">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">
          Industry Intelligence
        </h1>
        <p className="text-xs text-gray-500 mt-0.5 font-mono">
          OPEN_SOURCE_REPO_UPDATES // RECENT_RULES // TRENDING_TTPS_AND_PLATFORMS
        </p>
      </div>

      {/* Hero — upstream releases (the main signal: what did Sigma,
          Splunk, Elastic, etc. just ship?) */}
      <section>
        <div className="flex items-center gap-2 mb-2">
          <svg className="w-4 h-4 text-matrix-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z" />
          </svg>
          <h2 className="text-sm font-display font-bold text-white tracking-wider uppercase">
            Upstream Repo Releases
          </h2>
          <span className="text-[10px] text-gray-500 font-mono ml-auto">sigma · splunk · elastic</span>
        </div>
        <UnifiedReleaseFeed />
      </section>

      {/* Activity strip — 4 tables side-by-side, shared filter bar */}
      <section>
        <div className="flex items-center gap-2 mb-2 flex-wrap">
          <svg className="w-4 h-4 text-matrix-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
          </svg>
          <h2 className="text-sm font-display font-bold text-white tracking-wider uppercase">
            Catalog Activity
          </h2>
          <div className="ml-auto flex items-center gap-1">
            <span className="text-[10px] text-gray-500 font-mono mr-1">trending window:</span>
            {periodOptions.map((opt) => (
              <button
                key={opt.value}
                onClick={() => setTrendingPeriod(opt.value)}
                className={`px-2 py-0.5 text-[10px] font-mono uppercase transition-colors ${
                  trendingPeriod === opt.value
                    ? 'bg-matrix-500/20 text-matrix-400 border border-matrix-500/30'
                    : 'bg-void-800 text-gray-500 border border-void-700 hover:text-white'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>

        <div className="mb-3">
          <ActivityFilterBar filters={activityFilters} setFilters={setActivityFilters} />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
          <CompactCard title="Recently Created" accent="matrix">
            <RecentCreatedSection limit={10} filters={activityFilters} />
          </CompactCard>
          <CompactCard title="Recently Modified" accent="cyan">
            <RecentModifiedSection limit={10} filters={activityFilters} />
          </CompactCard>
          <CompactCard title="Trending Techniques" accent="matrix">
            <TrendingTechniquesSection days={trendingPeriod} limit={10} filters={activityFilters} />
          </CompactCard>
          <CompactCard title="Trending Platforms" accent="cyan">
            <TrendingPlatformsSection days={trendingPeriod} limit={10} filters={platformsTrendingFilters} />
          </CompactCard>
        </div>
      </section>
    </div>
  );
}
