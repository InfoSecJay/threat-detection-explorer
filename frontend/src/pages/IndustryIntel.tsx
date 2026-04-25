import { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import ReactMarkdown from 'react-markdown';
import { useReleases } from '../hooks/useReleases';
import {
  useTrendingTechniques,
  useTrendingPlatforms,
  useTrendingSummary,
  useRecentRules,
  useThreatPulse,
} from '../hooks/useTrending';
import { useFilterOptions } from '../hooks/useDetections';
import { useMitre } from '../contexts/MitreContext';
import { sourceTheme as sourceConfig, clipSm, clipMd } from '../constants/style';
import type {
  Release, RecentRuleItem, ActivityFilters, NamedThreat, CveMention,
} from '../services/api';

const severityColor: Record<string, string> = {
  critical: 'text-red-400 border-red-500/40 bg-red-500/10',
  high: 'text-orange-400 border-orange-500/40 bg-orange-500/10',
  medium: 'text-yellow-400 border-yellow-500/40 bg-yellow-500/10',
  low: 'text-blue-400 border-blue-500/40 bg-blue-500/10',
  informational: 'text-gray-400 border-gray-600/40 bg-void-800',
  unknown: 'text-gray-500 border-gray-600/40 bg-void-800',
};

interface ReleaseWithSource extends Release {
  source: string;
}

function formatRelDate(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  const diffDays = Math.floor((Date.now() - d.getTime()) / (1000 * 60 * 60 * 24));
  if (diffDays < 1) return 'today';
  if (diffDays === 1) return '1d';
  if (diffDays < 30) return `${diffDays}d`;
  if (diffDays < 365) return `${Math.floor(diffDays / 30)}mo`;
  return `${Math.floor(diffDays / 365)}y`;
}

// ---------------------------------------------------------------------------
// Shared shell
// ---------------------------------------------------------------------------

function Section({
  title,
  subtitle,
  action,
  children,
}: {
  title: string;
  subtitle?: string;
  action?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section>
      <div className="flex items-baseline justify-between gap-3 mb-3 flex-wrap">
        <div className="flex items-baseline gap-3">
          <h2 className="text-sm font-display font-bold text-white tracking-wider uppercase">
            {title}
          </h2>
          {subtitle && <span className="text-[10px] text-gray-500 font-mono">{subtitle}</span>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}

function SkeletonRow({ height = 'h-8' }: { height?: string }) {
  return <div className={`${height} bg-void-800 animate-pulse rounded-sm`} />;
}

function EmptyLabel({ label }: { label: string }) {
  return <div className="text-center py-6 text-gray-500 font-mono text-xs">{label}</div>;
}

// ---------------------------------------------------------------------------
// Pulse banner — "142 new rules · 6 repos · last 30d"
// ---------------------------------------------------------------------------

function PulseBanner({ days }: { days: number }) {
  const { data, isLoading } = useTrendingSummary(days);

  if (isLoading) {
    return <SkeletonRow height="h-20" />;
  }
  if (!data) return null;

  const entries = Object.entries(data.by_source).sort(([, a], [, b]) => b - a);
  const activeSources = entries.length;

  return (
    <div
      className="bg-gradient-to-r from-matrix-500/10 via-cyan-500/5 to-transparent border border-matrix-500/30 px-5 py-4"
      style={clipMd}
    >
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <div className="text-[10px] font-mono text-matrix-400 uppercase tracking-[0.2em] mb-1">
            Detection Pulse · last {days}d
          </div>
          <div className="flex items-baseline gap-3 flex-wrap">
            <span className="text-3xl font-display font-bold text-white tabular-nums">
              {data.total_modified.toLocaleString()}
            </span>
            <span className="text-sm text-gray-400 font-mono">rule updates</span>
            <span className="text-xs text-gray-600 font-mono">·</span>
            <span className="text-sm text-matrix-400 font-mono">{activeSources} active repos</span>
          </div>
        </div>

        {/* Per-source breakdown bars */}
        <div className="flex gap-1.5 items-end flex-wrap">
          {entries.map(([src, count]) => {
            const cfg = sourceConfig[src] || sourceConfig.sigma;
            const max = entries[0]?.[1] || 1;
            const pct = Math.max(15, Math.round((count / max) * 100));
            return (
              <div key={src} className="flex flex-col items-center gap-0.5" title={`${cfg.name}: ${count}`}>
                <div
                  className={`w-6 ${cfg.dot} transition-all`}
                  style={{ height: `${pct * 0.4}px` }}
                />
                <div className="text-[9px] font-mono text-gray-500 uppercase">{src.slice(0, 3)}</div>
                <div className={`text-[10px] font-mono ${cfg.text} tabular-nums`}>{count}</div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Threat Pulse — named campaigns/malware from vendor tags
// ---------------------------------------------------------------------------

function ThreatCard({ threat }: { threat: NamedThreat }) {
  const kindBadge = threat.kind === 'malware'
    ? 'bg-orange-500/10 text-orange-400 border-orange-500/30'
    : 'bg-breach-500/10 text-breach-400 border-breach-500/30';
  const kindLabel = threat.kind === 'malware' ? 'MALWARE' : 'CAMPAIGN';

  // Link to the Detections page filtered by one example rule's source
  // (no cross-vendor threat-name filter exists yet — clicking takes user
  // to that source's rule list so they can explore further).
  const example = threat.examples[0];

  return (
    <Link
      to={example ? `/detections/${example.id}` : '/detections'}
      className="group block bg-void-850 border border-void-700 hover:border-breach-500/40 p-3 transition-colors"
      style={clipSm}
    >
      <div className="flex items-start justify-between gap-2 mb-1.5">
        <span className={`text-[9px] font-mono uppercase tracking-wider px-1.5 py-0.5 border ${kindBadge}`}>
          {kindLabel}
        </span>
        <span className="text-base font-display font-bold text-white tabular-nums">
          {threat.count}
        </span>
      </div>
      <div className="text-sm text-gray-200 font-mono leading-tight line-clamp-2 mb-2 min-h-[2.5rem] group-hover:text-white">
        {threat.name}
      </div>
      <div className="flex items-center gap-1">
        {threat.sources.map((src) => {
          const cfg = sourceConfig[src];
          return (
            <span
              key={src}
              className={`w-1.5 h-1.5 rounded-full ${cfg?.dot || 'bg-gray-500'}`}
              title={cfg?.name || src}
            />
          );
        })}
        <span className="text-[10px] font-mono text-gray-500 ml-1">
          {threat.sources.length} {threat.sources.length === 1 ? 'source' : 'sources'}
        </span>
      </div>
    </Link>
  );
}

function CveCard({ cve }: { cve: CveMention }) {
  const year = parseInt(cve.cve.slice(4, 8));
  const isRecent = year >= new Date().getFullYear() - 1;

  return (
    <a
      href={`https://nvd.nist.gov/vuln/detail/${cve.cve}`}
      target="_blank"
      rel="noopener noreferrer"
      className={`group block bg-void-850 border p-3 transition-colors ${
        isRecent ? 'border-breach-500/30 hover:border-breach-500/60' : 'border-void-700 hover:border-gray-500'
      }`}
      style={clipSm}
    >
      <div className="flex items-start justify-between gap-2 mb-1.5">
        <span className={`text-[9px] font-mono uppercase tracking-wider px-1.5 py-0.5 border ${
          isRecent ? 'text-breach-400 border-breach-500/40 bg-breach-500/10' : 'text-gray-500 border-gray-600/40 bg-void-800'
        }`}>
          CVE
        </span>
        <span className="text-base font-display font-bold text-white tabular-nums">{cve.count}</span>
      </div>
      <div className="text-sm text-gray-200 font-mono font-bold leading-tight mb-2 group-hover:text-matrix-400">
        {cve.cve}
      </div>
      <div className="flex items-center gap-1">
        {cve.sources.map((src) => {
          const cfg = sourceConfig[src];
          return (
            <span
              key={src}
              className={`w-1.5 h-1.5 rounded-full ${cfg?.dot || 'bg-gray-500'}`}
              title={cfg?.name || src}
            />
          );
        })}
        <span className="text-[10px] font-mono text-gray-500 ml-1">nvd ↗</span>
      </div>
    </a>
  );
}

function ThreatPulseSection() {
  const { data, isLoading, error } = useThreatPulse(12);

  if (isLoading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-2">
        {[...Array(6)].map((_, i) => <SkeletonRow key={i} height="h-24" />)}
      </div>
    );
  }
  if (error || !data) return <EmptyLabel label="NO_THREAT_DATA" />;

  const threats = data.named_threats.slice(0, 12);
  const cves = data.cves.slice(0, 6);

  return (
    <div className="space-y-3">
      {threats.length > 0 && (
        <div>
          <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider mb-2">
            named threats · {threats.length} specific campaigns &amp; malware families
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-2">
            {threats.map((t) => <ThreatCard key={t.name} threat={t} />)}
          </div>
        </div>
      )}

      {cves.length > 0 && (
        <div>
          <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider mb-2">
            cve watch · vulnerabilities most covered by vendor rules
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2">
            {cves.map((c) => <CveCard key={c.cve} cve={c} />)}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Upstream releases — hero feed for sigma/splunk/elastic repo updates
// ---------------------------------------------------------------------------

function UpstreamReleases() {
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const { data: sigmaReleases, isLoading: sigmaLoading } = useReleases('sigma', 3);
  const { data: elasticReleases, isLoading: elasticLoading } = useReleases('elastic', 3);
  const { data: splunkReleases, isLoading: splunkLoading } = useReleases('splunk', 3);
  const isLoading = sigmaLoading || elasticLoading || splunkLoading;

  const releases = useMemo<ReleaseWithSource[]>(() => {
    const all: ReleaseWithSource[] = [];
    if (sigmaReleases) all.push(...sigmaReleases.map((r) => ({ ...r, source: 'sigma' })));
    if (elasticReleases) all.push(...elasticReleases.map((r) => ({ ...r, source: 'elastic' })));
    if (splunkReleases) all.push(...splunkReleases.map((r) => ({ ...r, source: 'splunk' })));
    return all
      .sort((a, b) => new Date(b.published_at).getTime() - new Date(a.published_at).getTime())
      .slice(0, 6);
  }, [sigmaReleases, elasticReleases, splunkReleases]);

  if (isLoading) {
    return (
      <div className="space-y-2">
        {[...Array(3)].map((_, i) => <SkeletonRow key={i} height="h-16" />)}
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {releases.map((release) => {
        const cfg = sourceConfig[release.source] || sourceConfig.sigma;
        const expanded = expandedId === release.id;
        return (
          <div
            key={`${release.source}-${release.id}`}
            className={`bg-void-850 border transition-colors ${
              expanded ? cfg.border : 'border-void-700 hover:border-void-600'
            }`}
            style={clipSm}
          >
            <button
              onClick={() => setExpandedId(expanded ? null : release.id)}
              className="w-full px-3 py-2.5 text-left flex items-center gap-2.5"
            >
              <span className={`px-1.5 py-0.5 text-[10px] font-mono uppercase tracking-wider shrink-0 ${cfg.bg} ${cfg.text} border ${cfg.border}`}>
                {cfg.name}
              </span>
              <span className="font-mono text-xs text-matrix-500 shrink-0">{release.tag_name}</span>
              <span className="text-sm text-gray-200 flex-1 truncate min-w-0">
                {release.name || release.tag_name}
              </span>
              <span className="text-[10px] text-gray-500 font-mono shrink-0">
                {formatRelDate(release.published_at)}
              </span>
              <svg
                className={`w-3 h-3 text-gray-500 transition-transform shrink-0 ${expanded ? 'rotate-180' : ''}`}
                fill="none" stroke="currentColor" viewBox="0 0 24 24"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>
            {expanded && release.body && (
              <div className="px-3 pb-3 border-t border-void-700">
                <div className="pt-2.5 prose prose-invert prose-sm max-w-none prose-headings:text-white prose-headings:font-display prose-headings:mt-2 prose-headings:mb-1 prose-h2:text-xs prose-h3:text-xs prose-p:text-gray-300 prose-p:my-1 prose-a:text-matrix-500 prose-a:no-underline hover:prose-a:underline prose-strong:text-white prose-code:text-matrix-400 prose-code:bg-void-800 prose-code:px-1 prose-code:rounded prose-code:text-xs prose-ul:my-1 prose-ul:pl-4 prose-ol:my-1 prose-ol:pl-4 prose-li:text-gray-300 prose-li:my-0 prose-li:marker:text-matrix-500">
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
                    className="text-[10px] font-mono text-matrix-500 hover:text-matrix-400"
                  >
                    VIEW_ON_GITHUB ↗
                  </a>
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Notable new rules — richer cards instead of 20 tiny rows
// ---------------------------------------------------------------------------

function NotableRuleCard({ rule }: { rule: RecentRuleItem }) {
  const cfg = sourceConfig[rule.source];
  const sev = severityColor[rule.severity] || severityColor.unknown;

  return (
    <Link
      to={`/detections/${rule.id}`}
      className="group block bg-void-850 border border-void-700 hover:border-matrix-500/40 p-3 transition-colors"
      style={clipSm}
    >
      <div className="flex items-center gap-2 mb-1.5">
        <span className={`text-[9px] font-mono uppercase tracking-wider px-1.5 py-0.5 border ${cfg?.bg || ''} ${cfg?.text || ''} ${cfg?.border || ''}`}>
          {cfg?.name || rule.source}
        </span>
        <span className={`text-[9px] font-mono uppercase tracking-wider px-1.5 py-0.5 border ${sev}`}>
          {rule.severity.slice(0, 4)}
        </span>
        <span className="text-[10px] font-mono text-gray-600 ml-auto">
          {formatRelDate(rule.date)}
        </span>
      </div>
      <div className="text-sm text-gray-200 leading-tight line-clamp-2 mb-2 min-h-[2.5rem] group-hover:text-white">
        {rule.title}
      </div>
      {(rule.platforms.length > 0 || rule.event_types.length > 0) && (
        <div className="flex items-center gap-1 flex-wrap">
          {rule.platforms.slice(0, 3).map((p) => (
            <span key={p} className="text-[9px] font-mono text-cyan-400/80 bg-cyan-500/5 border border-cyan-500/20 px-1.5 py-0.5">
              {p}
            </span>
          ))}
          {rule.event_types.slice(0, 2).map((e) => (
            <span key={e} className="text-[9px] font-mono text-gray-500 bg-void-800 border border-void-600 px-1.5 py-0.5">
              {e}
            </span>
          ))}
        </div>
      )}
    </Link>
  );
}

function NotableNewRulesSection({ filters }: { filters: ActivityFilters }) {
  const { data, isLoading, error } = useRecentRules(12, filters);

  // useMemo must run on every render — never conditionally. Guarded
  // against undefined `data` instead of hidden behind early returns.
  const merged = useMemo(() => {
    if (!data) return [] as RecentRuleItem[];
    const byId = new Map<string, RecentRuleItem>();
    for (const r of [...data.most_recently_created, ...data.most_recently_modified]) {
      const existing = byId.get(r.id);
      if (!existing || (r.date && existing.date && r.date > existing.date)) {
        byId.set(r.id, r);
      }
    }
    return Array.from(byId.values())
      .sort((a, b) => (b.date || '').localeCompare(a.date || ''))
      .slice(0, 6);
  }, [data]);

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
        {[...Array(6)].map((_, i) => <SkeletonRow key={i} height="h-24" />)}
      </div>
    );
  }
  if (error || !data) return <EmptyLabel label="NO_RECENT_DATA" />;
  if (merged.length === 0) return <EmptyLabel label="NO_RECENT_DATA" />;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
      {merged.map((r) => <NotableRuleCard key={r.id} rule={r} />)}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Bottom strip — trending techniques + platforms (compact rows, de-emphasized)
// ---------------------------------------------------------------------------

function TrendingRow({
  rank, primary, secondary, count, maxCount, sources, href, accent,
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
          {secondary && <span className="text-xs text-gray-400 truncate min-w-0 flex-1">{secondary}</span>}
          {!secondary && <span className="flex-1" />}
          <div className="flex gap-0.5 shrink-0">
            {sources.slice(0, 4).map((src) => (
              <span key={src} className={`w-1.5 h-1.5 rounded-full ${sourceConfig[src]?.dot || 'bg-gray-500'}`} title={src} />
            ))}
          </div>
          <span className="text-xs font-mono text-white tabular-nums w-10 text-right shrink-0">{count}</span>
        </div>
      </div>
    </Link>
  );
}

function TrendingTechniquesList({ days, filters }: { days: number; filters: ActivityFilters }) {
  const { data, isLoading, error } = useTrendingTechniques(days, 8, filters);
  const { getTechniqueName } = useMitre();

  if (isLoading) return <div className="space-y-1">{[...Array(8)].map((_, i) => <SkeletonRow key={i} />)}</div>;
  if (error || !data?.techniques?.length) return <EmptyLabel label="NO_TRENDING_DATA" />;

  const max = Math.max(...data.techniques.map((t) => t.count));
  return (
    <div className="space-y-1">
      {data.techniques.map((t, i) => (
        <TrendingRow
          key={t.technique_id}
          rank={i + 1}
          primary={t.technique_id}
          secondary={getTechniqueName(t.technique_id) || 'Unknown Technique'}
          count={t.count}
          maxCount={max}
          sources={t.sources}
          href={`/mitre/${t.technique_id}`}
          accent="matrix"
        />
      ))}
    </div>
  );
}

function TrendingPlatformsList({
  days,
  filters,
}: {
  days: number;
  filters: Omit<ActivityFilters, 'platforms'>;
}) {
  const { data, isLoading, error } = useTrendingPlatforms(days, 8, filters);

  if (isLoading) return <div className="space-y-1">{[...Array(8)].map((_, i) => <SkeletonRow key={i} />)}</div>;
  if (error || !data?.platforms?.length) return <EmptyLabel label="NO_TRENDING_DATA" />;

  const max = Math.max(...data.platforms.map((p) => p.count));
  return (
    <div className="space-y-1">
      {data.platforms.map((p, i) => (
        <TrendingRow
          key={p.platform}
          rank={i + 1}
          primary={p.platform.replace(/_/g, ' ').toUpperCase()}
          count={p.count}
          maxCount={max}
          sources={p.sources}
          href={`/detections?platforms=${p.platform}`}
          accent="cyan"
        />
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Filter bar — narrows Notable New Rules + trending (platforms-trending
// ignores its own `platforms` filter)
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
    const curr = filters.sources || [];
    const next = curr.includes(src) ? curr.filter((s) => s !== src) : [...curr, src];
    setFilters({ ...filters, sources: next.length ? next : undefined });
  };

  const setPlatform = (plat: string | null) => {
    setFilters({ ...filters, platforms: plat ? [plat] : undefined });
  };

  const activeCount =
    (filters.sources?.length || 0) + (filters.platforms?.length || 0) + (filters.event_types?.length || 0);

  return (
    <div className="bg-void-850 border border-void-700 px-3 py-2 flex items-center gap-3 flex-wrap">
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
                  ? `${cfg?.bg || 'bg-matrix-500/20'} ${cfg?.text || 'text-matrix-400'} ${cfg?.border || 'border-matrix-500/30'}`
                  : 'bg-void-800 text-gray-400 border-void-600 hover:text-white'
              }`}
              title={cfg?.name || src}
            >
              {(cfg?.name || src).replace(' Protections', ' Prot').replace(' Hunting', ' Hunt')}
            </button>
          );
        })}
      </div>

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

const periodOptions = [
  { value: 30, label: '30d' },
  { value: 90, label: '90d' },
  { value: 180, label: '6mo' },
  { value: 365, label: '1y' },
];

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function IndustryIntel() {
  const [trendingPeriod, setTrendingPeriod] = useState(90);
  const [filters, setFilters] = useState<ActivityFilters>({});

  const platformsTrendingFilters = useMemo(() => {
    const { platforms: _p, ...rest } = filters;
    return rest;
  }, [filters]);

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">
          Detection Intelligence
        </h1>
        <p className="text-xs text-gray-500 mt-0.5 font-mono">
          WHAT_THE_INDUSTRY_IS_WATCHING // NAMED_THREATS // CVE_COVERAGE // UPSTREAM_ACTIVITY
        </p>
      </div>

      {/* Pulse banner */}
      <PulseBanner days={trendingPeriod} />

      {/* Threat Pulse — the main "what is industry watching" signal */}
      <Section
        title="Threat Pulse"
        subtitle="extracted from vendor story tags + CVE mentions across the full catalog"
      >
        <ThreatPulseSection />
      </Section>

      {/* Upstream releases + Notable new rules — two columns */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Section
          title="Upstream Releases"
          subtitle="sigma · splunk · elastic"
        >
          <UpstreamReleases />
        </Section>

        <Section
          title="Notable New Rules"
          subtitle="latest across all sources"
        >
          <NotableNewRulesSection filters={filters} />
        </Section>
      </div>

      {/* Bottom strip — trending techniques + platforms with filter bar */}
      <Section
        title="Catalog Activity"
        subtitle={`trending over last ${trendingPeriod}d — filter to narrow`}
        action={
          <div className="flex items-center gap-1">
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
        }
      >
        <div className="space-y-3">
          <ActivityFilterBar filters={filters} setFilters={setFilters} />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="bg-void-850 border border-void-700 p-3" style={clipSm}>
              <div className="flex items-center gap-2 mb-2">
                <span className="w-1.5 h-1.5 rounded-full bg-matrix-500" />
                <h3 className="font-display font-semibold text-[11px] uppercase tracking-wider text-matrix-400">
                  Trending MITRE Techniques
                </h3>
              </div>
              <TrendingTechniquesList days={trendingPeriod} filters={filters} />
            </div>
            <div className="bg-void-850 border border-void-700 p-3" style={clipSm}>
              <div className="flex items-center gap-2 mb-2">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-500" />
                <h3 className="font-display font-semibold text-[11px] uppercase tracking-wider text-cyan-400">
                  Trending Platforms
                </h3>
              </div>
              <TrendingPlatformsList days={trendingPeriod} filters={platformsTrendingFilters} />
            </div>
          </div>
        </div>
      </Section>
    </div>
  );
}
