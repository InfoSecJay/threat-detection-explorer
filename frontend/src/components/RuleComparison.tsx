import { useState, useMemo, useEffect } from 'react';
import type { Detection, CompareResponse } from '../types';
import {
  ALL_SOURCES,
  sourceColors,
  sourceLabels,
  sourceTailwind,
  severityOrder,
  severityTailwind,
} from '../constants/sources';
import { RulePreviewModal } from './RulePreviewModal';

interface RuleComparisonProps {
  data: CompareResponse;
}

// ─── Enhanced Detection Card ────────────────────────────────────────────────

function EnhancedDetectionCard({
  detection,
  sourceColor,
  onClick,
}: {
  detection: Detection;
  sourceColor: string;
  onClick: () => void;
}) {
  return (
    <div
      onClick={onClick}
      className="block p-3 bg-void-900 border border-void-700 hover:border-matrix-500/30 transition-all group cursor-pointer"
      style={{
        borderLeftWidth: '3px',
        borderLeftColor: sourceColor,
        clipPath:
          'polygon(0 0, calc(100% - 6px) 0, 100% 6px, 100% 100%, 0 100%)',
      }}
    >
      {/* Title */}
      <h4 className="font-sans font-semibold text-sm text-gray-200 leading-tight line-clamp-2 group-hover:text-matrix-500 transition-colors">
        {detection.title}
      </h4>

      {/* Description */}
      <p className="text-xs text-gray-500 mt-1.5 line-clamp-2">
        {detection.description || 'No description'}
      </p>

      {/* Metadata row: severity + platform + language */}
      <div className="flex items-center gap-1.5 mt-2 flex-wrap">
        <span
          className={`px-1.5 py-0.5 text-[10px] font-mono font-medium border ${
            severityTailwind[detection.severity] || severityTailwind.unknown
          }`}
        >
          {detection.severity.toUpperCase()}
        </span>
        {detection.platforms && detection.platforms.length > 0 && (
          <span className="px-1.5 py-0.5 bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 text-[10px] font-mono">
            {(detection.platforms.filter(p => p !== 'unknown')[0] || detection.platforms[0]).toUpperCase()}
          </span>
        )}
        {detection.language && detection.language !== 'unknown' && (
          <span className="px-1.5 py-0.5 bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 text-[10px] font-mono uppercase">
            {detection.language}
          </span>
        )}
        {detection.status && detection.status !== 'unknown' && (
          <span className="text-[10px] font-mono text-gray-600">
            {detection.status}
          </span>
        )}
      </div>

      {/* MITRE techniques */}
      {detection.mitre_techniques?.length > 0 && (
        <div className="flex items-center gap-1 mt-1.5 flex-wrap">
          {detection.mitre_techniques.slice(0, 3).map((tech) => (
            <span
              key={tech}
              className="px-1.5 py-0.5 bg-matrix-500/10 text-matrix-500 text-[10px] font-mono border border-matrix-500/20"
            >
              {tech}
            </span>
          ))}
          {detection.mitre_techniques.length > 3 && (
            <span className="text-[10px] text-gray-600 font-mono">
              +{detection.mitre_techniques.length - 3}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Filter Pill Components ─────────────────────────────────────────────────

function TogglePill({
  label,
  isActive,
  color,
  count,
  onClick,
}: {
  label: string;
  isActive: boolean;
  color?: string;
  count?: number;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-mono border transition-all ${
        isActive
          ? 'text-white'
          : 'text-gray-600 border-void-700 bg-void-900 opacity-40 hover:opacity-70'
      }`}
      style={
        isActive && color
          ? {
              backgroundColor: `${color}18`,
              borderColor: `${color}50`,
              color: color,
            }
          : undefined
      }
    >
      {color && (
        <span
          className="w-1.5 h-1.5 rounded-full flex-shrink-0"
          style={{ backgroundColor: color }}
        />
      )}
      {label}
      {count !== undefined && (
        <span className={isActive ? 'opacity-60' : 'opacity-40'}>{count}</span>
      )}
    </button>
  );
}

// ─── Main Component ─────────────────────────────────────────────────────────

export function RuleComparison({ data }: RuleComparisonProps) {
  // ── Modal state ────────────────────────────────────────────────────────────
  const [selectedDetection, setSelectedDetection] = useState<Detection | null>(null);

  // ── Filter state ──────────────────────────────────────────────────────────
  const [activeSources, setActiveSources] = useState<Set<string>>(new Set());
  const [activePlatforms, setActivePlatforms] = useState<Set<string>>(
    new Set()
  );
  const [activeCategories, setActiveCategories] = useState<Set<string>>(
    new Set()
  );
  const [activeStatuses, setActiveStatuses] = useState<Set<string>>(
    new Set()
  );
  const [activeTactics, setActiveTactics] = useState<Set<string>>(new Set());
  const [activeComplexity, setActiveComplexity] = useState<Set<string>>(
    new Set()
  );
  const [sortBy, setSortBy] = useState('severity:desc');
  const [showFilters, setShowFilters] = useState(true);

  // Initialize activeSources to all sources with results
  useEffect(() => {
    const sourcesWithResults = Object.entries(data.results)
      .filter(([_, detections]) => detections.length > 0)
      .map(([source]) => source);
    setActiveSources(new Set(sourcesWithResults));
    // Reset other filters on new query
    setActivePlatforms(new Set());
    setActiveCategories(new Set());
    setActiveStatuses(new Set());
    setActiveTactics(new Set());
    setActiveComplexity(new Set());
  }, [data]);

  // ── Derive available filter values from data ──────────────────────────────
  const allDetections = useMemo(
    () => Object.values(data.results).flat(),
    [data]
  );

  const availableFilters = useMemo(() => {
    const platforms = new Map<string, number>();
    const categories = new Map<string, number>();
    const statuses = new Map<string, number>();
    const tactics = new Map<string, number>();
    const complexity = new Map<string, number>();

    allDetections.forEach((d) => {
      d.platforms?.filter(p => p !== 'unknown').forEach((p) => platforms.set(p, (platforms.get(p) || 0) + 1));
      d.event_types?.filter(e => e !== 'unknown').forEach((e) => categories.set(e, (categories.get(e) || 0) + 1));
      if (d.status) statuses.set(d.status, (statuses.get(d.status) || 0) + 1);
      if (d.query_complexity && d.query_complexity !== 'unknown')
        complexity.set(d.query_complexity, (complexity.get(d.query_complexity) || 0) + 1);
      d.mitre_tactics?.forEach((t) =>
        tactics.set(t, (tactics.get(t) || 0) + 1)
      );
    });

    const sortByCount = (m: Map<string, number>) =>
      [...m.entries()].sort((a, b) => b[1] - a[1]);

    return {
      platforms: sortByCount(platforms),
      categories: sortByCount(categories),
      statuses: sortByCount(statuses),
      tactics: sortByCount(tactics).slice(0, 12),
      complexity: sortByCount(complexity),
    };
  }, [allDetections]);

  // ── Toggle helpers ────────────────────────────────────────────────────────
  const toggle = (
    set: Set<string>,
    setter: React.Dispatch<React.SetStateAction<Set<string>>>,
    value: string
  ) => {
    const next = new Set(set);
    if (next.has(value)) next.delete(value);
    else next.add(value);
    setter(next);
  };

  const toggleSource = (source: string) =>
    toggle(activeSources, setActiveSources, source);

  const hasActiveFilters =
    activePlatforms.size > 0 ||
    activeCategories.size > 0 ||
    activeStatuses.size > 0 ||
    activeTactics.size > 0 ||
    activeComplexity.size > 0;

  const clearFilters = () => {
    setActivePlatforms(new Set());
    setActiveCategories(new Set());
    setActiveStatuses(new Set());
    setActiveTactics(new Set());
    setActiveComplexity(new Set());
  };

  // ── Filtering + sorting via useMemo ───────────────────────────────────────
  const filteredResults = useMemo(() => {
    const result: Record<string, Detection[]> = {};
    const [sortField, sortDir] = sortBy.split(':');

    for (const [source, detections] of Object.entries(data.results)) {
      if (!activeSources.has(source)) continue;

      let filtered = detections;

      if (activePlatforms.size > 0) {
        filtered = filtered.filter((d) =>
          d.platforms?.some((p) => activePlatforms.has(p))
        );
      }
      if (activeCategories.size > 0) {
        filtered = filtered.filter((d) =>
          d.event_types?.some((e) => activeCategories.has(e))
        );
      }
      if (activeStatuses.size > 0) {
        filtered = filtered.filter((d) => activeStatuses.has(d.status));
      }
      if (activeTactics.size > 0) {
        filtered = filtered.filter((d) =>
          d.mitre_tactics?.some((t) => activeTactics.has(t))
        );
      }
      if (activeComplexity.size > 0) {
        filtered = filtered.filter((d) =>
          activeComplexity.has(d.query_complexity || '')
        );
      }

      // Sort
      filtered = [...filtered].sort((a, b) => {
        if (sortField === 'severity') {
          const diff =
            (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4);
          return sortDir === 'asc' ? diff : -diff;
        }
        if (sortField === 'title') {
          return sortDir === 'asc'
            ? a.title.localeCompare(b.title)
            : b.title.localeCompare(a.title);
        }
        return 0;
      });

      if (filtered.length > 0) {
        result[source] = filtered;
      }
    }

    return result;
  }, [
    data,
    activeSources,
    activePlatforms,
    activeCategories,
    activeStatuses,
    activeTactics,
    activeComplexity,
    sortBy,
  ]);

  // ── Computed values ───────────────────────────────────────────────────────
  const totalCount = Object.values(data.total_by_source).reduce(
    (a, b) => a + b,
    0
  );
  const filteredTotal = Object.values(filteredResults).reduce(
    (a, arr) => a + arr.length,
    0
  );
  // Always show columns for sources that have results in the ORIGINAL data
  // and are toggled on — preserves layout when filters narrow results
  const originalSourcesWithResults = ALL_SOURCES.filter(
    (s) => (data.total_by_source[s] || 0) > 0 && activeSources.has(s)
  );
  const colCount = originalSourcesWithResults.length;

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="space-y-4">
      {/* ── Source Toggle Pills ────────────────────────────────────────────── */}
      <div
        className="bg-void-850 border border-void-700 p-4"
        style={{
          clipPath:
            'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))',
        }}
      >
        {/* Top row: source toggles + sort + result count */}
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[10px] font-mono text-gray-600 mr-1">
              SOURCES:
            </span>
            {ALL_SOURCES.map((source) => {
              const count = data.total_by_source[source] || 0;
              if (count === 0) return null;
              return (
                <TogglePill
                  key={source}
                  label={sourceLabels[source]}
                  isActive={activeSources.has(source)}
                  color={sourceColors[source]}
                  count={count}
                  onClick={() => toggleSource(source)}
                />
              );
            })}
          </div>
          <div className="flex items-center gap-3">
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              className="text-[11px] bg-void-900 border border-void-700 text-gray-300 px-2 py-1 font-mono focus:ring-matrix-500/50 focus:border-matrix-500/50"
            >
              <option value="severity:desc">Severity (High first)</option>
              <option value="severity:asc">Severity (Low first)</option>
              <option value="title:asc">Title (A-Z)</option>
              <option value="title:desc">Title (Z-A)</option>
            </select>
            <span className="text-[11px] font-mono text-gray-500">
              <span className="text-matrix-500">{filteredTotal}</span>
              <span className="text-gray-600"> / {totalCount}</span>
            </span>
            <button
              onClick={() => setShowFilters(!showFilters)}
              className="text-[11px] font-mono text-matrix-500 hover:text-matrix-400 transition-colors"
            >
              {showFilters ? '[ HIDE FILTERS ]' : '[ FILTERS ]'}
            </button>
          </div>
        </div>

        {/* ── Drill-down Filters ──────────────────────────────────────────── */}
        {showFilters && (
          <div className="mt-3 pt-3 border-t border-void-700 space-y-2.5">
            {/* Platform */}
            {availableFilters.platforms.length > 0 && (
              <div className="flex items-start gap-2">
                <span className="text-[10px] font-mono text-gray-600 w-20 pt-1 flex-shrink-0">
                  PLATFORM:
                </span>
                <div className="flex flex-wrap gap-1">
                  {availableFilters.platforms.map(([platform, count]) => (
                    <TogglePill
                      key={platform}
                      label={platform.toUpperCase()}
                      isActive={activePlatforms.has(platform)}
                      count={count}
                      onClick={() =>
                        toggle(activePlatforms, setActivePlatforms, platform)
                      }
                    />
                  ))}
                </div>
              </div>
            )}

            {/* Event Category */}
            {availableFilters.categories.length > 0 && (
              <div className="flex items-start gap-2">
                <span className="text-[10px] font-mono text-gray-600 w-20 pt-1 flex-shrink-0">
                  CATEGORY:
                </span>
                <div className="flex flex-wrap gap-1">
                  {availableFilters.categories.map(([cat, count]) => (
                    <TogglePill
                      key={cat}
                      label={cat.toUpperCase()}
                      isActive={activeCategories.has(cat)}
                      count={count}
                      onClick={() =>
                        toggle(activeCategories, setActiveCategories, cat)
                      }
                    />
                  ))}
                </div>
              </div>
            )}

            {/* Status */}
            {availableFilters.statuses.length > 1 && (
              <div className="flex items-start gap-2">
                <span className="text-[10px] font-mono text-gray-600 w-20 pt-1 flex-shrink-0">
                  STATUS:
                </span>
                <div className="flex flex-wrap gap-1">
                  {availableFilters.statuses.map(([status, count]) => (
                    <TogglePill
                      key={status}
                      label={status.toUpperCase()}
                      isActive={activeStatuses.has(status)}
                      count={count}
                      onClick={() =>
                        toggle(activeStatuses, setActiveStatuses, status)
                      }
                    />
                  ))}
                </div>
              </div>
            )}

            {/* MITRE Tactics */}
            {availableFilters.tactics.length > 0 && (
              <div className="flex items-start gap-2">
                <span className="text-[10px] font-mono text-gray-600 w-20 pt-1 flex-shrink-0">
                  TACTICS:
                </span>
                <div className="flex flex-wrap gap-1">
                  {availableFilters.tactics.map(([tactic, count]) => (
                    <TogglePill
                      key={tactic}
                      label={tactic}
                      isActive={activeTactics.has(tactic)}
                      count={count}
                      onClick={() =>
                        toggle(activeTactics, setActiveTactics, tactic)
                      }
                    />
                  ))}
                </div>
              </div>
            )}

            {/* Query Complexity */}
            {availableFilters.complexity.length > 0 && (
              <div className="flex items-start gap-2">
                <span className="text-[10px] font-mono text-gray-600 w-20 pt-1 flex-shrink-0">
                  COMPLEXITY:
                </span>
                <div className="flex flex-wrap gap-1">
                  {availableFilters.complexity.map(([complexity, count]) => (
                    <TogglePill
                      key={complexity}
                      label={complexity.toUpperCase()}
                      isActive={activeComplexity.has(complexity)}
                      count={count}
                      onClick={() =>
                        toggle(activeComplexity, setActiveComplexity, complexity)
                      }
                    />
                  ))}
                </div>
              </div>
            )}

            {/* Clear filters */}
            {hasActiveFilters && (
              <div className="flex items-center gap-2 pt-1">
                <button
                  onClick={clearFilters}
                  className="text-[11px] font-mono text-breach-400 hover:text-breach-300 transition-colors"
                >
                  CLEAR FILTERS
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── Summary Cards ─────────────────────────────────────────────────── */}
      {colCount > 0 && (
        <div
          className="grid gap-3"
          style={{
            gridTemplateColumns: `repeat(${Math.min(colCount, 8)}, minmax(0, 1fr))`,
          }}
        >
          {originalSourcesWithResults.map((source) => (
            <div
              key={source}
              className={`p-3 border-l-4 ${sourceTailwind[source]}`}
              style={{
                clipPath:
                  'polygon(0 0, calc(100% - 8px) 0, 100% 8px, 100% 100%, 0 100%)',
              }}
            >
              <h3 className="font-display font-semibold text-xs text-gray-300 uppercase tracking-wide">
                {sourceLabels[source]}
              </h3>
              <p className="text-xl font-display font-bold mt-0.5 text-white">
                {filteredResults[source]?.length || 0}
              </p>
              <p className="text-[10px] font-mono text-gray-500">detections</p>
            </div>
          ))}
        </div>
      )}

      {/* ── Empty state ───────────────────────────────────────────────────── */}
      {colCount === 0 && (
        <div className="text-center py-12">
          <p className="text-sm font-mono text-gray-500">
            NO DETECTIONS MATCH CURRENT FILTERS
          </p>
          <button
            onClick={() => {
              const sourcesWithResults = Object.entries(data.results)
                .filter(([_, d]) => d.length > 0)
                .map(([s]) => s);
              setActiveSources(new Set(sourcesWithResults));
              clearFilters();
            }}
            className="mt-3 text-xs font-mono text-matrix-500 hover:text-matrix-400 transition-colors"
          >
            [ RESET ALL FILTERS ]
          </button>
        </div>
      )}

      {/* ── Detection Grid ────────────────────────────────────────────────── */}
      {colCount > 0 && (
        <div
          className="grid gap-4"
          style={{
            gridTemplateColumns: `repeat(${Math.min(colCount, 8)}, minmax(0, 1fr))`,
          }}
        >
          {originalSourcesWithResults.map((source) => (
            <div key={source} className="space-y-2">
              <h3
                className="font-display font-semibold text-sm text-gray-300 border-b pb-2 tracking-wide uppercase"
                style={{ borderColor: `${sourceColors[source]}40` }}
              >
                {sourceLabels[source]}
              </h3>
              {filteredResults[source]?.length ? (
                filteredResults[source].map((detection) => (
                  <EnhancedDetectionCard
                    key={detection.id}
                    detection={detection}
                    sourceColor={sourceColors[source]}
                    onClick={() => setSelectedDetection(detection)}
                  />
                ))
              ) : (
                <p className="text-xs font-mono text-gray-600 py-4 text-center">
                  No matches
                </p>
              )}
            </div>
          ))}
        </div>
      )}

      {/* ── Rule Preview Modal ────────────────────────────────────────────── */}
      <RulePreviewModal
        detection={selectedDetection}
        isOpen={selectedDetection !== null}
        onClose={() => setSelectedDetection(null)}
      />
    </div>
  );
}
