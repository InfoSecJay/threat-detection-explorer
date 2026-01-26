import { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useCoverageMatrix } from '../hooks/useCompare';
import type { TechniqueCoverage, TacticCoverage } from '../services/api';

// Source colors
const sourceColors: Record<string, { bg: string; text: string; border: string }> = {
  sigma: { bg: 'bg-blue-500', text: 'text-blue-400', border: 'border-blue-500' },
  elastic: { bg: 'bg-amber-500', text: 'text-amber-400', border: 'border-amber-500' },
  splunk: { bg: 'bg-green-500', text: 'text-green-400', border: 'border-green-500' },
  sublime: { bg: 'bg-purple-500', text: 'text-purple-400', border: 'border-purple-500' },
  elastic_protections: { bg: 'bg-orange-500', text: 'text-orange-400', border: 'border-orange-500' },
  lolrmm: { bg: 'bg-pink-500', text: 'text-pink-400', border: 'border-pink-500' },
};

const sourceDisplayNames: Record<string, string> = {
  sigma: 'Sigma',
  elastic: 'Elastic',
  splunk: 'Splunk',
  sublime: 'Sublime',
  elastic_protections: 'Elastic Prot.',
  lolrmm: 'LOLRMM',
};

function CoverageSummary({ data }: { data: ReturnType<typeof useCoverageMatrix>['data'] }) {
  if (!data) return null;

  const { summary, sources } = data;

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3 mb-6">
      {/* Overall Coverage */}
      <div
        className="bg-void-850 border border-matrix-500/30 p-4"
        style={{
          clipPath: 'polygon(0 0, calc(100% - 8px) 0, 100% 8px, 100% 100%, 8px 100%, 0 calc(100% - 8px))',
        }}
      >
        <div className="text-xs font-mono text-gray-500 mb-1">OVERALL</div>
        <div className="text-2xl font-display font-bold text-matrix-500">
          {summary.overall_coverage_percent}%
        </div>
        <div className="text-xs text-gray-500">
          {summary.techniques_with_any_coverage}/{summary.total_techniques}
        </div>
      </div>

      {/* Per-Source Coverage */}
      {sources.map((source) => {
        const coverage = summary.source_coverage[source];
        const colors = sourceColors[source] || sourceColors.sigma;
        return (
          <div
            key={source}
            className={`bg-void-850 border ${colors.border}/30 p-4`}
            style={{
              clipPath: 'polygon(0 0, calc(100% - 8px) 0, 100% 8px, 100% 100%, 8px 100%, 0 calc(100% - 8px))',
            }}
          >
            <div className="text-xs font-mono text-gray-500 mb-1 uppercase">
              {sourceDisplayNames[source] || source}
            </div>
            <div className={`text-2xl font-display font-bold ${colors.text}`}>
              {coverage.coverage_percent}%
            </div>
            <div className="text-xs text-gray-500">
              {coverage.covered_techniques} techniques
            </div>
          </div>
        );
      })}
    </div>
  );
}

function TechniqueRow({ technique, sources }: { technique: TechniqueCoverage; sources: string[] }) {
  const hasAnyCoverage = technique.total_detections > 0;

  return (
    <Link
      to={`/compare?technique=${technique.id}`}
      className={`flex items-center gap-2 px-3 py-2 border-b border-void-700/50 hover:bg-void-800/50 transition-colors ${
        hasAnyCoverage ? '' : 'opacity-50'
      }`}
    >
      {/* Technique ID & Name */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className={`font-mono text-xs ${hasAnyCoverage ? 'text-matrix-500' : 'text-gray-600'}`}>
            {technique.id}
          </span>
          <span className={`text-sm truncate ${hasAnyCoverage ? 'text-gray-300' : 'text-gray-600'}`}>
            {technique.name}
          </span>
        </div>
      </div>

      {/* Coverage Indicators */}
      <div className="flex items-center gap-1.5">
        {sources.map((source) => {
          const count = technique.coverage[source] || 0;
          const colors = sourceColors[source] || sourceColors.sigma;
          return (
            <div
              key={source}
              className={`w-6 h-6 flex items-center justify-center text-xs font-mono rounded-sm ${
                count > 0
                  ? `${colors.bg}/20 ${colors.text} border ${colors.border}/30`
                  : 'bg-void-900 text-gray-700 border border-void-700'
              }`}
              title={`${sourceDisplayNames[source] || source}: ${count} detection${count !== 1 ? 's' : ''}`}
            >
              {count > 0 ? (count > 99 ? '99+' : count) : '—'}
            </div>
          );
        })}
      </div>

      {/* Total */}
      <div className="w-12 text-right">
        <span className={`text-sm font-mono ${hasAnyCoverage ? 'text-white' : 'text-gray-600'}`}>
          {technique.total_detections}
        </span>
      </div>
    </Link>
  );
}

function TacticSection({ tactic, sources, expanded, onToggle }: {
  tactic: TacticCoverage;
  sources: string[];
  expanded: boolean;
  onToggle: () => void;
}) {
  const coveredCount = tactic.techniques.filter((t) => t.total_detections > 0).length;
  const coveragePercent = Math.round((coveredCount / tactic.technique_count) * 100);

  return (
    <div
      className="bg-void-850 border border-void-700 mb-4"
      style={{
        clipPath: 'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))',
      }}
    >
      {/* Tactic Header */}
      <button
        onClick={onToggle}
        className="w-full px-4 py-3 flex items-center justify-between hover:bg-void-800/50 transition-colors"
      >
        <div className="flex items-center gap-3">
          <span className="text-xs font-mono text-gray-500">{tactic.id}</span>
          <h3 className="font-display font-semibold text-white uppercase tracking-wide">
            {tactic.name}
          </h3>
          <span className="text-xs text-gray-500 font-mono">
            {coveredCount}/{tactic.technique_count} techniques
          </span>
        </div>
        <div className="flex items-center gap-4">
          {/* Coverage Bar */}
          <div className="w-24 h-2 bg-void-900 rounded-full overflow-hidden">
            <div
              className="h-full bg-matrix-500 transition-all"
              style={{ width: `${coveragePercent}%` }}
            />
          </div>
          <span className="text-sm font-mono text-matrix-500 w-12 text-right">
            {coveragePercent}%
          </span>
          {/* Expand Icon */}
          <svg
            className={`w-4 h-4 text-gray-500 transition-transform ${expanded ? 'rotate-180' : ''}`}
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </button>

      {/* Techniques List */}
      {expanded && (
        <div className="border-t border-void-700">
          {/* Header Row */}
          <div className="flex items-center gap-2 px-3 py-2 bg-void-900/50 text-xs font-mono text-gray-500">
            <div className="flex-1">TECHNIQUE</div>
            <div className="flex items-center gap-1.5">
              {sources.map((source) => (
                <div
                  key={source}
                  className="w-6 text-center"
                  title={sourceDisplayNames[source] || source}
                >
                  {(sourceDisplayNames[source] || source).substring(0, 2).toUpperCase()}
                </div>
              ))}
            </div>
            <div className="w-12 text-right">TOTAL</div>
          </div>
          {/* Technique Rows */}
          {tactic.techniques.map((technique) => (
            <TechniqueRow key={technique.id} technique={technique} sources={sources} />
          ))}
        </div>
      )}
    </div>
  );
}

export function CoverageMatrix() {
  const [includeSubtechniques, setIncludeSubtechniques] = useState(false);
  const [expandedTactics, setExpandedTactics] = useState<Set<string>>(new Set());
  const [filterCoverage, setFilterCoverage] = useState<'all' | 'covered' | 'gaps'>('all');

  const { data, isLoading, error } = useCoverageMatrix({
    include_subtechniques: includeSubtechniques,
  });

  // Filter tactics based on coverage filter
  const filteredTactics = useMemo(() => {
    if (!data) return [];
    if (filterCoverage === 'all') return data.tactics;

    return data.tactics.map((tactic) => ({
      ...tactic,
      techniques: tactic.techniques.filter((t) =>
        filterCoverage === 'covered' ? t.total_detections > 0 : t.total_detections === 0
      ),
    })).filter((tactic) => tactic.techniques.length > 0);
  }, [data, filterCoverage]);

  const toggleTactic = (tacticId: string) => {
    setExpandedTactics((prev) => {
      const next = new Set(prev);
      if (next.has(tacticId)) {
        next.delete(tacticId);
      } else {
        next.add(tacticId);
      }
      return next;
    });
  };

  const expandAll = () => {
    if (data) {
      setExpandedTactics(new Set(data.tactics.map((t) => t.id)));
    }
  };

  const collapseAll = () => {
    setExpandedTactics(new Set());
  };

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
          {[...Array(7)].map((_, i) => (
            <div key={i} className="h-24 bg-void-800 animate-pulse rounded" />
          ))}
        </div>
        <div className="space-y-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-16 bg-void-800 animate-pulse rounded" />
          ))}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-breach-500/10 border border-breach-500/30 p-6 text-center">
        <p className="text-breach-400 font-mono text-sm">
          ERROR: Failed to load coverage matrix
        </p>
      </div>
    );
  }

  if (!data) return null;

  return (
    <div className="space-y-4">
      {/* Summary Cards */}
      <CoverageSummary data={data} />

      {/* Controls */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-4">
          {/* Filter by coverage */}
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-gray-500">SHOW:</span>
            <div className="flex">
              {(['all', 'covered', 'gaps'] as const).map((filter) => (
                <button
                  key={filter}
                  onClick={() => setFilterCoverage(filter)}
                  className={`px-3 py-1.5 text-xs font-mono uppercase border ${
                    filterCoverage === filter
                      ? 'bg-matrix-500/20 text-matrix-400 border-matrix-500/30'
                      : 'bg-void-800 text-gray-400 border-void-600 hover:text-white'
                  } ${filter === 'all' ? 'rounded-l' : ''} ${filter === 'gaps' ? 'rounded-r' : ''} ${
                    filter !== 'all' ? '-ml-px' : ''
                  }`}
                >
                  {filter === 'all' ? 'All' : filter === 'covered' ? 'Covered' : 'Gaps'}
                </button>
              ))}
            </div>
          </div>

          {/* Include subtechniques toggle */}
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={includeSubtechniques}
              onChange={(e) => setIncludeSubtechniques(e.target.checked)}
              className="w-4 h-4 text-matrix-500 bg-void-900 border-void-600 rounded focus:ring-matrix-500/50"
            />
            <span className="text-sm text-gray-400">Include sub-techniques</span>
          </label>
        </div>

        {/* Expand/Collapse All */}
        <div className="flex items-center gap-2">
          <button
            onClick={expandAll}
            className="text-xs font-mono text-gray-500 hover:text-matrix-500 transition-colors"
          >
            [ EXPAND_ALL ]
          </button>
          <button
            onClick={collapseAll}
            className="text-xs font-mono text-gray-500 hover:text-matrix-500 transition-colors"
          >
            [ COLLAPSE_ALL ]
          </button>
        </div>
      </div>

      {/* Source Legend */}
      <div className="flex items-center gap-4 text-xs font-mono text-gray-500 flex-wrap">
        <span>SOURCES:</span>
        {data.sources.map((source) => {
          const colors = sourceColors[source] || sourceColors.sigma;
          return (
            <div key={source} className="flex items-center gap-1.5">
              <span className={`w-3 h-3 rounded-sm ${colors.bg}`} />
              <span>{sourceDisplayNames[source] || source}</span>
            </div>
          );
        })}
      </div>

      {/* Tactics List */}
      <div className="space-y-0">
        {filteredTactics.map((tactic) => (
          <TacticSection
            key={tactic.id}
            tactic={tactic}
            sources={data.sources}
            expanded={expandedTactics.has(tactic.id)}
            onToggle={() => toggleTactic(tactic.id)}
          />
        ))}
      </div>

      {/* Empty State for Gaps */}
      {filterCoverage === 'gaps' && filteredTactics.length === 0 && (
        <div className="text-center py-12">
          <div className="text-matrix-500 text-4xl mb-4">✓</div>
          <p className="text-gray-400 font-display">
            Full coverage! All techniques have at least one detection.
          </p>
        </div>
      )}
    </div>
  );
}
