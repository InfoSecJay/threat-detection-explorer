/** MITRE ATT&CK browser: tactic/technique tree on the left, coverage
 * summary or technique detail on the right. Panes live in pages/mitre/. */

import { useState, useEffect } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useCoverageMatrix } from '../hooks/useCompare';
import { useMitre } from '../contexts/MitreContext';
import { clipSm as clipCornerSm, clipMd as clipCornerMd } from '../constants/style';
import { TacticGroup } from './mitre/TacticGroup';
import { SummaryPane } from './mitre/SummaryPane';
import { TechniqueDetailPane } from './mitre/TechniqueDetailPane';
import type { CoverageFilter } from './mitre/types';

export function MitreCoverage() {
  const { techniqueId } = useParams<{ techniqueId?: string }>();
  const selectedId = techniqueId?.toUpperCase();

  const [includeSubtechniques, setIncludeSubtechniques] = useState(true);
  const [filterCoverage, setFilterCoverage] = useState<CoverageFilter>('all');
  const [search, setSearch] = useState('');
  const [expandedTactics, setExpandedTactics] = useState<Set<string>>(new Set());

  const { data, isLoading, error } = useCoverageMatrix({
    include_subtechniques: includeSubtechniques,
  });
  // The home page quotes parent-only coverage (~207); this page defaults
  // to parents + subs (~655). Name the denominator so the two agree.
  const techniqueNoun = includeSubtechniques ? 'techniques + sub-techniques' : 'parent techniques';

  // If a technique is selected, auto-expand its parent tactic(s).
  const { techniques } = useMitre();
  useEffect(() => {
    if (!selectedId || !techniques[selectedId]) return;
    const tech = techniques[selectedId];
    setExpandedTactics((prev) => {
      const next = new Set(prev);
      for (const tId of tech.tactics || []) next.add(tId);
      return next;
    });
  }, [selectedId, techniques]);

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
  const expandAll = () => data && setExpandedTactics(new Set(data.tactics.map((t) => t.id)));
  const collapseAll = () => setExpandedTactics(new Set());

  return (
    <div className="space-y-4">
      {/* Page Header */}
      <div className="flex items-end justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">
            MITRE ATT&amp;CK Browser
          </h1>
          <p className="text-xs text-gray-500 mt-1 font-mono">
            BROWSE_BY_TECHNIQUE // CROSS_VENDOR_COVERAGE // DRILL_TO_RULES
            <Link to="/mitre/heatmap" className="ml-3 text-matrix-500 hover:text-matrix-400 uppercase tracking-wider">[ coverage by data source ]</Link>
          </p>
        </div>
        {data && (
          <div className="flex items-center gap-3 text-xs font-mono text-gray-500">
            <span>
              <span className="text-matrix-500 font-bold">{data.summary.overall_coverage_percent}%</span>
              {' '}coverage
            </span>
            <span className="text-gray-700">·</span>
            <span>
              <span className="text-white font-bold">{data.summary.techniques_with_any_coverage}</span>
              <span className="text-gray-600"> / {data.summary.total_techniques} {techniqueNoun}</span>
            </span>
            <span className="text-gray-700">·</span>
            <span>{data.sources.length} sources</span>
          </div>
        )}
      </div>

      {error && (
        <div className="bg-breach-500/10 border border-breach-500/30 p-4" style={clipCornerMd}>
          <p className="text-breach-400 font-mono text-sm">
            ERROR: Failed to load coverage matrix. The backend may still be redeploying.
          </p>
        </div>
      )}

      {/* Split layout */}
      <div className="grid lg:grid-cols-[360px_1fr] gap-4">
        {/* Left pane */}
        <aside className="space-y-3 lg:sticky lg:top-[72px] lg:self-start lg:max-h-[calc(100vh-96px)] lg:overflow-y-auto lg:pr-1">
          {/* Controls */}
          <div className="bg-void-850 border border-void-700 p-3 space-y-2" style={clipCornerSm}>
            <div className="relative">
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Filter T-ID or name…"
                className="w-full bg-void-900 border border-void-600 text-sm text-white placeholder-gray-600 px-3 py-1.5 focus:outline-none focus:border-matrix-500/50 font-mono"
              />
            </div>

            <div className="flex items-center gap-1">
              {(['all', 'covered', 'gaps'] as const).map((f, i, arr) => (
                <button
                  key={f}
                  onClick={() => setFilterCoverage(f)}
                  className={`flex-1 px-2 py-1 text-[10px] font-mono uppercase border ${
                    filterCoverage === f
                      ? 'bg-matrix-500/20 text-matrix-400 border-matrix-500/30'
                      : 'bg-void-800 text-gray-400 border-void-600 hover:text-white'
                  } ${i > 0 ? '-ml-px' : ''} ${i === 0 ? 'rounded-l-sm' : ''} ${i === arr.length - 1 ? 'rounded-r-sm' : ''}`}
                >
                  {f}
                </button>
              ))}
            </div>

            <label className="flex items-center gap-2 cursor-pointer text-xs text-gray-400">
              <input
                type="checkbox"
                checked={includeSubtechniques}
                onChange={(e) => setIncludeSubtechniques(e.target.checked)}
                className="w-3.5 h-3.5 text-matrix-500 bg-void-900 border-void-600 rounded focus:ring-matrix-500/50"
              />
              <span>Show sub-techniques</span>
            </label>

            <div className="flex items-center gap-2 pt-1 border-t border-void-700">
              <button
                onClick={expandAll}
                className="text-[10px] font-mono text-gray-500 hover:text-matrix-500 transition-colors"
              >
                [ EXPAND ]
              </button>
              <button
                onClick={collapseAll}
                className="text-[10px] font-mono text-gray-500 hover:text-matrix-500 transition-colors"
              >
                [ COLLAPSE ]
              </button>
            </div>
          </div>

          {/* Tactic tree */}
          {isLoading ? (
            <div className="space-y-2">
              {[...Array(8)].map((_, i) => (
                <div key={i} className="h-10 bg-void-800 animate-pulse rounded" />
              ))}
            </div>
          ) : (
            <div className="space-y-2">
              {data?.tactics.map((tactic) => (
                <TacticGroup
                  key={tactic.id}
                  tactic={tactic}
                  selectedId={selectedId}
                  expanded={expandedTactics.has(tactic.id)}
                  onToggle={() => toggleTactic(tactic.id)}
                  filterCoverage={filterCoverage}
                  search={search}
                />
              ))}
            </div>
          )}
        </aside>

        {/* Right pane */}
        <section className="min-w-0">
          {isLoading ? (
            <div className="space-y-3">
              <div className="h-24 bg-void-800 animate-pulse rounded" />
              <div className="h-48 bg-void-800 animate-pulse rounded" />
              <div className="h-32 bg-void-800 animate-pulse rounded" />
            </div>
          ) : !data ? null : selectedId ? (
            <TechniqueDetailPane techniqueId={selectedId} coverageData={data} />
          ) : (
            <SummaryPane data={data} techniqueNoun={techniqueNoun} />
          )}
        </section>
      </div>
    </div>
  );
}
