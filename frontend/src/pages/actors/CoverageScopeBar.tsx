/** "My stack" selector (#143 / DX-01): pick the repos coverage is
 * scored against, and whether the excluded modalities count. Shared by
 * the /actors table and the actor page so both compute the same
 * numbers; the state lives in the URL (see useCoverageScope). */

import { ALL_SOURCES, sourceColors, sourceLabelsShort } from '../../constants/sources';
import { clipSm } from '../../constants/style';
import { describeScope, type CoverageScopeState } from '../../hooks/useCoverageScope';

export function CoverageScopeBar({
  scope, setScope,
}: {
  scope: CoverageScopeState;
  setScope: (next: CoverageScopeState) => void;
}) {
  const selected = scope.sources ?? [...ALL_SOURCES];
  const allSelected = scope.sources === null;

  const toggle = (src: string) => {
    const next = selected.includes(src) ? selected.filter((s) => s !== src) : [...selected, src];
    // Deselecting the last source would score against nothing; treat
    // it as "back to every source" rather than an empty stack.
    setScope({ sources: next.length === 0 ? null : next, coverage: scope.coverage });
  };

  return (
    <div className="bg-void-900/60 border border-void-700 px-4 py-3" style={clipSm} data-testid="scope-bar">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-[10px] font-mono text-dim-400 uppercase tracking-wider mr-1" title="Score coverage, gaps and Named counts against only the repos you run">
          My stack:
        </span>
        <button
          type="button"
          onClick={() => setScope({ sources: null, coverage: scope.coverage })}
          aria-pressed={allSelected}
          className={`min-h-[24px] px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider border transition-colors ${
            allSelected ? 'bg-matrix-500/20 text-matrix-400 border-matrix-500/40' : 'bg-void-900 text-dim-400 border-void-700 hover:text-white'
          }`}
          data-testid="scope-all"
        >
          all {ALL_SOURCES.length}
        </button>
        {ALL_SOURCES.map((src) => {
          const on = selected.includes(src);
          return (
            <button
              key={src}
              type="button"
              onClick={() => toggle(src)}
              aria-pressed={on}
              className={`inline-flex items-center gap-1.5 min-h-[24px] px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider border transition-colors ${
                on && !allSelected
                  ? 'bg-void-800 text-white border-matrix-500/40'
                  : on
                    ? 'bg-void-900 text-gray-300 border-void-700 hover:border-matrix-500/40'
                    : 'bg-void-900/40 text-gray-600 border-void-800 hover:text-gray-300 line-through decoration-gray-700'
              }`}
              title={on ? `${src}: counted -- click to drop it from your stack` : `${src}: not in your stack -- click to add it back`}
              data-testid={`scope-src-${src}`}
            >
              <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: sourceColors[src], opacity: on ? 1 : 0.35 }} />
              {sourceLabelsShort[src] ?? src}
            </button>
          );
        })}
      </div>
      <div className="flex items-center gap-4 flex-wrap mt-2">
        <label className="inline-flex items-center gap-2 min-h-[24px] text-[11px] font-mono text-gray-300 cursor-pointer">
          <input
            type="checkbox"
            checked={scope.coverage === 'all'}
            onChange={(e) => setScope({ sources: scope.sources, coverage: e.target.checked ? 'all' : 'strict' })}
            className="w-3.5 h-3.5 rounded-sm bg-void-900 border-void-600 text-matrix-500 focus:ring-matrix-500/50 focus:ring-offset-void-900"
            data-testid="scope-coverage-toggle"
          />
          count hunting, building-block, passthrough and indicator rules as coverage
        </label>
        <span className="text-[11px] font-mono text-dim-400" data-testid="scope-summary">
          scored against {describeScope(scope)}
        </span>
      </div>
    </div>
  );
}
