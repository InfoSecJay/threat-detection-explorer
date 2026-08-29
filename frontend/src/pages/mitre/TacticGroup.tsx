/** Left pane of the ATT&CK browser: one collapsible tactic with its
 * parent techniques and their sub-techniques, filtered by coverage
 * state and search text. */

import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { clipSm as clipCornerSm } from '../../constants/style';
import type { TechniqueCoverage, TacticCoverage } from '../../services/api';
import type { CoverageFilter } from './types';

export function TacticGroup({
  tactic,
  selectedId,
  expanded,
  onToggle,
  filterCoverage,
  search,
}: {
  tactic: TacticCoverage;
  selectedId: string | undefined;
  expanded: boolean;
  onToggle: () => void;
  filterCoverage: CoverageFilter;
  search: string;
}) {
  const navigate = useNavigate();

  // Group subtechniques under their parent technique.
  const grouped = useMemo(() => {
    const parents: TechniqueCoverage[] = [];
    const byParent: Record<string, TechniqueCoverage[]> = {};
    for (const t of tactic.techniques) {
      if (t.is_subtechnique) {
        const parentId = t.id.split('.')[0];
        (byParent[parentId] ||= []).push(t);
      } else {
        parents.push(t);
      }
    }
    return { parents, byParent };
  }, [tactic.techniques]);

  const matchesFilter = (t: TechniqueCoverage) => {
    if (filterCoverage === 'covered' && t.total_detections === 0) return false;
    if (filterCoverage === 'gaps' && t.total_detections > 0) return false;
    if (search) {
      const q = search.toLowerCase();
      if (!t.id.toLowerCase().includes(q) && !t.name.toLowerCase().includes(q)) return false;
    }
    return true;
  };

  // Filter parents, but keep them if any child subtechnique matches.
  const visibleParents = grouped.parents.filter((p) => {
    if (matchesFilter(p)) return true;
    const subs = grouped.byParent[p.id] || [];
    return subs.some(matchesFilter);
  });

  const coveredCount = tactic.techniques.filter((t) => t.total_detections > 0 && !t.is_subtechnique).length;
  const parentCount = grouped.parents.length;
  const coveragePercent = parentCount ? Math.round((coveredCount / parentCount) * 100) : 0;

  if (visibleParents.length === 0) return null;

  return (
    <div className="border border-void-700 bg-void-850" style={clipCornerSm}>
      <button
        onClick={onToggle}
        className="w-full px-3 py-2.5 flex items-center justify-between hover:bg-void-800/50 transition-colors"
      >
        <div className="flex items-center gap-2 min-w-0">
          <svg
            className={`w-3 h-3 text-gray-500 transition-transform flex-shrink-0 ${expanded ? 'rotate-90' : ''}`}
            fill="none" stroke="currentColor" viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
          </svg>
          <span className="font-display text-sm text-white uppercase tracking-wide truncate">
            {tactic.name}
          </span>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <span className="text-[10px] font-mono text-gray-500">
            {coveredCount}/{parentCount}
          </span>
          <span className="text-[10px] font-mono text-matrix-500 w-8 text-right">{coveragePercent}%</span>
        </div>
      </button>

      {expanded && (
        <div className="border-t border-void-700 divide-y divide-void-700/50">
          {visibleParents.map((p) => {
            const subs = (grouped.byParent[p.id] || []).filter(matchesFilter);
            const isSelected = selectedId === p.id;
            return (
              <div key={p.id}>
                <button
                  onClick={() => navigate(`/mitre/${p.id}`)}
                  className={`w-full text-left px-3 py-1.5 flex items-center gap-2 hover:bg-void-800/70 transition-colors ${
                    isSelected ? 'bg-matrix-500/10 border-l-2 border-l-matrix-500' : ''
                  }`}
                >
                  <span className={`font-mono text-[11px] ${p.total_detections > 0 ? 'text-matrix-500' : 'text-gray-600'}`}>
                    {p.id}
                  </span>
                  <span className={`text-xs truncate flex-1 ${p.total_detections > 0 ? 'text-gray-300' : 'text-gray-600'}`}>
                    {p.name}
                  </span>
                  <span className={`text-[10px] font-mono ${p.total_detections > 0 ? 'text-white' : 'text-gray-700'}`}>
                    {p.total_detections || '—'}
                  </span>
                </button>
                {subs.map((s) => {
                  const subSelected = selectedId === s.id;
                  return (
                    <button
                      key={s.id}
                      onClick={() => navigate(`/mitre/${s.id}`)}
                      className={`w-full text-left pl-8 pr-3 py-1 flex items-center gap-2 hover:bg-void-800/70 transition-colors ${
                        subSelected ? 'bg-matrix-500/10 border-l-2 border-l-matrix-500' : ''
                      }`}
                    >
                      <span className={`font-mono text-[10px] ${s.total_detections > 0 ? 'text-matrix-500/80' : 'text-gray-700'}`}>
                        {s.id}
                      </span>
                      <span className={`text-xs truncate flex-1 ${s.total_detections > 0 ? 'text-gray-400' : 'text-gray-700'}`}>
                        {s.name}
                      </span>
                      <span className={`text-[10px] font-mono ${s.total_detections > 0 ? 'text-gray-300' : 'text-gray-700'}`}>
                        {s.total_detections || '—'}
                      </span>
                    </button>
                  );
                })}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
