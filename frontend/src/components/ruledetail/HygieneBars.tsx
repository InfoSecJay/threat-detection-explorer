/** Hygiene score (issue #10): five-dimension rubric bars. Measures
 * rule hygiene (metadata, mapping, docs, testability), not detection
 * accuracy. */

import type { Detection } from '../../types';

export function HygieneBars({ details }: { details: NonNullable<Detection['quality_details']> }) {
  return (
        <div>
      <div className="flex items-center gap-2 mb-2">
        <label className="text-xs font-medium text-gray-500 uppercase tracking-wide">
          Hygiene Score
        </label>
        <span
          className="text-sm font-mono text-white tabular-nums"
          title="Deterministic 0-100 rubric over metadata, ATT&CK mapping, specificity, documentation, testability"
        >
          {details.total}/100
        </span>
        <span className="text-[10px] font-mono text-gray-600">
          measures rule hygiene, not detection accuracy
        </span>
      </div>
      <div className="space-y-1.5">
        {Object.entries(details.dimensions).map(([name, dim]) => (
          <div key={name} className="flex items-center gap-2">
            <span className="text-[11px] font-mono text-gray-500 uppercase w-32 shrink-0">
              {name}
            </span>
            <div className="flex-1 h-1.5 bg-void-800 rounded overflow-hidden">
              <div
                className={`h-full ${
                  dim.score >= dim.of * 0.75
                    ? 'bg-green-500'
                    : dim.score >= dim.of * 0.4
                      ? 'bg-amber-500'
                      : 'bg-red-500'
                }`}
                style={{ width: `${(dim.score / dim.of) * 100}%` }}
              />
            </div>
            <span className="text-[11px] font-mono text-gray-400 tabular-nums w-10 text-right shrink-0">
              {dim.score}/{dim.of}
            </span>
            {dim.issues.length > 0 && (
              <span
                className="text-[10px] font-mono text-gray-600 shrink-0 cursor-help"
                title={dim.issues.join('\n')}
              >
                {dim.issues.length} issue{dim.issues.length > 1 ? 's' : ''}
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
