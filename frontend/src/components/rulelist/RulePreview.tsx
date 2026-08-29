/** Inline row preview: query logic, references and FP notes without
 * leaving the result list (keeps scroll position intact). */

import { Link } from 'react-router-dom';
import type { Detection } from '../../types';

export function RulePreview({ detection, lang, colSpan }: { detection: Detection; lang: string | null; colSpan: number }) {
  return (
    <tr className="bg-void-900/60">
      <td colSpan={colSpan} className="px-6 py-4">
        <div className="space-y-4">
          {/* Query logic */}
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <span className="text-[10px] font-display font-semibold text-gray-500 uppercase tracking-wider">
                Detection Logic
              </span>
              {lang && (
                <span className="px-1.5 py-0.5 bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 text-[10px] font-mono">
                  {lang}
                </span>
              )}
            </div>
            <pre className="p-3 bg-void-950 border border-void-700 text-xs font-mono text-gray-300 whitespace-pre-wrap break-words max-h-72 overflow-y-auto">
              {detection.detection_logic || 'No query logic available'}
            </pre>
          </div>

          {/* References */}
          {detection.references && detection.references.length > 0 && (
            <div>
              <div className="text-[10px] font-display font-semibold text-gray-500 uppercase tracking-wider mb-1.5">
                References
              </div>
              <ul className="space-y-1">
                {detection.references.map((ref) => (
                  <li key={ref} className="text-xs font-mono truncate">
                    <a
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-cyan-400 hover:text-cyan-300 transition-colors"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {ref}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* False positives */}
          {detection.false_positives && detection.false_positives.length > 0 && (
            <div>
              <div className="text-[10px] font-display font-semibold text-gray-500 uppercase tracking-wider mb-1.5">
                False Positives
              </div>
              <ul className="space-y-1">
                {detection.false_positives.map((fp, i) => (
                  <li key={i} className="text-xs text-gray-400 flex gap-2">
                    <span className="text-yellow-500/70 shrink-0">!</span>
                    <span>{fp}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <Link
            to={`/detections/${detection.id}`}
            className="inline-block text-xs font-mono text-matrix-500 hover:text-matrix-400 transition-colors"
          >
            VIEW FULL RULE -&gt;
          </Link>
        </div>
      </td>
    </tr>
  );
}
