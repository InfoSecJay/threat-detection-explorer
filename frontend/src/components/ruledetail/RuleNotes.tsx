/** Free-text rule documentation: tags, references, false positives. */

import type { Detection } from '../../types';

export function RuleNotes({ detection }: { detection: Detection }) {
  return (
    <>
    {/* Tags */}
    <div className="grid grid-cols-1 gap-6">
      <div>
        <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">Tags</label>
        <div className="flex flex-wrap gap-1.5">
          {detection.tags.length > 0 ? (
            detection.tags.slice(0, 10).map((tag) => (
              <span key={tag} className="px-2 py-0.5 bg-void-700 text-gray-400 rounded text-sm">
                {tag}
              </span>
            ))
          ) : (
            <span className="text-gray-500 text-sm italic">None</span>
          )}
          {detection.tags.length > 10 && (
            <span className="px-2 py-0.5 text-gray-500 text-sm">+{detection.tags.length - 10} more</span>
          )}
        </div>
      </div>
    </div>

    {/* References */}
    {detection.references && detection.references.length > 0 && (
      <div>
        <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">References</label>
        <ul className="space-y-1">
          {detection.references.map((ref, index) => (
            <li key={index}>
              {ref.startsWith('http') ? (
                <a
                  href={ref}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm text-cyan-400 hover:text-cyan-300 hover:underline break-all"
                >
                  {ref}
                </a>
              ) : (
                <span className="text-sm text-gray-400">{ref}</span>
              )}
            </li>
          ))}
        </ul>
      </div>
    )}

    {/* False Positives */}
    {detection.false_positives && detection.false_positives.length > 0 && (
      <div>
        <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">False Positives</label>
        <ul className="space-y-1">
          {detection.false_positives.map((fp, index) => (
            <li key={index} className="text-sm text-gray-400">• {fp}</li>
          ))}
        </ul>
      </div>
    )}
    </>
  );
}
