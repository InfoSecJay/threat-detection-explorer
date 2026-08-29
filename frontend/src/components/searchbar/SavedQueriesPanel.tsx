/** Saved + recent queries panel (#14), opened from the bookmark button. */

import type { RefObject } from 'react';
import { clipSm } from '../../constants/style';

interface SavedQuery { query: string; name: string }
interface RecentQuery { query: string }

export function SavedQueriesPanel({
  panelRef, saved, recent, onRun, onStar, onUnstar, onRename, onClearRecent,
}: {
  panelRef: RefObject<HTMLDivElement>;
  saved: SavedQuery[];
  recent: RecentQuery[];
  onRun: (query: string) => void;
  onStar: (query: string) => void;
  onUnstar: (query: string) => void;
  onRename: (query: string, name: string) => void;
  onClearRecent: () => void;
}) {
  return (
    <div
      ref={panelRef}
      className="absolute z-40 top-full right-0 mt-1 w-full sm:w-96 bg-void-900 border border-void-700 p-2 space-y-2"
      style={clipSm}
    >
      <div>
        <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider mb-1">
          Saved
        </div>
        {saved.length === 0 && (
          <div className="text-[11px] font-mono text-gray-600 px-1 py-0.5">
            star a recent query to keep it
          </div>
        )}
        {saved.map((s) => (
          <div
            key={s.query}
            className="flex items-center gap-1.5 group px-1 py-0.5 hover:bg-void-800"
          >
            <button
              onClick={() => onRun(s.query)}
              className="flex-1 text-left min-w-0"
              title={s.query}
            >
              <span className="block text-xs font-mono text-matrix-400 truncate">
                {s.name}
              </span>
              {s.name !== s.query && (
                <span className="block text-[10px] font-mono text-gray-600 truncate">
                  {s.query}
                </span>
              )}
            </button>
            <button
              onClick={() => {
                const next = window.prompt('Rename saved query', s.name);
                if (next) onRename(s.query, next);
              }}
              className="text-[10px] font-mono text-gray-600 hover:text-white shrink-0 opacity-0 group-hover:opacity-100"
              aria-label={`Rename ${s.name}`}
              title="Rename"
            >
              edit
            </button>
            <button
              onClick={() => onUnstar(s.query)}
              className="text-xs text-amber-400 hover:text-gray-500 shrink-0"
              aria-label={`Remove ${s.name} from saved`}
              title="Unstar"
            >
              ★
            </button>
          </div>
        ))}
      </div>

      <div>
        <div className="flex items-center justify-between mb-1">
          <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">
            Recent
          </span>
          {recent.length > 0 && (
            <button
              onClick={onClearRecent}
              className="text-[10px] font-mono text-gray-600 hover:text-breach-400 uppercase"
            >
              clear
            </button>
          )}
        </div>
        {recent.length === 0 && (
          <div className="text-[11px] font-mono text-gray-600 px-1 py-0.5">
            submitted queries show up here
          </div>
        )}
        {recent.map((r) => (
          <div
            key={r.query}
            className="flex items-center gap-1.5 group px-1 py-0.5 hover:bg-void-800"
          >
            <button
              onClick={() => onRun(r.query)}
              className="flex-1 text-left text-xs font-mono text-gray-300 truncate min-w-0"
              title={r.query}
            >
              {r.query}
            </button>
            <button
              onClick={() => onStar(r.query)}
              className="text-xs text-gray-600 hover:text-amber-400 shrink-0 opacity-0 group-hover:opacity-100"
              aria-label={`Save ${r.query}`}
              title="Star to save"
            >
              ☆
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
