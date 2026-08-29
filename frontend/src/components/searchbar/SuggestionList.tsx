/** Typeahead dropdown under the search bar. */

import { clipSm } from '../../constants/style';
import type { Suggestion } from './suggestions';

export function SuggestionList({
  suggestions, activeIdx, onPick,
}: {
  suggestions: Suggestion[];
  activeIdx: number;
  onPick: (sug: Suggestion) => void;
}) {
  return (
    <ul
      id="searchbar-suggestions"
      role="listbox"
      className="absolute z-40 top-full left-0 right-0 mt-1 bg-void-900 border border-void-700 max-h-80 overflow-y-auto"
      style={clipSm}
    >
      {suggestions.map((sug, i) => {
        const active = i === activeIdx;
        return (
          <li
            key={`${sug.kind}-${sug.value}-${i}`}
            role="option"
            aria-selected={active}
            onMouseDown={(e) => {
              // mousedown fires before blur so we don't lose the click.
              e.preventDefault();
              onPick(sug);
            }}
            className={`px-3 py-1.5 cursor-pointer flex items-center gap-3 text-xs font-mono ${active ? 'bg-matrix-500/10 text-white' : 'text-gray-300 hover:bg-void-800'}`}
          >
            <span className={`shrink-0 uppercase text-[9px] tracking-wider ${sug.kind === 'field' ? 'text-cyan-400' : 'text-matrix-500'}`}>
              {sug.kind === 'field' ? 'FIELD' : 'VAL'}
            </span>
            <span className="truncate">{sug.label}</span>
            {sug.hint && (
              <span className="ml-auto text-gray-500 text-[10px] truncate max-w-[50%]">
                {sug.hint}
              </span>
            )}
          </li>
        );
      })}
    </ul>
  );
}
