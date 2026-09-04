/**
 * The `?` overlay: every keyboard shortcut the catalog page honours,
 * in one place. Shortcuts that nobody can discover are shortcuts
 * nobody uses -- the list page had `/` and `f` for weeks with no hint.
 */

import { useEffect } from 'react';

const GROUPS: { title: string; rows: [string, string][] }[] = [
  {
    title: 'Catalog',
    rows: [
      ['/', 'Focus the search bar'],
      ['f', 'Open the filter sheet'],
      ['Esc', 'Close the sheet, a modal or the suggestions'],
      ['?', 'This help'],
    ],
  },
  {
    title: 'Search bar',
    rows: [
      ['Tab', 'Accept the highlighted suggestion'],
      ['Enter', 'Run the query (or accept a suggestion)'],
      ['Up / Down', 'Move through suggestions'],
    ],
  },
];

export function KeyboardShortcutsHelp({ open, onClose }: { open: boolean; onClose: () => void }) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50" onClick={onClose}>
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="shortcuts-title"
        className="bg-void-850 border border-void-700 shadow-xl p-5 w-full max-w-md"
        onClick={(e) => e.stopPropagation()}
        data-testid="shortcuts-help"
      >
        <div className="flex items-baseline justify-between mb-3">
          <h2 id="shortcuts-title" className="font-display font-bold text-white tracking-wider uppercase">Keyboard shortcuts</h2>
          <button type="button" onClick={onClose} className="text-xs font-mono text-gray-500 hover:text-white uppercase tracking-wider">close</button>
        </div>
        <div className="space-y-4">
          {GROUPS.map((g) => (
            <div key={g.title}>
              <div className="text-[10px] font-mono uppercase tracking-wider text-matrix-400 mb-1">{g.title}</div>
              <dl className="divide-y divide-void-800">
                {g.rows.map(([key, what]) => (
                  <div key={key} className="flex items-center gap-3 py-1.5">
                    <dt className="w-24 shrink-0">
                      <kbd className="px-1.5 py-0.5 text-[11px] font-mono bg-void-900 border border-void-600 text-gray-200 rounded-sm">{key}</kbd>
                    </dt>
                    <dd className="text-xs text-gray-300">{what}</dd>
                  </div>
                ))}
              </dl>
            </div>
          ))}
        </div>
        <p className="mt-4 text-[11px] text-gray-500">
          Shortcuts are ignored while typing in a field. The query syntax itself is documented on the Query Reference page.
        </p>
      </div>
    </div>
  );
}
