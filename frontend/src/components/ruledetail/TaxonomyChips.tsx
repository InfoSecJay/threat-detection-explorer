/** Canonical taxonomy -- the official platforms / data_sources /
 * event_types fields. Multi-value because a single rule can
 * legitimately span multiple OSes, data feeds, or event categories. */

import type { Detection } from '../../types';

function Group({ label, items, tone }: { label: string; items: string[] | null | undefined; tone: string }) {
  return (
    <div>
      <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">
        {label}
      </label>
      {items && items.length > 0 ? (
        <div className="flex flex-wrap gap-1.5">
          {items.map((v) => (
            <span
              key={v}
              className={`inline-flex px-2.5 py-1 rounded text-xs font-medium border ${
                v === 'unknown'
                  ? 'bg-gray-500/20 text-gray-400 border-gray-500/30 italic'
                  : tone
              }`}
            >
              {v}
            </span>
          ))}
        </div>
      ) : (
        <span className="text-gray-500 text-xs italic">(not populated)</span>
      )}
    </div>
  );
}

export function TaxonomyChips({ detection }: { detection: Detection }) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
      <Group label="Platforms" items={detection.platforms} tone="bg-cyan-500/15 text-cyan-300 border-cyan-500/30" />
      <Group label="Data Sources" items={detection.data_sources} tone="bg-emerald-500/15 text-emerald-300 border-emerald-500/30" />
      <Group label="Event Types" items={detection.event_types} tone="bg-orange-500/15 text-orange-300 border-orange-500/30" />
    </div>
  );
}
