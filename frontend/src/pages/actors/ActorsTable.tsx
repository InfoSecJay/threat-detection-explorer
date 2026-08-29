// Extracted from pages/Actors.tsx (#23). Behaviour unchanged.
import { Link } from 'react-router-dom';
import { clipSm } from '../../constants/style';
import { countryFlag, countryName, coverageBarClass, coverageTextClass, GAP_ACCENT_THRESHOLD, MOTIVATION_STYLE } from '../../utils/actorDisplay';
import type { ActorsQueryItem } from '../../services/api';
import { TYPE_TOOLTIP } from './constants';

// ── Table ──────────────────────────────────────────────────────────

const TABLE_COLUMNS: {
  key: string;
  label: string;
  sort?: string;
  groupsOnly?: boolean;
  softwareOnly?: boolean;
}[] = [
  { key: 'name', label: 'Name', sort: 'name' },
  { key: 'aliases', label: 'Aliases' },
  { key: 'type', label: 'Type', sort: 'type', softwareOnly: true },
  { key: 'used_by', label: 'Used by', sort: 'used_by_actor_count', softwareOnly: true },
  { key: 'origin', label: 'Origin', sort: 'origin', groupsOnly: true },
  { key: 'motivation', label: 'Motivation', sort: 'motivation', groupsOnly: true },
  { key: 'sectors', label: 'Sectors', groupsOnly: true },
  { key: 'technique_count', label: 'Techniques', sort: 'technique_count' },
  { key: 'gap_count', label: 'Gaps', sort: 'gap_count' },
  { key: 'weighted_coverage', label: 'Weighted cov.', sort: 'weighted_coverage' },
  { key: 'our_rule_count', label: 'Dedicated', sort: 'our_rule_count' },
  { key: 'mention_count', label: 'Referenced', sort: 'mention_count' },
  { key: 'modified', label: 'Modified', sort: 'modified' },
];

export function ActorsTable({
  items,
  isGroup,
  sort,
  order,
  onSort,
  onSectorClick,
}: {
  items: ActorsQueryItem[];
  isGroup: boolean;
  sort: string;
  order: 'asc' | 'desc';
  onSort: (key: string) => void;
  onSectorClick: (sector: string) => void;
}) {
  const columns = TABLE_COLUMNS.filter((c) =>
    isGroup ? !c.softwareOnly : !c.groupsOnly
  );
  return (
    <div className="overflow-x-auto border border-void-700" style={clipSm}>
      <table className="w-full text-xs font-mono">
        <thead className="bg-void-900 text-gray-500 uppercase tracking-wider">
          <tr>
            {columns.map((c) => (
              <th key={c.key} className="px-3 py-2 text-left font-display font-semibold whitespace-nowrap">
                {c.sort ? (
                  <button
                    onClick={() => onSort(c.sort!)}
                    className={`uppercase tracking-wider hover:text-white transition-colors ${
                      sort === c.sort ? 'text-matrix-400' : ''
                    }`}
                  >
                    {c.label}
                    {sort === c.sort && (
                      <span className="ml-1">{order === 'desc' ? '▼' : '▲'}</span>
                    )}
                  </button>
                ) : (
                  c.label
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-void-800">
          {items.map((item) => (
            <tr key={item.id} className="hover:bg-void-850 transition-colors">
              <td className="px-3 py-2 whitespace-nowrap">
                <Link to={`/actors/${item.id}`} className="text-gray-200 hover:text-matrix-400 transition-colors">
                  {item.name}
                </Link>
                <span className="text-gray-700 ml-2 tabular-nums">{item.id}</span>
              </td>
              <td className="px-3 py-2 max-w-[220px]">
                <span className="block truncate text-gray-500" title={item.aliases.join(', ')}>
                  {item.aliases.slice(0, 3).join(' · ')}
                  {item.aliases.length > 3 && ` +${item.aliases.length - 3}`}
                </span>
              </td>
              {!isGroup && (
                <td className="px-3 py-2 whitespace-nowrap">
                  <span
                    className={`px-1.5 py-0.5 text-[9px] uppercase tracking-wider border ${
                      item.type === 'malware'
                        ? 'bg-orange-500/10 text-orange-400 border-orange-500/30'
                        : 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
                    }`}
                    title={TYPE_TOOLTIP[item.type ?? '']}
                  >
                    {item.type ?? 'sw'}
                  </span>
                </td>
              )}
              {!isGroup && (
                <td
                  className="px-3 py-2 tabular-nums"
                  title={(item.used_by_actors ?? []).join(', ')}
                >
                  <span className={(item.used_by_actor_count ?? 0) > 0 ? 'text-white font-semibold' : 'text-gray-700'}>
                    {item.used_by_actor_count ?? 0}
                  </span>
                  <span className="text-gray-600 ml-1">actors</span>
                </td>
              )}
              {isGroup && (
                <td className="px-3 py-2 whitespace-nowrap">
                  {item.origin_country ? (
                    <span title={countryName(item.origin_country)}>
                      {countryFlag(item.origin_country)} {item.origin_country}
                    </span>
                  ) : (
                    <span className="text-gray-700">—</span>
                  )}
                </td>
              )}
              {isGroup && (
                <td className="px-3 py-2 whitespace-nowrap">
                  {(item.motivations ?? []).length > 0 ? (
                    <span
                      className={`px-1.5 py-0.5 text-[9px] uppercase tracking-wider border ${
                        MOTIVATION_STYLE[item.motivations![0]] ?? MOTIVATION_STYLE.unknown
                      }`}
                    >
                      {item.motivations![0]}
                    </span>
                  ) : (
                    <span className="text-gray-700">—</span>
                  )}
                </td>
              )}
              {isGroup && (
                <td className="px-3 py-2 max-w-[200px]">
                  <span className="flex gap-1 flex-wrap">
                    {(item.target_sectors ?? []).slice(0, 3).map((s) => (
                      <button
                        key={s}
                        onClick={() => onSectorClick(s)}
                        className="text-[9px] text-gray-400 border border-void-700 px-1 hover:text-matrix-400 hover:border-matrix-500/40 transition-colors"
                      >
                        {s}
                      </button>
                    ))}
                  </span>
                </td>
              )}
              <td className="px-3 py-2 text-gray-400 tabular-nums">{item.technique_count}</td>
              <td className="px-3 py-2 tabular-nums">
                <span className={item.gap_count > GAP_ACCENT_THRESHOLD ? 'text-breach-400 font-semibold' : 'text-gray-300'}>
                  {item.gap_count}
                </span>
              </td>
              <td className="px-3 py-2 whitespace-nowrap">
                {item.weighted_coverage === null ? (
                  <span className="text-gray-700">n/a</span>
                ) : (
                  <span className="inline-flex items-center gap-2">
                    <span className="w-16 h-1 bg-void-800 relative overflow-hidden inline-block">
                      <span
                        className={`absolute inset-y-0 left-0 ${coverageBarClass(item.weighted_coverage)}`}
                        style={{ width: `${Math.round(item.weighted_coverage * 100)}%` }}
                      />
                    </span>
                    <span className={`tabular-nums ${coverageTextClass(item.weighted_coverage)}`}>
                      {Math.round(item.weighted_coverage * 100)}%
                    </span>
                  </span>
                )}
              </td>
              <td className="px-3 py-2 tabular-nums">
                <span className={item.our_rule_count > 0 ? 'text-white' : 'text-gray-700'}>
                  {item.our_rule_count}
                </span>
              </td>
              <td
                className="px-3 py-2 tabular-nums"
                title="Rules that cite the name or an alias in prose, tags, or references without being built for the actor — intel chatter with no dedicated content"
              >
                <span
                  className={
                    item.mention_count > 0 && item.our_rule_count === 0
                      ? 'text-cyan-400 font-semibold'
                      : item.mention_count > 0
                        ? 'text-gray-300'
                        : 'text-gray-700'
                  }
                >
                  {item.mention_count}
                </span>
              </td>
              <td className="px-3 py-2 text-gray-500 tabular-nums whitespace-nowrap">
                {item.modified ? item.modified.slice(0, 10) : '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Combined Navigator layer for the current filter set — "everything
 *  targeting telecom, scored by our coverage" as one download. */
