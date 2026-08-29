/**
 * Threat Actors + Software index — MITRE-parity catalog with our
 * corpus coverage overlaid, ranked by outstanding detection work
 * (weighted_gap desc).
 *
 * Density toggle (table | cards, table default, persisted in
 * localStorage) + URL-param filters so views are shareable: sector,
 * region, motivation, origin (multi-select), min_gaps,
 * has_exact_rules, q, sort, order, page, tab. Facet counts come from
 * the backend so filter options show result counts before clicking.
 */

import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useActorsQuery } from '../hooks/useActors';
import { actorsApi } from '../services/api';
import { stripMitreMarkup } from '../components/MitreText';
import { sourceTheme as sourceConfig, clipSm, clipMd } from '../constants/style';
import {
  countryFlag,
  countryName,
  coverageBarClass,
  coverageTextClass,
  GAP_ACCENT_THRESHOLD,
  MOTIVATION_STYLE,
} from '../utils/actorDisplay';
import type { ActorsQueryItem } from '../services/api';

// ── Cards (Phase 3) ────────────────────────────────────────────────

function SourceDots({ sources }: { sources: string[] }) {
  return (
    <div className="flex gap-0.5 items-center">
      {sources.slice(0, 6).map((src) => {
        const cfg = sourceConfig[src];
        return (
          <span
            key={src}
            className={`w-1.5 h-1.5 rounded-full ${cfg?.dot || 'bg-gray-500'}`}
            title={cfg?.name || src}
          />
        );
      })}
    </div>
  );
}

/** Origin / motivation / sector chips. Chips with no data are omitted
 *  entirely — no placeholders. Sector chips apply as a filter. */
function ContextChips({
  item,
  onSectorClick,
}: {
  item: ActorsQueryItem;
  onSectorClick?: (sector: string) => void;
}) {
  const origin = item.origin_country;
  const motivation = item.motivations?.[0];
  const sectors = (item.target_sectors ?? []).slice(0, 2);
  if (!origin && !motivation && sectors.length === 0) return null;
  return (
    <div className="flex items-center gap-1 mb-2 flex-wrap">
      {origin && (
        <span
          className="text-[9px] font-mono text-gray-400 border border-void-700 bg-void-900 px-1.5 py-0.5"
          title={`Origin: ${countryName(origin)}`}
        >
          {countryFlag(origin)} {countryName(origin)}
        </span>
      )}
      {motivation && (
        <span
          className={`text-[9px] font-mono uppercase tracking-wider border px-1.5 py-0.5 ${
            MOTIVATION_STYLE[motivation] ?? MOTIVATION_STYLE.unknown
          }`}
        >
          {motivation}
        </span>
      )}
      {sectors.map((sec) => (
        <button
          key={sec}
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            onSectorClick?.(sec);
          }}
          className="text-[9px] font-mono text-gray-400 border border-void-700 bg-void-900 px-1.5 py-0.5 hover:text-matrix-400 hover:border-matrix-500/40 transition-colors"
          title={`Filter to actors targeting ${sec}`}
        >
          {sec}
        </button>
      ))}
    </div>
  );
}

/** Headline stat + weighted-coverage bar + exact rules. Actors lead
 *  with what's NOT covered; software leads with how many actors share
 *  it — a rule for widely-shared tooling is the highest-leverage
 *  detection on the site. */
function GapStats({ item, isGroup }: { item: ActorsQueryItem; isGroup: boolean }) {
  const pct =
    item.weighted_coverage === null || item.weighted_coverage === undefined
      ? null
      : Math.round(item.weighted_coverage * 100);
  const fullyCovered = item.gap_count === 0 && item.technique_count > 0;
  return (
    <div className="pt-2 border-t border-void-700 space-y-2">
      {!isGroup ? (
        <div
          className="flex items-baseline gap-1.5"
          title="Distinct ATT&CK groups with a `uses` relationship to this software"
        >
          <span
            className={`text-2xl font-display font-bold tabular-nums leading-none ${
              (item.used_by_actor_count ?? 0) > 0 ? 'text-white' : 'text-gray-600'
            }`}
          >
            {item.used_by_actor_count ?? 0}
          </span>
          <span className="text-[9px] font-mono text-gray-500 uppercase tracking-wider">
            actors use this
          </span>
        </div>
      ) : fullyCovered ? (
        <div className="text-xs font-mono text-gray-500 uppercase tracking-wider py-1">
          fully covered
        </div>
      ) : (
        <div className="flex items-baseline gap-1.5">
          <span
            className={`text-2xl font-display font-bold tabular-nums leading-none ${
              item.gap_count > GAP_ACCENT_THRESHOLD ? 'text-breach-400' : 'text-white'
            }`}
          >
            {item.gap_count}
          </span>
          <span className="text-[9px] font-mono text-gray-500 uppercase tracking-wider">
            techniques with no rules
          </span>
        </div>
      )}
      <div
        className="w-full"
        title={
          pct === null
            ? 'No weighted coverage score (no techniques in the weight corpus)'
            : `Weighted coverage ${pct}% — techniques weighted by distinctiveness (rare TTPs count more)`
        }
      >
        <div className="h-1 bg-void-800 relative overflow-hidden">
          <div
            className={`absolute inset-y-0 left-0 ${coverageBarClass(item.weighted_coverage ?? null)}`}
            style={{ width: `${pct ?? 0}%` }}
          />
        </div>
        <div className="flex items-center justify-between mt-1">
          <span className={`text-[9px] font-mono tabular-nums ${coverageTextClass(item.weighted_coverage ?? null)}`}>
            {pct === null ? 'n/a' : `${pct}% weighted`}
          </span>
          <span className="text-[9px] font-mono text-gray-500 tabular-nums">
            {item.covered_technique_count}/{item.technique_count} raw
          </span>
        </div>
      </div>
      <div className="flex items-center justify-between gap-2">
        <span className={`text-[10px] font-mono tabular-nums ${item.our_rule_count > 0 ? 'text-white' : 'text-gray-600'}`}>
          <span className="font-semibold">{item.our_rule_count}</span>
          <span className="text-gray-600 ml-1">dedicated</span>
          {item.mention_count > 0 && (
            <span
              className={item.our_rule_count === 0 ? 'text-cyan-400 ml-2' : 'text-gray-500 ml-2'}
              title="Rules that cite the name or an alias in prose, tags, or references without being built for the actor"
            >
              · {item.mention_count} referenced
            </span>
          )}
        </span>
        <SourceDots sources={item.sources_with_coverage} />
      </div>
    </div>
  );
}

function EntityCard({
  item,
  isGroup,
  onSectorClick,
}: {
  item: ActorsQueryItem;
  isGroup: boolean;
  onSectorClick?: (sector: string) => void;
}) {
  const kindLabel = isGroup
    ? 'ACTOR'
    : item.type === 'tool' ? 'TOOL' : item.type === 'malware' ? 'MALWARE' : 'SW';
  const accent = isGroup
    ? { label: 'bg-breach-500/10 text-breach-400 border-breach-500/30', border: 'hover:border-breach-500/50', name: 'group-hover:text-breach-300' }
    : item.type === 'malware'
      ? { label: 'bg-orange-500/10 text-orange-400 border-orange-500/30', border: 'hover:border-orange-500/50', name: 'group-hover:text-orange-300' }
      : { label: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30', border: 'hover:border-cyan-500/50', name: 'group-hover:text-cyan-300' };

  return (
    <Link
      to={`/actors/${item.id}`}
      title={item.description ? stripMitreMarkup(item.description) : item.name}
      className={`group relative block bg-void-850 border border-void-700 ${accent.border} p-3 transition-colors`}
      style={clipSm}
    >
      <div className="flex items-start justify-between gap-2 mb-2">
        <span
          className={`text-[9px] font-mono uppercase tracking-wider px-1.5 py-0.5 border ${accent.label}`}
          title={!isGroup ? TYPE_TOOLTIP[item.type ?? ''] : undefined}
        >
          {kindLabel}
        </span>
        <span className="text-[10px] font-mono text-gray-600 tabular-nums">{item.id}</span>
      </div>
      <div className={`text-sm font-mono font-semibold text-white leading-tight line-clamp-2 mb-2 ${accent.name}`}>
        {item.name}
      </div>
      {isGroup && <ContextChips item={item} onSectorClick={onSectorClick} />}
      {item.aliases.length > 0 && (
        <div className="text-[10px] font-mono text-gray-500 mb-2 truncate" title={item.aliases.join(', ')}>
          aka {item.aliases.slice(0, 2).join(' · ')}
          {item.aliases.length > 2 && ` +${item.aliases.length - 2}`}
        </div>
      )}
      <GapStats item={item} isGroup={isGroup} />
    </Link>
  );
}

/** Why the tool/malware split matters for detection work. */
const TYPE_TOOLTIP: Record<string, string> = {
  tool: 'Dual-use: legitimate admin software abused by actors. Needs behavioral detections and carries FP cost.',
  malware: 'Bespoke: built for the operation. Signature/IOC detections work.',
};

// ── Filters ────────────────────────────────────────────────────────

/** Multi-select facet dropdown with result counts. */
function FacetSelect({
  label,
  options,
  selected,
  onChange,
  renderOption,
}: {
  label: string;
  options: Record<string, number>;
  selected: string[];
  onChange: (values: string[]) => void;
  renderOption?: (value: string) => string;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', close);
    return () => document.removeEventListener('mousedown', close);
  }, [open]);

  const entries = Object.entries(options);
  if (entries.length === 0 && selected.length === 0) return null;

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((o) => !o)}
        className={`px-2.5 py-1.5 text-[10px] font-mono uppercase tracking-wider border transition-colors ${
          selected.length > 0
            ? 'bg-matrix-500/10 text-matrix-400 border-matrix-500/40'
            : 'bg-void-900 text-gray-400 border-void-700 hover:text-white'
        }`}
        style={clipSm}
      >
        {label}
        {selected.length > 0 && <span className="ml-1 tabular-nums">({selected.length})</span>}
        <span className="ml-1 text-gray-600">▾</span>
      </button>
      {open && (
        <div
          className="absolute z-20 mt-1 min-w-[220px] max-h-72 overflow-y-auto bg-void-900 border border-void-600 shadow-xl p-1"
        >
          {entries.map(([value, count]) => {
            const checked = selected.includes(value);
            return (
              <label
                key={value}
                className="flex items-center gap-2 px-2 py-1.5 text-xs font-mono text-gray-300 hover:bg-void-800 cursor-pointer"
              >
                <input
                  type="checkbox"
                  checked={checked}
                  onChange={() =>
                    onChange(
                      checked ? selected.filter((v) => v !== value) : [...selected, value]
                    )
                  }
                  className="accent-matrix-500"
                />
                <span className="flex-1 truncate">{renderOption ? renderOption(value) : value}</span>
                <span className="text-gray-600 tabular-nums">{count}</span>
              </label>
            );
          })}
          {/* Selected values that fell out of the facet (count 0 under
              current filters) stay listed so they can be uchecked. */}
          {selected.filter((v) => !(v in options)).map((value) => (
            <label
              key={value}
              className="flex items-center gap-2 px-2 py-1.5 text-xs font-mono text-gray-500 hover:bg-void-800 cursor-pointer"
            >
              <input
                type="checkbox"
                checked
                onChange={() => onChange(selected.filter((v) => v !== value))}
                className="accent-matrix-500"
              />
              <span className="flex-1 truncate">{renderOption ? renderOption(value) : value}</span>
              <span className="text-gray-600 tabular-nums">0</span>
            </label>
          ))}
        </div>
      )}
    </div>
  );
}

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

function ActorsTable({
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
function BulkExportButton({
  params,
}: {
  params: Parameters<typeof actorsApi.downloadBulkNavigatorLayer>[0];
}) {
  const [exporting, setExporting] = useState(false);
  return (
    <button
      onClick={async () => {
        if (exporting) return;
        setExporting(true);
        try {
          await actorsApi.downloadBulkNavigatorLayer(params);
        } finally {
          setExporting(false);
        }
      }}
      disabled={exporting}
      className="text-[10px] font-mono text-cyan-400 hover:text-cyan-300 uppercase tracking-wider border border-cyan-500/30 hover:border-cyan-500/60 px-2 py-1 transition-colors disabled:opacity-50"
      style={clipSm}
      title="Download a combined ATT&CK Navigator layer for every actor matching the current filters, scored by our rule coverage"
    >
      {exporting ? '[ exporting… ]' : '[ export navigator layer ]'}
    </button>
  );
}

// ── Page ───────────────────────────────────────────────────────────

type Tab = 'groups' | 'software';
type View = 'table' | 'cards';

const VIEW_STORAGE_KEY = 'actors-view';
const CARDS_PER_PAGE = 500;
const TABLE_PER_PAGE = 50;

export function Actors() {
  const [searchParams, setSearchParams] = useSearchParams();

  const tab = (searchParams.get('tab') === 'software' ? 'software' : 'groups') as Tab;
  const [view, setView] = useState<View>(() => {
    // localStorage throws when site data is blocked; a throw inside a
    // useState initializer is a render-phase crash for the whole page.
    try {
      return localStorage.getItem(VIEW_STORAGE_KEY) === 'cards' ? 'cards' : 'table';
    } catch {
      return 'table';
    }
  });

  // getAll() returns a fresh array every call; memoize on searchParams
  // (stable per URL) so the arrays are valid useMemo deps below.
  const { sector, region, motivation, origin, swType } = useMemo(
    () => ({
      sector: searchParams.getAll('sector'),
      region: searchParams.getAll('region'),
      motivation: searchParams.getAll('motivation'),
      origin: searchParams.getAll('origin'),
      swType: searchParams.getAll('type'),
    }),
    [searchParams],
  );
  const usedByActor = searchParams.get('used_by_actor');
  const minGaps = searchParams.get('min_gaps');
  const hasExactRules = searchParams.get('has_exact_rules');
  const q = searchParams.get('q') ?? '';
  const sort =
    searchParams.get('sort') ??
    (tab === 'software' ? 'used_by_actor_count' : 'weighted_gap');
  const order = (searchParams.get('order') === 'asc' ? 'asc' : 'desc') as 'asc' | 'desc';
  const page = Math.max(1, Number(searchParams.get('page') ?? '1') || 1);

  const params = useMemo(
    () => ({
      kind: tab,
      sector: tab === 'groups' ? sector : undefined,
      region: tab === 'groups' ? region : undefined,
      motivation: tab === 'groups' ? motivation : undefined,
      origin: tab === 'groups' ? origin : undefined,
      type: tab === 'software' ? swType : undefined,
      used_by_actor: tab === 'software' ? usedByActor ?? undefined : undefined,
      min_gaps: minGaps !== null ? Number(minGaps) : undefined,
      has_exact_rules:
        hasExactRules === 'true' ? true : hasExactRules === 'false' ? false : undefined,
      q: q || undefined,
      sort,
      order,
      page: view === 'cards' ? 1 : page,
      per_page: view === 'cards' ? CARDS_PER_PAGE : TABLE_PER_PAGE,
    }),
    [tab, sector, region, motivation, origin, swType, usedByActor,
     minGaps, hasExactRules, q, sort, order, page, view]
  );

  const { data, isLoading, error } = useActorsQuery(params);

  const update = (mutate: (next: URLSearchParams) => void, resetPage = true, replace = false) => {
    const next = new URLSearchParams(searchParams);
    mutate(next);
    if (resetPage) next.delete('page');
    setSearchParams(next, { replace });
  };

  // Free-text filter: type into local state, commit to the URL after a
  // short pause and as a history REPLACE. Committing per keystroke
  // pushed one history entry and one /actors request per character.
  const [qDraft, setQDraft] = useState(q);
  useEffect(() => {
    setQDraft(q);
  }, [q]);
  useEffect(() => {
    if (qDraft === q) return;
    const t = setTimeout(
      () =>
        update((next) => {
          if (qDraft) next.set('q', qDraft);
          else next.delete('q');
        }, true, true),
      250,
    );
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `update` is rebuilt every render; only the draft should schedule a commit
  }, [qDraft]);

  const setDim = (dim: string, values: string[]) =>
    update((next) => {
      next.delete(dim);
      for (const v of values) next.append(dim, v);
    });

  const addSector = (sec: string) =>
    update((next) => {
      if (!next.getAll('sector').includes(sec)) next.append('sector', sec);
    });

  const setSort = (key: string) =>
    update((next) => {
      const current = next.get('sort') ?? 'weighted_gap';
      if (current === key) {
        next.set('order', (next.get('order') === 'asc' ? 'desc' : 'asc'));
      } else {
        next.set('sort', key);
        next.set('order', 'desc');
      }
    }, false);

  const switchView = (v: View) => {
    setView(v);
    try {
      localStorage.setItem(VIEW_STORAGE_KEY, v);
    } catch {
      /* preference simply does not persist when site data is blocked */
    }
  };

  const activeFilterCount =
    sector.length + region.length + motivation.length + origin.length +
    swType.length + (usedByActor ? 1 : 0) +
    (minGaps !== null ? 1 : 0) + (hasExactRules !== null ? 1 : 0) + (q ? 1 : 0);

  const isGroup = tab === 'groups';
  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.per_page)) : 1;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">
          Threat Actors
        </h1>
        <p className="text-xs text-gray-500 mt-1 font-mono">
          the full MITRE ATT&amp;CK catalog ranked by outstanding detection work — click any entry to see what we cover and what we don&apos;t
        </p>
      </div>

      {/* Hero counts + search */}
      <div className="bg-gradient-to-r from-breach-500/10 via-orange-500/5 to-transparent border border-breach-500/30 px-5 py-4" style={clipMd}>
        <div className="flex items-end justify-between gap-4 flex-wrap">
          <div className="flex items-baseline gap-6 flex-wrap">
            <div>
              <div className="text-[10px] font-mono text-breach-400 uppercase tracking-[0.2em] mb-1">Actors</div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-display font-bold text-white tabular-nums">
                  {data?.summary.total_groups ?? '—'}
                </span>
                <span className="text-[10px] font-mono text-gray-500">
                  ({data?.summary.groups_with_coverage ?? 0} with rules)
                </span>
              </div>
            </div>
            <div>
              <div className="text-[10px] font-mono text-cyan-400 uppercase tracking-[0.2em] mb-1">Software + tools</div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-display font-bold text-white tabular-nums">
                  {data?.summary.total_software ?? '—'}
                </span>
                <span className="text-[10px] font-mono text-gray-500">
                  ({data?.summary.software_with_coverage ?? 0} with rules)
                </span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-3 flex-wrap">
            {/* Density toggle */}
            <div className="flex border border-void-700" style={clipSm}>
              {(['table', 'cards'] as View[]).map((v) => (
                <button
                  key={v}
                  onClick={() => switchView(v)}
                  className={`px-2.5 py-1.5 text-[10px] font-mono uppercase tracking-wider transition-colors ${
                    view === v ? 'bg-matrix-500/20 text-matrix-400' : 'bg-void-900 text-gray-500 hover:text-white'
                  }`}
                >
                  {v}
                </button>
              ))}
            </div>
            <input
              type="search"
              value={qDraft}
              onChange={(e) => setQDraft(e.target.value)}
              placeholder="filter: apt29, cobalt strike, g0016…"
              className="bg-void-900 border border-void-700 text-sm text-white font-mono px-3 py-2 min-w-[260px] focus:outline-none focus:border-matrix-500/50 placeholder:text-gray-600"
              style={clipSm}
              aria-label="Filter actors and software by name, alias, or ID"
            />
          </div>
        </div>
      </div>

      {/* Tab switcher */}
      <div className="flex items-center gap-1 border-b border-void-800">
        {(['groups', 'software'] as Tab[]).map((t) => {
          const active = tab === t;
          return (
            <button
              key={t}
              onClick={() =>
                update((next) => {
                  if (t === 'software') next.set('tab', 'software');
                  else next.delete('tab');
                  // Kind-specific filters and sort keys don't carry
                  // across tabs — reset them on switch.
                  for (const key of ['sector', 'region', 'motivation', 'origin', 'type', 'used_by_actor', 'sort', 'order']) {
                    next.delete(key);
                  }
                })
              }
              className={`px-4 py-2 text-xs font-display font-semibold uppercase tracking-wider border-b-2 -mb-[1px] transition-colors ${
                active
                  ? t === 'groups'
                    ? 'text-breach-400 border-breach-500'
                    : 'text-cyan-400 border-cyan-500'
                  : 'text-gray-500 border-transparent hover:text-white'
              }`}
            >
              {t === 'groups' ? 'Actors' : 'Software'}
              {active && data && (
                <span className="ml-2 text-[10px] font-mono text-gray-600 tabular-nums">{data.total}</span>
              )}
            </button>
          );
        })}
      </div>

      {/* Filter bar */}
      <div className="flex items-center gap-2 flex-wrap">
        {!isGroup && data && (
          <>
            <FacetSelect
              label="type"
              options={data.facets.type ?? {}}
              selected={swType}
              onChange={(v) => setDim('type', v)}
              renderOption={(v) => v}
            />
            {usedByActor && (
              <button
                onClick={() => update((next) => next.delete('used_by_actor'))}
                className="text-[10px] font-mono uppercase tracking-wider text-matrix-400 border border-matrix-500/40 bg-matrix-500/10 px-2 py-1 hover:border-matrix-500/70 transition-colors"
                title="Clear used-by-actor filter"
              >
                used by {usedByActor} ✕
              </button>
            )}
          </>
        )}
        {isGroup && data && (
          <>
            <FacetSelect
              label="sector"
              options={data.facets.sector ?? {}}
              selected={sector}
              onChange={(v) => setDim('sector', v)}
            />
            <FacetSelect
              label="region"
              options={data.facets.region ?? {}}
              selected={region}
              onChange={(v) => setDim('region', v)}
            />
            <FacetSelect
              label="motivation"
              options={data.facets.motivation ?? {}}
              selected={motivation}
              onChange={(v) => setDim('motivation', v)}
            />
            <FacetSelect
              label="origin"
              options={data.facets.origin ?? {}}
              selected={origin}
              onChange={(v) => setDim('origin', v)}
              renderOption={(v) => `${countryFlag(v)} ${countryName(v)}`}
            />
          </>
        )}
        <label className="flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-wider text-gray-400">
          min gaps
          <input
            type="number"
            min={0}
            value={minGaps ?? ''}
            onChange={(e) =>
              update((next) => {
                if (e.target.value) next.set('min_gaps', e.target.value);
                else next.delete('min_gaps');
              })
            }
            className="w-16 bg-void-900 border border-void-700 text-xs text-white font-mono px-2 py-1 focus:outline-none focus:border-matrix-500/50"
          />
        </label>
        <select
          value={hasExactRules ?? 'any'}
          onChange={(e) =>
            update((next) => {
              if (e.target.value === 'any') next.delete('has_exact_rules');
              else next.set('has_exact_rules', e.target.value);
            })
          }
          className="bg-void-900 border border-void-700 text-[10px] text-gray-300 font-mono uppercase tracking-wider px-2 py-1.5 focus:outline-none focus:border-matrix-500/50"
          aria-label="Filter by dedicated rule presence"
        >
          <option value="any">dedicated rules: any</option>
          <option value="true">has dedicated rules</option>
          <option value="false">no dedicated rules</option>
        </select>
        {activeFilterCount > 0 && (
          <button
            onClick={() =>
              update((next) => {
                for (const key of ['sector', 'region', 'motivation', 'origin', 'type', 'used_by_actor', 'min_gaps', 'has_exact_rules', 'q']) {
                  next.delete(key);
                }
              })
            }
            className="text-[10px] font-mono text-gray-500 hover:text-breach-400 uppercase tracking-wider transition-colors"
          >
            clear filters ({activeFilterCount})
          </button>
        )}
        {data && (
          <span className="ml-auto text-[10px] font-mono text-gray-600 tabular-nums">
            {data.total} result{data.total === 1 ? '' : 's'}
          </span>
        )}
        {isGroup && data && data.total > 0 && (
          <BulkExportButton
            params={{
              sector, region, motivation, origin,
              min_gaps: minGaps !== null ? Number(minGaps) : undefined,
              has_exact_rules:
                hasExactRules === 'true' ? true : hasExactRules === 'false' ? false : undefined,
              q: q || undefined,
            }}
          />
        )}
      </div>

      {/* Results */}
      {isLoading && !data && (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-2">
          {[...Array(15)].map((_, i) => (
            <div key={i} className="h-40 bg-void-800 animate-pulse" style={clipSm} />
          ))}
        </div>
      )}
      {error && (
        <div className="text-xs font-mono text-breach-400 py-4">Failed to load actors.</div>
      )}
      {data && data.items.length === 0 && (
        <div className="text-center py-12 text-gray-500 font-mono text-xs">
          nothing matches these filters
        </div>
      )}
      {data && data.items.length > 0 && view === 'table' && (
        <>
          <ActorsTable
            items={data.items}
            isGroup={isGroup}
            sort={sort}
            order={order}
            onSort={setSort}
            onSectorClick={addSector}
          />
          {totalPages > 1 && (
            <div className="flex items-center justify-between text-[10px] font-mono text-gray-500">
              <button
                disabled={page <= 1}
                onClick={() => update((next) => next.set('page', String(page - 1)), false)}
                className="px-2 py-1 border border-void-700 disabled:opacity-30 hover:text-white transition-colors uppercase tracking-wider"
              >
                ← prev
              </button>
              <span className="tabular-nums">page {page} / {totalPages}</span>
              <button
                disabled={page >= totalPages}
                onClick={() => update((next) => next.set('page', String(page + 1)), false)}
                className="px-2 py-1 border border-void-700 disabled:opacity-30 hover:text-white transition-colors uppercase tracking-wider"
              >
                next →
              </button>
            </div>
          )}
        </>
      )}
      {data && data.items.length > 0 && view === 'cards' && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-2">
            {data.items.map((item) => (
              <EntityCard key={item.id} item={item} isGroup={isGroup} onSectorClick={addSector} />
            ))}
          </div>
          {data.total > data.items.length && (
            // Cards are capped at CARDS_PER_PAGE with no paging; say so
            // instead of silently showing 500 of 743 (#51).
            <div className="text-[10px] font-mono text-gray-500 text-center py-2" role="status">
              showing the first {data.items.length.toLocaleString()} of {data.total.toLocaleString()} --
              narrow the filters or{' '}
              <button onClick={() => switchView('table')} className="text-matrix-400 hover:text-matrix-300 underline">
                switch to table view
              </button>{' '}
              to page through the rest
            </div>
          )}
        </>
      )}
    </div>
  );
}
