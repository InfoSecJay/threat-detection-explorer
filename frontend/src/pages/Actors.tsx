/**
 * Threat Actors + Software index — MITRE-parity catalog with our
 * corpus coverage overlaid. Every ATT&CK Group and Software appears
 * regardless of whether we have rules for it. Cards make it obvious
 * which entries have coverage vs which are gaps.
 *
 * Two tabs (Actors / Software), inline search across name + alias +
 * ID, sort + "coverage only" toggle. Cards deep-link to the detail
 * page. This is the "who's out there and who are we chasing?"
 * lay of the land — the drill-in is on the detail page.
 */

import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useActors } from '../hooks/useActors';
import { stripMitreMarkup } from '../components/MitreText';
import { sourceTheme as sourceConfig, clipSm, clipMd } from '../constants/style';
import type { ActorListGroup, ActorListSoftware } from '../services/api';

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

function CoverageMeter({
  covered,
  total,
  accent,
}: {
  covered: number;
  total: number;
  accent: string;
}) {
  const pct = total > 0 ? Math.round((covered / total) * 100) : 0;
  return (
    <div className="w-full" title={`${covered} of ${total} techniques have rules (${pct}%)`}>
      <div className="h-1 bg-void-800 relative overflow-hidden">
        <div
          className={`absolute inset-y-0 left-0 ${accent}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <div className="flex items-center justify-between mt-1">
        <span className="text-[9px] font-mono text-gray-600">
          {covered}/{total} TTPs covered
        </span>
        <span className="text-[9px] font-mono text-gray-500 tabular-nums">
          {pct}%
        </span>
      </div>
    </div>
  );
}

function GroupCard({ g }: { g: ActorListGroup }) {
  const hasRules = g.our_rule_count > 0;
  return (
    <Link
      to={`/actors/${g.id}`}
      title={g.description ? stripMitreMarkup(g.description) : g.name}
      className={`group relative block bg-void-850 border p-3 transition-colors ${
        hasRules ? 'border-void-700 hover:border-breach-500/50' : 'border-void-800 hover:border-void-600 opacity-70 hover:opacity-100'
      }`}
      style={clipSm}
    >
      <div className="flex items-start justify-between gap-2 mb-2">
        <span className="text-[9px] font-mono uppercase tracking-wider px-1.5 py-0.5 border bg-breach-500/10 text-breach-400 border-breach-500/30">
          ACTOR
        </span>
        <span className="text-[10px] font-mono text-gray-600 tabular-nums">{g.id}</span>
      </div>
      <div className="text-sm font-mono font-semibold text-white leading-tight line-clamp-2 mb-2 min-h-[2.5rem] group-hover:text-breach-300">
        {g.name}
      </div>
      {g.aliases.length > 0 && (
        <div className="text-[10px] font-mono text-gray-500 mb-2 truncate" title={g.aliases.join(', ')}>
          aka {g.aliases.slice(0, 2).join(' · ')}
          {g.aliases.length > 2 && ` +${g.aliases.length - 2}`}
        </div>
      )}
      <div className="pt-2 border-t border-void-700 space-y-2">
        <CoverageMeter
          covered={g.covered_technique_count}
          total={g.technique_count}
          accent="bg-breach-500/60"
        />
        <div className="flex items-center justify-between gap-2">
          <span className={`text-[10px] font-mono tabular-nums ${hasRules ? 'text-white' : 'text-gray-600'}`}>
            <span className="font-semibold">{g.our_rule_count}</span>
            <span className="text-gray-600 ml-1">exact-tag rules</span>
          </span>
          <SourceDots sources={g.sources_with_coverage} />
        </div>
      </div>
    </Link>
  );
}

function SoftwareCard({ s }: { s: ActorListSoftware }) {
  const hasRules = s.our_rule_count > 0;
  const kindLabel = s.type === 'tool' ? 'TOOL' : s.type === 'malware' ? 'MALWARE' : 'SW';
  const accent =
    s.type === 'malware'
      ? { label: 'bg-orange-500/10 text-orange-400 border-orange-500/30', border: 'hover:border-orange-500/50', name: 'group-hover:text-orange-300', bar: 'bg-orange-500/60' }
      : { label: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30', border: 'hover:border-cyan-500/50', name: 'group-hover:text-cyan-300', bar: 'bg-cyan-500/60' };

  return (
    <Link
      to={`/actors/${s.id}`}
      title={s.description ? stripMitreMarkup(s.description) : s.name}
      className={`group relative block bg-void-850 border p-3 transition-colors ${
        hasRules ? `border-void-700 ${accent.border}` : `border-void-800 hover:border-void-600 opacity-70 hover:opacity-100`
      }`}
      style={clipSm}
    >
      <div className="flex items-start justify-between gap-2 mb-2">
        <span className={`text-[9px] font-mono uppercase tracking-wider px-1.5 py-0.5 border ${accent.label}`}>
          {kindLabel}
        </span>
        <span className="text-[10px] font-mono text-gray-600 tabular-nums">{s.id}</span>
      </div>
      <div className={`text-sm font-mono font-semibold text-white leading-tight line-clamp-2 mb-2 min-h-[2.5rem] ${accent.name}`}>
        {s.name}
      </div>
      {s.aliases.length > 0 && (
        <div className="text-[10px] font-mono text-gray-500 mb-2 truncate" title={s.aliases.join(', ')}>
          aka {s.aliases.slice(0, 2).join(' · ')}
          {s.aliases.length > 2 && ` +${s.aliases.length - 2}`}
        </div>
      )}
      <div className="pt-2 border-t border-void-700 space-y-2">
        <CoverageMeter
          covered={s.covered_technique_count}
          total={s.technique_count}
          accent={accent.bar}
        />
        <div className="flex items-center justify-between gap-2">
          <span className={`text-[10px] font-mono tabular-nums ${hasRules ? 'text-white' : 'text-gray-600'}`}>
            <span className="font-semibold">{s.our_rule_count}</span>
            <span className="text-gray-600 ml-1">exact-tag rules</span>
          </span>
          <SourceDots sources={s.sources_with_coverage} />
        </div>
      </div>
    </Link>
  );
}

type Tab = 'groups' | 'software';

export function Actors() {
  const { data, isLoading, error } = useActors();
  const [tab, setTab] = useState<Tab>('groups');
  const [query, setQuery] = useState('');
  const [coverageOnly, setCoverageOnly] = useState(false);

  const filtered = useMemo(() => {
    if (!data) return { groups: [] as ActorListGroup[], software: [] as ActorListSoftware[] };
    const q = query.trim().toLowerCase();
    const bucket = (group: boolean) => (item: ActorListGroup | ActorListSoftware) => {
      if (coverageOnly && item.our_rule_count === 0) return false;
      if (!q) return true;
      const hay = [
        item.name,
        item.id,
        ...(group ? (item as ActorListGroup).aliases : (item as ActorListSoftware).aliases),
      ]
        .join(' ')
        .toLowerCase();
      return hay.includes(q);
    };
    return {
      groups: data.groups.filter(bucket(true)) as ActorListGroup[],
      software: data.software.filter(bucket(false)) as ActorListSoftware[],
    };
  }, [data, query, coverageOnly]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">
          Threat Actors
        </h1>
        <p className="text-xs text-gray-500 mt-1 font-mono">
          the full MITRE ATT&amp;CK catalog with our detection coverage overlaid — click any entry to see what we cover and what we don&apos;t
        </p>
      </div>

      {/* Hero counts + search + coverage-only toggle */}
      <div className="bg-gradient-to-r from-breach-500/10 via-orange-500/5 to-transparent border border-breach-500/30 px-5 py-4" style={clipMd}>
        <div className="flex items-end justify-between gap-4 flex-wrap">
          <div className="flex items-baseline gap-6 flex-wrap">
            <div>
              <div className="text-[10px] font-mono text-breach-400 uppercase tracking-[0.2em] mb-1">Actors</div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-display font-bold text-white tabular-nums">
                  {data?.total_groups ?? '—'}
                </span>
                <span className="text-[10px] font-mono text-gray-500">
                  ({data?.groups_with_coverage ?? 0} with rules)
                </span>
              </div>
            </div>
            <div>
              <div className="text-[10px] font-mono text-cyan-400 uppercase tracking-[0.2em] mb-1">Software + tools</div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-display font-bold text-white tabular-nums">
                  {data?.total_software ?? '—'}
                </span>
                <span className="text-[10px] font-mono text-gray-500">
                  ({data?.software_with_coverage ?? 0} with rules)
                </span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-3 flex-wrap">
            <label className="flex items-center gap-2 text-[10px] font-mono uppercase tracking-wider text-gray-400 cursor-pointer">
              <input
                type="checkbox"
                checked={coverageOnly}
                onChange={(e) => setCoverageOnly(e.target.checked)}
                className="accent-matrix-500"
              />
              hide entries with no rules
            </label>
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
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
          const count = t === 'groups' ? filtered.groups.length : filtered.software.length;
          return (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-4 py-2 text-xs font-display font-semibold uppercase tracking-wider border-b-2 -mb-[1px] transition-colors ${
                active
                  ? t === 'groups'
                    ? 'text-breach-400 border-breach-500'
                    : 'text-cyan-400 border-cyan-500'
                  : 'text-gray-500 border-transparent hover:text-white'
              }`}
            >
              {t === 'groups' ? 'Actors' : 'Software'}
              <span className="ml-2 text-[10px] font-mono text-gray-600 tabular-nums">{count}</span>
            </button>
          );
        })}
      </div>

      {/* Grid */}
      {isLoading && (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-2">
          {[...Array(15)].map((_, i) => (
            <div key={i} className="h-40 bg-void-800 animate-pulse" style={clipSm} />
          ))}
        </div>
      )}
      {error && (
        <div className="text-xs font-mono text-breach-400 py-4">Failed to load actors.</div>
      )}
      {data && tab === 'groups' && (
        filtered.groups.length === 0 ? (
          <div className="text-center py-12 text-gray-500 font-mono text-xs">
            {query ? 'no actors match this filter' : coverageOnly ? 'no actors with rule coverage' : 'no actors loaded'}
          </div>
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-2">
            {filtered.groups.map((g) => <GroupCard key={g.id} g={g} />)}
          </div>
        )
      )}
      {data && tab === 'software' && (
        filtered.software.length === 0 ? (
          <div className="text-center py-12 text-gray-500 font-mono text-xs">
            {query ? 'no software matches this filter' : coverageOnly ? 'no software with rule coverage' : 'no software loaded'}
          </div>
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-2">
            {filtered.software.map((s) => <SoftwareCard key={s.id} s={s} />)}
          </div>
        )
      )}
    </div>
  );
}
