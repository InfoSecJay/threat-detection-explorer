/**
 * Threat Actors + Software index — the "wanted board" view. Two tabs:
 * Groups (breach accent) and Software (split malware/tool). Cards are
 * dense, ordered by rule count, and deep-link to the actor detail page.
 *
 * Data scope is intentionally what our corpus already covers via
 * `mitre_groups` / `mitre_software` (Sigma + LOLRMM tag extraction).
 * A future page enhancement will overlay the full ATT&CK actor
 * catalog with gap-analysis; that lives in the roadmap.
 */

import { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useActors } from '../hooks/useActors';
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

function GroupCard({ g }: { g: ActorListGroup }) {
  const isKnown = g.name !== g.id;
  return (
    <Link
      to={`/actors/${g.id}`}
      className="group block bg-void-850 border border-void-700 hover:border-breach-500/50 p-3 transition-colors"
      style={clipSm}
      title={g.aliases.length ? `${g.name} · aka ${g.aliases.join(', ')}` : g.name}
    >
      <div className="flex items-start justify-between gap-2 mb-2">
        <span className="text-[9px] font-mono uppercase tracking-wider px-1.5 py-0.5 border bg-breach-500/10 text-breach-400 border-breach-500/30">
          ACTOR
        </span>
        <span className="text-[10px] font-mono text-gray-600 tabular-nums">{g.id}</span>
      </div>
      <div className={`text-sm font-mono font-semibold leading-tight line-clamp-2 mb-2 min-h-[2.5rem] ${isKnown ? 'text-white group-hover:text-breach-300' : 'text-gray-500 italic'}`}>
        {g.name}
      </div>
      {g.aliases.length > 0 && (
        <div className="text-[10px] font-mono text-gray-500 mb-2 truncate" title={g.aliases.join(', ')}>
          aka {g.aliases.slice(0, 2).join(' · ')}
          {g.aliases.length > 2 && ` +${g.aliases.length - 2}`}
        </div>
      )}
      <div className="flex items-center justify-between gap-2 pt-2 border-t border-void-700">
        <div className="flex gap-3 text-[10px] font-mono">
          <span className="text-white">
            <span className="tabular-nums font-semibold">{g.rule_count}</span>
            <span className="text-gray-600 ml-1">rules</span>
          </span>
          <span className="text-white">
            <span className="tabular-nums font-semibold">{g.technique_count}</span>
            <span className="text-gray-600 ml-1">tech</span>
          </span>
        </div>
        <SourceDots sources={g.sources} />
      </div>
    </Link>
  );
}

function SoftwareCard({ s }: { s: ActorListSoftware }) {
  const isKnown = s.name !== s.id;
  const kindLabel = s.type === 'tool' ? 'TOOL' : s.type === 'malware' ? 'MALWARE' : 'SW';
  const accent =
    s.type === 'malware'
      ? { label: 'bg-orange-500/10 text-orange-400 border-orange-500/30', border: 'hover:border-orange-500/50', name: 'group-hover:text-orange-300' }
      : { label: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30', border: 'hover:border-cyan-500/50', name: 'group-hover:text-cyan-300' };

  return (
    <Link
      to={`/actors/${s.id}`}
      className={`group block bg-void-850 border border-void-700 ${accent.border} p-3 transition-colors`}
      style={clipSm}
      title={s.name}
    >
      <div className="flex items-start justify-between gap-2 mb-2">
        <span className={`text-[9px] font-mono uppercase tracking-wider px-1.5 py-0.5 border ${accent.label}`}>
          {kindLabel}
        </span>
        <span className="text-[10px] font-mono text-gray-600 tabular-nums">{s.id}</span>
      </div>
      <div className={`text-sm font-mono font-semibold leading-tight line-clamp-2 mb-2 min-h-[2.5rem] ${isKnown ? `text-white ${accent.name}` : 'text-gray-500 italic'}`}>
        {s.name}
      </div>
      <div className="flex items-center justify-between gap-2 pt-2 border-t border-void-700 mt-auto">
        <div className="flex gap-3 text-[10px] font-mono">
          <span className="text-white">
            <span className="tabular-nums font-semibold">{s.rule_count}</span>
            <span className="text-gray-600 ml-1">rules</span>
          </span>
          <span className="text-white">
            <span className="tabular-nums font-semibold">{s.technique_count}</span>
            <span className="text-gray-600 ml-1">tech</span>
          </span>
        </div>
        <SourceDots sources={s.sources} />
      </div>
    </Link>
  );
}

type Tab = 'groups' | 'software';

export function Actors() {
  const { data, isLoading, error } = useActors();
  const [tab, setTab] = useState<Tab>('groups');
  const [query, setQuery] = useState('');

  const filtered = useMemo(() => {
    if (!data) return { groups: [], software: [] };
    const q = query.trim().toLowerCase();
    if (!q) return data;
    const match = (name: string, id: string, extras: string[]) => {
      const hay = [name, id, ...extras].join(' ').toLowerCase();
      return hay.includes(q);
    };
    return {
      groups: data.groups.filter((g) => match(g.name, g.id, g.aliases)),
      software: data.software.filter((s) => match(s.name, s.id, [])),
    };
  }, [data, query]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">
          Threat Actors
        </h1>
        <p className="text-xs text-gray-500 mt-1 font-mono">
          named adversaries + software our detection corpus covers, resolved from vendor attack.g / attack.s tags
        </p>
      </div>

      {/* Hero counts + search */}
      <div className="bg-gradient-to-r from-breach-500/10 via-orange-500/5 to-transparent border border-breach-500/30 px-5 py-4" style={clipMd}>
        <div className="flex items-end justify-between gap-4 flex-wrap">
          <div className="flex items-baseline gap-6 flex-wrap">
            <div>
              <div className="text-[10px] font-mono text-breach-400 uppercase tracking-[0.2em] mb-1">Actors covered</div>
              <span className="text-3xl font-display font-bold text-white tabular-nums">
                {data?.groups.length ?? '—'}
              </span>
            </div>
            <div>
              <div className="text-[10px] font-mono text-cyan-400 uppercase tracking-[0.2em] mb-1">Software + tools</div>
              <span className="text-3xl font-display font-bold text-white tabular-nums">
                {data?.software.length ?? '—'}
              </span>
            </div>
          </div>
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="filter: apt29, cobalt strike, g0016…"
            className="bg-void-900 border border-void-700 text-sm text-white font-mono px-3 py-2 min-w-[280px] focus:outline-none focus:border-matrix-500/50 placeholder:text-gray-600"
            style={clipSm}
            aria-label="Filter actors and software by name, alias, or ID"
          />
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
          {[...Array(10)].map((_, i) => (
            <div key={i} className="h-32 bg-void-800 animate-pulse" style={clipSm} />
          ))}
        </div>
      )}
      {error && (
        <div className="text-xs font-mono text-breach-400 py-4">Failed to load actors.</div>
      )}
      {data && tab === 'groups' && (
        filtered.groups.length === 0 ? (
          <div className="text-center py-12 text-gray-500 font-mono text-xs">
            {query ? 'no actors match this filter' : 'no actor coverage yet — run ingest to populate from attack.g tags'}
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
            {query ? 'no software matches this filter' : 'no software coverage yet — run ingest to populate from attack.s tags'}
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
