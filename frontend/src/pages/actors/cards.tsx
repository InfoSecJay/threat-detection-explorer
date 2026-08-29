// Extracted from pages/Actors.tsx (#23). Behaviour unchanged.
import { Link } from 'react-router-dom';
import { stripMitreMarkup } from '../../components/MitreText';
import { sourceTheme as sourceConfig, clipSm } from '../../constants/style';
import { countryFlag, countryName, coverageBarClass, coverageTextClass, GAP_ACCENT_THRESHOLD, MOTIVATION_STYLE } from '../../utils/actorDisplay';
import type { ActorsQueryItem } from '../../services/api';
import { TYPE_TOOLTIP } from './constants';


export function SourceDots({ sources }: { sources: string[] }) {
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

export function ContextChips({
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

export function GapStats({ item, isGroup }: { item: ActorsQueryItem; isGroup: boolean }) {
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

export function EntityCard({
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

// ── Filters ────────────────────────────────────────────────────────

/** Multi-select facet dropdown with result counts. */
