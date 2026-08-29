/** Actor / software hero: kind, name, origin + motivations + sectors,
 * aliases, and the three headline numbers (gaps, weighted coverage,
 * rule count under the active match mode). */

import { Link } from 'react-router-dom';
import { countryFlag, countryName, MOTIVATION_STYLE } from '../../../utils/actorDisplay';
import { clipMd } from '../../../constants/style';
import type { ActorMatchMode } from '../../../services/api';
import type { ActorDetail as ActorDetailData } from '../../../services/api';

export function ActorHero({ actor, matchMode }: { actor: ActorDetailData; matchMode: ActorMatchMode }) {
  const isGroup = actor.kind === 'group';
  const accentText = isGroup
    ? 'text-breach-400'
    : actor.type === 'malware'
      ? 'text-orange-400'
      : 'text-cyan-400';
  const accentBorder = isGroup
    ? 'border-breach-500/30'
    : actor.type === 'malware'
      ? 'border-orange-500/30'
      : 'border-cyan-500/30';
  const accentGrad = isGroup
    ? 'from-breach-500/10 via-orange-500/5'
    : actor.type === 'malware'
      ? 'from-orange-500/10 via-red-500/5'
      : 'from-cyan-500/10 via-matrix-500/5';
  const kindLabel = isGroup
    ? 'ACTOR'
    : actor.type === 'malware'
      ? 'MALWARE'
      : actor.type === 'tool'
        ? 'TOOL'
        : 'SOFTWARE';

  const coveredPct = actor.technique_count > 0
    ? Math.round((actor.covered_technique_count / actor.technique_count) * 100)
    : 0;
  const weightedPct = actor.weighted_coverage === null
    ? null
    : Math.round(actor.weighted_coverage * 100);

  return (
  <div
    className={`bg-gradient-to-r ${accentGrad} to-transparent border ${accentBorder} px-6 py-5`}
    style={clipMd}
  >
    <div className="flex items-start justify-between gap-4 flex-wrap">
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-3 mb-2">
          <span className={`text-[10px] font-mono uppercase tracking-[0.2em] ${accentText}`}>
            {kindLabel}
          </span>
          <span className="text-[10px] font-mono text-gray-600 tabular-nums">{actor.id}</span>
          {actor.deprecated && (
            <span className="text-[10px] font-mono uppercase tracking-wider px-1.5 py-0.5 border border-gray-600 text-gray-500">
              DEPRECATED
            </span>
          )}
        </div>
        <h1 className="text-3xl font-display font-bold text-white tracking-wider mb-2">
          {actor.name}
        </h1>
        {(actor.origin_country || (actor.motivations?.length ?? 0) > 0 || (actor.target_sectors?.length ?? 0) > 0) && (
          <div className="flex items-center gap-1.5 mb-2 flex-wrap">
            {actor.origin_country && (
              <span
                className="text-[10px] font-mono text-gray-300 border border-void-700 bg-void-900/60 px-2 py-0.5"
                title={`Suspected origin: ${countryName(actor.origin_country)} (MISP galaxy)`}
              >
                {countryFlag(actor.origin_country)} {countryName(actor.origin_country)}
              </span>
            )}
            {(actor.motivations ?? []).map((m) => (
              <span
                key={m}
                className={`text-[10px] font-mono uppercase tracking-wider border px-2 py-0.5 ${MOTIVATION_STYLE[m] ?? MOTIVATION_STYLE.unknown}`}
              >
                {m}
              </span>
            ))}
            {(actor.target_sectors ?? []).map((s) => (
              <Link
                key={s}
                to={`/actors?sector=${encodeURIComponent(s)}`}
                className="text-[10px] font-mono text-gray-400 border border-void-700 bg-void-900/60 px-2 py-0.5 hover:text-matrix-400 hover:border-matrix-500/40 transition-colors"
                title={`All actors targeting ${s}`}
              >
                {s}
              </Link>
            ))}
          </div>
        )}
        {actor.aliases.length > 0 && (
          <div className="text-xs font-mono text-gray-400">
            aka <span className="text-gray-200">{actor.aliases.join(' · ')}</span>
          </div>
        )}
        {(actor.target_regions?.length ?? 0) > 0 && (
          <div
            className="text-xs font-mono text-gray-500 mt-1"
            title={(actor.target_countries ?? []).join(', ')}
          >
            targets: <span className="text-gray-300">{(actor.target_regions ?? []).join(' · ')}</span>
          </div>
        )}
        {actor.platforms && actor.platforms.length > 0 && (
          <div className="text-xs font-mono text-gray-500 mt-1">
            platforms: <span className="text-gray-300">{actor.platforms.join(', ')}</span>
          </div>
        )}
        <a
          href={actor.mitre_url}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1 mt-3 text-xs font-mono text-matrix-500 hover:text-matrix-400 transition-colors"
        >
          VIEW_ON_ATT&amp;CK ↗
        </a>
      </div>
      <div className="flex gap-6 shrink-0">
        <div>
          <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider mb-1">Detection gaps</div>
          <div className={`text-3xl font-display font-bold tabular-nums ${actor.gap_count > 0 ? 'text-white' : 'text-gray-500'}`}>
            {actor.gap_count}
            <span className="text-lg text-gray-500"> / {actor.technique_count}</span>
          </div>
          <div className="text-[10px] font-mono text-gray-500 mt-1">
            techniques with no rules
          </div>
        </div>
        <div>
          <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider mb-1">Weighted coverage</div>
          <div className="text-3xl font-display font-bold text-white tabular-nums">
            {weightedPct === null ? '—' : `${weightedPct}%`}
          </div>
          <div
            className="text-[10px] font-mono text-gray-500 mt-1"
            title="Raw coverage counts every technique equally; the weighted score discounts TTPs nearly every actor uses"
          >
            raw: {actor.covered_technique_count}/{actor.technique_count} ({coveredPct}%)
          </div>
        </div>
        <div>
          <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider mb-1">Rules ({matchMode})</div>
          <div className="text-3xl font-display font-bold text-white tabular-nums">
            {actor.rules.length}
            {actor.match_counts[matchMode] > actor.rules.length && (
              <span className="text-sm text-gray-500 ml-1">of {actor.match_counts[matchMode]}</span>
            )}
          </div>
        </div>
      </div>
    </div>
  </div>
  );
}
