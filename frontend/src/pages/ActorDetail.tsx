/**
 * Threat Actor / Software detail — MITRE-parity metadata + our
 * coverage. Layout mirrors what attack.mitre.org renders per group
 * or software (description, aliases, references, techniques,
 * cross-references) with our rule-coverage overlaid on top.
 *
 * The value-add over the MITRE site is the match-mode toggle. Modes
 * are DISJOINT tiers of attribution strength (issue #34): DEDICATED
 * (wire value `exact`) = rules built for the actor (ID tag, analytic
 * story named after it, or its name in the title); COVERAGE = rules
 * tagging any technique it uses; REFERENCED (wire value `mention`) =
 * rules that only cite it in prose/tags/references. All three counts
 * are always displayed, and each dedicated/referenced rule carries
 * match-reason chips saying why it counted.
 */

import { useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { useActor } from '../hooks/useActors';
import { actorsApi } from '../services/api';
import { MitreText, MitreReferences, resolveCitations } from '../components/MitreText';
import { useAttackRouteResolver } from '../hooks/useAttackRoutes';
import { countryFlag, countryName, MOTIVATION_STYLE } from '../utils/actorDisplay';
import { sourceTheme as sourceConfig, clipSm, clipMd } from '../constants/style';
import { ALL_SOURCES } from '../constants/sources';
import { severityColor } from './intel/lib';
import type { ActorMatchMode } from '../services/api';

// Wire values stay exact/coverage/mention (URL + API stability);
// the UI names the disjoint tiers for what they are (issue #34).
const MATCH_MODE_LABEL: Record<ActorMatchMode, string> = {
  exact: 'dedicated',
  coverage: 'coverage',
  mention: 'referenced',
};

// Chip styling per match reason: dedicated signals get the matrix
// accent, referenced signals stay neutral.
const REASON_STYLE: Record<string, string> = {
  'id-tag': 'text-matrix-400 border-matrix-500/40',
  story: 'text-matrix-400 border-matrix-500/40',
  title: 'text-matrix-400 border-matrix-500/40',
  description: 'text-gray-400 border-void-600',
  tag: 'text-gray-400 border-void-600',
  'use-case': 'text-gray-400 border-void-600',
  reference: 'text-gray-400 border-void-600',
};

function SeverityBadge({ severity }: { severity: string }) {
  const cls = severityColor[severity] || severityColor.unknown;
  return (
    <span
      className={`px-1.5 py-0.5 text-[9px] font-mono uppercase tracking-wider border tabular-nums ${cls}`}
    >
      {severity.slice(0, 4)}
    </span>
  );
}

export function ActorDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [matchMode, setMatchMode] = useState<ActorMatchMode>('exact');
  const [exporting, setExporting] = useState(false);
  const { data: actor, isLoading, error } = useActor(id, matchMode);
  const resolveRoute = useAttackRouteResolver();

  const exportLayer = async () => {
    if (!actor || exporting) return;
    setExporting(true);
    try {
      await actorsApi.downloadNavigatorLayer(actor.id, matchMode);
    } finally {
      setExporting(false);
    }
  };

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="h-32 bg-void-800 animate-pulse" style={clipMd} />
        <div className="h-64 bg-void-800 animate-pulse" style={clipMd} />
      </div>
    );
  }
  if (error || !actor) {
    return (
      <div className="text-center py-16">
        <div className="text-xs font-mono text-breach-400 mb-2">FAILED_TO_LOAD_ACTOR</div>
        <Link to="/actors" className="text-xs font-mono text-matrix-500 hover:text-matrix-400">
          &larr; back to Threat Actors
        </Link>
      </div>
    );
  }

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
    <div className="space-y-6">
      {/* Breadcrumb */}
      <div className="text-xs font-mono text-gray-500">
        <Link to="/actors" className="hover:text-matrix-500 transition-colors">
          &larr; Threat Actors
        </Link>
      </div>

      {/* Hero */}
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

      {/* Coverage by source (#18): which vendor covers this actor and which does not */}
      {actor.technique_count > 0 && (
        <section>
          <SectionHead
            title="Coverage by source"
            subtitle={`of ${actor.technique_count} techniques, per vendor · sources with no rules are the gap`}
          />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-1.5">
            {ALL_SOURCES.map((src) => {
              const cov = actor.coverage_by_source?.[src];
              const covered = cov?.techniques_covered ?? 0;
              const pct = actor.technique_count ? Math.round((covered / actor.technique_count) * 100) : 0;
              const cfg = sourceConfig[src];
              return (
                <Link
                  key={src}
                  to={`/detections?sources=${src}&mitre_techniques=${actor.techniques.map((t) => t.technique_id).join(',')}`}
                  className={`relative block border px-3 py-1.5 transition-colors ${
                    covered > 0 ? 'bg-void-850 border-void-700 hover:border-matrix-500/50' : 'bg-void-900/60 border-void-800 hover:border-void-600'
                  }`}
                  style={clipSm}
                  title={covered > 0 ? `${cfg?.name || src}: ${cov!.rule_count} rule(s) across ${covered} technique(s) -- open in catalog` : `${cfg?.name || src}: no rules for any of this actor's techniques`}
                  data-testid={`cov-${src}`}
                >
                  <div className={`absolute inset-y-0 left-0 ${cfg?.bg || 'bg-matrix-500/20'}`} style={{ width: `${pct}%` }} />
                  <div className="relative flex items-center gap-2 text-xs">
                    <span className={`w-2 h-2 rounded-full shrink-0 ${cfg?.dot || 'bg-gray-500'}`} />
                    <span className={`font-mono uppercase tracking-wider shrink-0 ${covered > 0 ? cfg?.text || 'text-gray-300' : 'text-gray-600'}`}>
                      {cfg?.name || src}
                    </span>
                    <span className="flex-1" />
                    <span className={`font-mono tabular-nums ${covered > 0 ? 'text-white' : 'text-gray-700'}`}>
                      {covered > 0 ? `${covered}/${actor.technique_count} · ${cov!.rule_count} rules` : 'gap'}
                    </span>
                  </div>
                </Link>
              );
            })}
          </div>
        </section>
      )}

      {/* Description + numbered references */}
      {actor.description && (
        <section>
          <SectionHead title="About" subtitle="from mitre att&ck" />
          <MitreText
            text={actor.description}
            references={actor.references}
            resolveRoute={resolveRoute}
          />
        </section>
      )}

      {/* Techniques used — with coverage indicator */}
      <section>
        <SectionHead
          title="Techniques used"
          subtitle={`${actor.covered_technique_count} of ${actor.technique_count} have rules in our catalog · click to open in mitre browser`}
        />
        {actor.techniques.length === 0 ? (
          <div className="text-center py-6 text-gray-500 font-mono text-xs">
            No techniques associated in MITRE for this {isGroup ? 'actor' : 'software'}.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
            {actor.techniques.map((t) => (
              <Link
                key={t.technique_id}
                to={`/mitre/${t.technique_id}`}
                className={`group block border px-3 py-2 transition-colors ${
                  t.has_rules
                    ? 'bg-void-850 border-void-700 hover:border-matrix-500/50'
                    : 'bg-void-900/60 border-void-800 hover:border-void-600'
                }`}
                style={clipSm}
                title={t.has_rules ? `${t.rule_count} rule(s) in our catalog` : 'Gap: no rules in our catalog for this technique'}
              >
                <div className="flex items-center gap-2">
                  <span
                    className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                      t.has_rules ? 'bg-matrix-500' : 'bg-gray-700'
                    }`}
                    aria-hidden="true"
                  />
                  <span
                    className={`text-xs font-mono tabular-nums shrink-0 ${
                      t.has_rules ? 'text-matrix-500' : 'text-gray-600'
                    }`}
                  >
                    {t.technique_id}
                  </span>
                  <span
                    className={`text-xs truncate flex-1 min-w-0 ${
                      t.has_rules ? 'text-gray-300 group-hover:text-white' : 'text-gray-500 italic'
                    }`}
                  >
                    {t.technique_name || 'Unknown technique'}
                  </span>
                  <span
                    className={`text-xs font-mono tabular-nums shrink-0 ${
                      t.has_rules ? 'text-white' : 'text-gray-700'
                    }`}
                  >
                    {t.has_rules ? t.rule_count : 'gap'}
                  </span>
                </div>
              </Link>
            ))}
          </div>
        )}
      </section>

      {/* Associated software / groups */}
      {isGroup && actor.associated_software && actor.associated_software.length > 0 && (
        <section>
          <div className="flex items-center justify-between flex-wrap gap-2">
            <SectionHead title="Associated software" subtitle="malware + tools this actor is known to use" />
            <Link
              to={`/actors?tab=software&used_by_actor=${actor.id}`}
              className="text-[10px] font-mono text-matrix-500 hover:text-matrix-400 uppercase tracking-wider border border-matrix-500/30 hover:border-matrix-500/60 px-2 py-1 transition-colors mb-3"
            >
              [ filter software tab ]
            </Link>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-2">
            {actor.associated_software.map((s) => (
              <Link
                key={s.id}
                to={`/actors/${s.id}`}
                className={`block border px-3 py-2 transition-colors ${
                  s.has_rules
                    ? 'bg-void-850 border-void-700 hover:border-cyan-500/50'
                    : 'bg-void-900/60 border-void-800 hover:border-void-600'
                }`}
                style={clipSm}
              >
                <div className="flex items-center gap-1.5 mb-1">
                  <span className={`text-[9px] font-mono uppercase tracking-wider ${s.type === 'malware' ? 'text-orange-400' : 'text-cyan-400'}`}>
                    {s.type}
                  </span>
                  <span className="text-[10px] font-mono text-gray-600 ml-auto tabular-nums">{s.id}</span>
                </div>
                <div className={`text-xs font-mono truncate ${s.has_rules ? 'text-white' : 'text-gray-500'}`}>{s.name}</div>
                <div className={`text-[10px] font-mono mt-1 ${s.has_rules ? 'text-gray-400' : 'text-gray-700'}`}>
                  {s.has_rules ? `${s.rule_count} rules` : 'no rules'}
                </div>
              </Link>
            ))}
          </div>
        </section>
      )}

      {!isGroup && actor.associated_groups && actor.associated_groups.length > 0 && (
        <section>
          <SectionHead title="Used by" subtitle="threat groups known to use this software" />
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-2">
            {actor.associated_groups.map((g) => (
              <Link
                key={g.id}
                to={`/actors/${g.id}`}
                className={`block border px-3 py-2 transition-colors ${
                  g.has_rules
                    ? 'bg-void-850 border-void-700 hover:border-breach-500/50'
                    : 'bg-void-900/60 border-void-800 hover:border-void-600'
                }`}
                style={clipSm}
                title={g.aliases.length ? `aka ${g.aliases.join(', ')}` : g.name}
              >
                <div className="flex items-center gap-1.5 mb-1">
                  <span className="text-[9px] font-mono uppercase tracking-wider text-breach-400">ACTOR</span>
                  <span className="text-[10px] font-mono text-gray-600 ml-auto tabular-nums">{g.id}</span>
                </div>
                <div className={`text-xs font-mono truncate ${g.has_rules ? 'text-white' : 'text-gray-500'}`}>{g.name}</div>
                <div className={`text-[10px] font-mono mt-1 ${g.has_rules ? 'text-gray-400' : 'text-gray-700'}`}>
                  {g.has_rules ? `${g.rule_count} rules` : 'no rules'}
                </div>
              </Link>
            ))}
          </div>
        </section>
      )}

      {/* Rules — with match-mode toggle */}
      <section>
        <SectionHead
          title="Rules"
          subtitle="detection rules from our catalog · pick a match mode to change which count"
        />
        <div className="flex items-center gap-2 mb-3 flex-wrap">
          <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider mr-1">match mode:</span>
          {(['exact', 'coverage', 'mention'] as ActorMatchMode[]).map((m) => (
            <button
              key={m}
              role="radio"
              aria-checked={matchMode === m}
              onClick={() => setMatchMode(m)}
              className={`px-2.5 py-1 text-[10px] font-mono uppercase tracking-wider border transition-colors ${
                matchMode === m
                  ? 'bg-matrix-500/20 text-matrix-400 border-matrix-500/40'
                  : 'bg-void-900 text-gray-500 border-void-700 hover:text-white'
              }`}
              title={
                m === 'exact'
                  ? 'Rules built FOR this actor: ATT&CK ID tag, analytic story named after it, or its name in the rule title'
                  : m === 'coverage'
                    ? 'Rules tagged with any technique this actor is known to use'
                    : 'Rules that only cite the actor: name/alias in description, tags, use cases, or reference URLs (excludes dedicated rules)'
              }
            >
              {MATCH_MODE_LABEL[m]} <span className="ml-1 tabular-nums text-gray-500">{actor.match_counts[m]}</span>
            </button>
          ))}
          <button
            onClick={exportLayer}
            disabled={exporting}
            className="ml-auto text-[10px] font-mono text-cyan-400 hover:text-cyan-300 uppercase tracking-wider border border-cyan-500/30 hover:border-cyan-500/60 px-2 py-1 transition-colors disabled:opacity-50"
            style={clipSm}
            title={`Download an ATT&CK Navigator layer: one entry per technique, scored by ${matchMode}-mode rule count. Gaps stay visible at score 0.`}
          >
            {exporting ? '[ exporting… ]' : '[ export navigator layer ]'}
          </button>
          {actor.match_counts[matchMode] > 0 && (
            <button
              onClick={() => {
                const paramKey = isGroup ? 'mitre_groups' : 'mitre_software';
                const qs = matchMode === 'exact'
                  ? `${paramKey}=${actor.id}`
                  : matchMode === 'coverage'
                    ? `mitre_techniques=${actor.techniques.map((t) => t.technique_id).join(',')}`
                    : `q=${encodeURIComponent([actor.name, ...actor.aliases].map((n) => `"${n}"`).join(' OR '))}`;
                navigate(`/detections?${qs}`);
              }}
              className="text-[10px] font-mono text-matrix-500 hover:text-matrix-400 uppercase tracking-wider border border-matrix-500/30 hover:border-matrix-500/60 px-2 py-1 transition-colors"
              style={clipSm}
            >
              [ open in catalog ]
            </button>
          )}
        </div>
        {actor.rules.length === 0 ? (
          <div className="text-center py-8 text-gray-500 font-mono text-xs">
            no rules match this actor under the <span className="text-gray-300">{MATCH_MODE_LABEL[matchMode]}</span> mode
          </div>
        ) : (
          <div className="overflow-x-auto border border-void-700" style={clipSm}>
            <table className="w-full text-xs font-mono">
              <thead className="bg-void-900 text-gray-500 uppercase tracking-wider">
                <tr>
                  <th className="px-3 py-2 text-left font-display font-semibold">Source</th>
                  <th className="px-3 py-2 text-left font-display font-semibold">Sev</th>
                  <th className="px-3 py-2 text-left font-display font-semibold">Title</th>
                  {matchMode !== 'coverage' && (
                    <th className="px-3 py-2 text-left font-display font-semibold">Match</th>
                  )}
                  <th className="px-3 py-2 text-left font-display font-semibold">Techniques</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-void-800">
                {actor.rules.map((r) => {
                  const cfg = sourceConfig[r.source];
                  return (
                    <tr key={r.id} className="hover:bg-void-850 transition-colors">
                      <td className="px-3 py-2 whitespace-nowrap">
                        <span className={`px-1.5 py-0.5 text-[9px] uppercase tracking-wider border ${cfg?.bg || ''} ${cfg?.text || 'text-gray-400'} ${cfg?.border || 'border-void-700'}`}>
                          {cfg?.name || r.source}
                        </span>
                      </td>
                      <td className="px-3 py-2 whitespace-nowrap">
                        <SeverityBadge severity={r.severity} />
                      </td>
                      <td className="px-3 py-2">
                        <Link to={`/detections/${r.id}`} className="text-gray-200 hover:text-matrix-400 transition-colors">
                          {r.title}
                        </Link>
                      </td>
                      {matchMode !== 'coverage' && (
                        <td className="px-3 py-2 whitespace-nowrap">
                          <span className="inline-flex gap-1">
                            {(r.match_reasons ?? []).map((why) => (
                              <span
                                key={why}
                                className={`px-1.5 py-0.5 text-[9px] font-mono uppercase tracking-wider border ${REASON_STYLE[why] || 'text-gray-400 border-void-600'}`}
                                title={`Matched via ${why}`}
                              >
                                {why}
                              </span>
                            ))}
                          </span>
                        </td>
                      )}
                      <td className="px-3 py-2 text-gray-500 tabular-nums whitespace-nowrap">
                        {r.techniques.slice(0, 3).join(' · ')}
                        {r.techniques.length > 3 && ` +${r.techniques.length - 3}`}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* References — numbered to match the citation markers in the
          About text, uncited refs appended unnumbered */}
      {(actor.references.length > 0 ||
        resolveCitations(actor.description || '').length > 0) && (
        <section>
          <SectionHead title="References" subtitle="external sources cited by mitre" />
          <MitreReferences
            citations={resolveCitations(actor.description || '', actor.references)}
            references={actor.references}
          />
        </section>
      )}
    </div>
  );
}

function SectionHead({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div className="flex items-baseline gap-3 mb-3 flex-wrap">
      <span className="w-1 h-4 bg-matrix-500 shrink-0" aria-hidden="true" />
      <h2 className="text-base font-display font-bold text-white tracking-wider uppercase">
        {title}
      </h2>
      {subtitle && (
        <span className="text-[10px] text-gray-500 font-mono uppercase tracking-wider">
          // {subtitle}
        </span>
      )}
    </div>
  );
}
