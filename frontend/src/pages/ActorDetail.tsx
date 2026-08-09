/**
 * Threat Actor / Software detail — MITRE-parity metadata + our
 * coverage. Layout mirrors what attack.mitre.org renders per group
 * or software (description, aliases, references, techniques,
 * cross-references) with our rule-coverage overlaid on top.
 *
 * The value-add over the MITRE site is the match-mode toggle: users
 * pick whether to see rules that (exact) explicitly tag the actor,
 * (coverage) tag any technique the actor is known to use, or
 * (mention) reference the actor by name in title/description/tags.
 * All three counts are always displayed so the toggle is informative
 * on its own.
 */

import { useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { useActor } from '../hooks/useActors';
import { sourceTheme as sourceConfig, clipSm, clipMd } from '../constants/style';
import { severityColor } from './intel/lib';
import type { ActorMatchMode } from '../services/api';

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

/** Renders long MITRE description text with basic paragraph splits. */
function MitreDescription({ text }: { text: string }) {
  if (!text) return null;
  const paragraphs = text.split(/\n{2,}/).map((p) => p.trim()).filter(Boolean);
  return (
    <div className="prose prose-invert prose-sm max-w-none space-y-2">
      {paragraphs.map((p, i) => (
        <p key={i} className="text-sm text-gray-300 leading-relaxed">
          {p}
        </p>
      ))}
    </div>
  );
}

export function ActorDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [matchMode, setMatchMode] = useState<ActorMatchMode>('exact');
  const { data: actor, isLoading, error } = useActor(id, matchMode);

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
            {actor.aliases.length > 0 && (
              <div className="text-xs font-mono text-gray-400">
                aka <span className="text-gray-200">{actor.aliases.join(' · ')}</span>
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
              <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider mb-1">Techniques covered</div>
              <div className="text-3xl font-display font-bold text-white tabular-nums">
                {actor.covered_technique_count}
                <span className="text-lg text-gray-500"> / {actor.technique_count}</span>
              </div>
              <div className="text-[10px] font-mono text-gray-500 mt-1">{coveredPct}% coverage</div>
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

      {/* Description */}
      {actor.description && (
        <section>
          <SectionHead title="About" subtitle="from mitre att&ck" />
          <MitreDescription text={actor.description} />
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
          <SectionHead title="Associated software" subtitle="malware + tools this actor is known to use" />
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
                  ? 'Rules explicitly tagged with this ATT&CK ID'
                  : m === 'coverage'
                    ? 'Rules tagged with any technique this actor is known to use'
                    : 'Rules whose title/description/tags contain the actor name or an alias'
              }
            >
              {m} <span className="ml-1 tabular-nums text-gray-500">{actor.match_counts[m]}</span>
            </button>
          ))}
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
              className="ml-auto text-[10px] font-mono text-matrix-500 hover:text-matrix-400 uppercase tracking-wider border border-matrix-500/30 hover:border-matrix-500/60 px-2 py-1 transition-colors"
              style={clipSm}
            >
              [ open in catalog ]
            </button>
          )}
        </div>
        {actor.rules.length === 0 ? (
          <div className="text-center py-8 text-gray-500 font-mono text-xs">
            no rules match this actor under the <span className="text-gray-300">{matchMode}</span> mode
          </div>
        ) : (
          <div className="overflow-x-auto border border-void-700" style={clipSm}>
            <table className="w-full text-xs font-mono">
              <thead className="bg-void-900 text-gray-500 uppercase tracking-wider">
                <tr>
                  <th className="px-3 py-2 text-left font-display font-semibold">Source</th>
                  <th className="px-3 py-2 text-left font-display font-semibold">Sev</th>
                  <th className="px-3 py-2 text-left font-display font-semibold">Title</th>
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

      {/* External references from MITRE */}
      {actor.references.length > 0 && (
        <section>
          <SectionHead title="References" subtitle="external sources cited by mitre" />
          <ul className="space-y-1.5">
            {actor.references.map((r, i) => (
              <li key={i} className="text-xs">
                <a
                  href={r.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-matrix-500 hover:text-matrix-400 break-all"
                >
                  {r.source_name || r.url}
                </a>
                {r.description && (
                  <span className="text-gray-500 ml-2">— {r.description}</span>
                )}
              </li>
            ))}
          </ul>
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
