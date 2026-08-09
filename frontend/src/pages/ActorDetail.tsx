/**
 * Actor / Software detail — metadata hero, technique-by-technique
 * coverage table, and a scrollable list of the rules that cite this
 * actor. `by_technique` uses the MITRE technique lookup to render
 * human-readable names alongside the T-IDs.
 */

import { useParams, Link, useNavigate } from 'react-router-dom';
import { useActor } from '../hooks/useActors';
import { useMitre } from '../contexts/MitreContext';
import { sourceTheme as sourceConfig, clipSm, clipMd } from '../constants/style';
import { severityColor } from './intel/lib';

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
  const { data: actor, isLoading, error } = useActor(id);
  const { getTechniqueName } = useMitre();

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="h-24 bg-void-800 animate-pulse" style={clipMd} />
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
          <div>
            <div className="flex items-center gap-3 mb-2">
              <span className={`text-[10px] font-mono uppercase tracking-[0.2em] ${accentText}`}>
                {kindLabel}
              </span>
              <span className="text-[10px] font-mono text-gray-600 tabular-nums">{actor.id}</span>
            </div>
            <h1 className="text-3xl font-display font-bold text-white tracking-wider mb-2">
              {actor.name}
            </h1>
            {isGroup && actor.aliases && actor.aliases.length > 0 && (
              <div className="text-xs font-mono text-gray-400">
                aka <span className="text-gray-200">{actor.aliases.join(' · ')}</span>
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
          <div className="flex gap-6">
            <div>
              <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider mb-1">Rules</div>
              <div className="text-3xl font-display font-bold text-white tabular-nums">{actor.rule_count}</div>
            </div>
            <div>
              <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider mb-1">Techniques</div>
              <div className="text-3xl font-display font-bold text-white tabular-nums">{actor.technique_count}</div>
            </div>
            <div>
              <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider mb-1">Sources</div>
              <div className="text-3xl font-display font-bold text-white tabular-nums">{actor.sources.length}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Filter shortcut */}
      <div className="flex items-center gap-3 flex-wrap">
        <button
          onClick={() =>
            navigate(
              `/detections?${isGroup ? 'mitre_groups' : 'mitre_software'}=${actor.id}`,
            )
          }
          className="text-xs font-mono text-matrix-500 hover:text-matrix-400 uppercase tracking-wider border border-matrix-500/30 hover:border-matrix-500/60 px-3 py-1.5 transition-colors"
          style={clipSm}
        >
          [ open all {actor.rule_count} rules in catalog ]
        </button>
        <div className="flex gap-1 items-center">
          <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">sources:</span>
          {actor.sources.map((src) => {
            const cfg = sourceConfig[src];
            return (
              <Link
                key={src}
                to={`/detections?sources=${src}&${isGroup ? 'mitre_groups' : 'mitre_software'}=${actor.id}`}
                className={`px-1.5 py-0.5 text-[10px] font-mono uppercase tracking-wider border transition-colors ${cfg?.bg || ''} ${cfg?.text || ''} ${cfg?.border || 'border-void-700'} hover:opacity-80`}
              >
                {cfg?.name || src}
              </Link>
            );
          })}
        </div>
      </div>

      {/* Techniques covered */}
      <section>
        <div className="flex items-baseline gap-3 mb-3">
          <span className="w-1 h-4 bg-matrix-500" aria-hidden="true" />
          <h2 className="text-base font-display font-bold text-white tracking-wider uppercase">
            Techniques covered
          </h2>
          <span className="text-[10px] text-gray-500 font-mono uppercase tracking-wider">
            // rules that map this {isGroup ? 'actor' : 'software'} to specific MITRE techniques
          </span>
        </div>
        {actor.by_technique.length === 0 ? (
          <div className="text-center py-8 text-gray-500 font-mono text-xs">
            no rules tag techniques alongside this {isGroup ? 'actor' : 'software'}
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
            {actor.by_technique.map((t) => {
              const name = getTechniqueName(t.technique_id);
              return (
                <Link
                  key={t.technique_id}
                  to={`/mitre/${t.technique_id}`}
                  className="group block bg-void-850 border border-void-700 hover:border-matrix-500/50 px-3 py-2 transition-colors"
                  style={clipSm}
                >
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-matrix-500 tabular-nums shrink-0">{t.technique_id}</span>
                    <span className="text-xs text-gray-300 truncate flex-1 min-w-0 group-hover:text-white">
                      {name || 'Unknown technique'}
                    </span>
                    <span className="text-xs font-mono text-white tabular-nums shrink-0">{t.rule_count}</span>
                  </div>
                </Link>
              );
            })}
          </div>
        )}
      </section>

      {/* Rules table */}
      <section>
        <div className="flex items-baseline gap-3 mb-3">
          <span className="w-1 h-4 bg-matrix-500" aria-hidden="true" />
          <h2 className="text-base font-display font-bold text-white tracking-wider uppercase">
            Rules
          </h2>
          <span className="text-[10px] text-gray-500 font-mono uppercase tracking-wider">
            // {actor.rules.length} across {actor.sources.length} source{actor.sources.length === 1 ? '' : 's'}
          </span>
        </div>
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
      </section>
    </div>
  );
}
