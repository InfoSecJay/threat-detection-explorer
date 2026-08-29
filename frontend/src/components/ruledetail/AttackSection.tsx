/** MITRE ATT&CK mapping of one rule: techniques, tactics, and (when
 * tagged) threat actors and software. */

import { Link } from 'react-router-dom';
import type { Detection } from '../../types';
import { useMitre } from '../../contexts/MitreContext';
import { resolveGroup, resolveSoftware } from '../../services/mitreLookup';

export function AttackSection({ detection }: { detection: Detection }) {
  const { getTacticName, getTechniqueName, getTacticUrl, getTechniqueUrl } = useMitre();
  return (
    <>
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      <div>
        <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">
          MITRE Techniques
        </label>
        <div className="flex flex-wrap gap-2">
          {detection.mitre_techniques.length > 0 ? (
            detection.mitre_techniques.map((tech) => {
              const techniqueName = getTechniqueName(tech);
              return (
                <a
                  key={tech}
                  href={getTechniqueUrl(tech)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center px-2.5 py-1 bg-blue-500/20 text-blue-400 rounded-lg text-sm hover:bg-blue-500/30 transition-colors border border-blue-500/30"
                >
                  <span className="font-semibold">{tech}</span>
                  {techniqueName && <span className="ml-1.5 text-blue-300">· {techniqueName}</span>}
                </a>
              );
            })
          ) : (
            <span className="text-gray-500 italic text-sm">None mapped</span>
          )}
        </div>
      </div>
      <div>
        <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">
          MITRE Tactics
        </label>
        <div className="flex flex-wrap gap-2">
          {detection.mitre_tactics.length > 0 ? (
            detection.mitre_tactics.map((tactic) => (
              <a
                key={tactic}
                href={getTacticUrl(tactic)}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center px-2.5 py-1 bg-purple-500/20 text-purple-400 rounded-lg text-sm hover:bg-purple-500/30 transition-colors border border-purple-500/30"
              >
                <span className="font-semibold">{tactic}</span>
                <span className="ml-1.5 text-purple-300">· {getTacticName(tactic)}</span>
              </a>
            ))
          ) : (
            <span className="text-gray-500 italic text-sm">None mapped</span>
          )}
        </div>
      </div>
    </div>

    {/* Threat Actors + Software — only render when a rule has any.
        Populated from Sigma/LOLRMM `attack.g*` / `attack.s*` tags.
        Names resolve via mitreLookup; unknown IDs show the raw
        G-/S- form (still useful, never a fake name). */}
    {((detection.mitre_groups?.length || 0) > 0 || (detection.mitre_software?.length || 0) > 0) && (
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {(detection.mitre_groups?.length || 0) > 0 && (
          <div>
            <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">
              Threat Actors
            </label>
            <div className="flex flex-wrap gap-2">
              {detection.mitre_groups!.map((gid) => {
                const g = resolveGroup(gid);
                const isKnown = g.name !== g.id;
                return (
                  <Link
                    key={gid}
                    to={`/detections?mitre_groups=${g.id}`}
                    title={g.aliases.length ? `aka ${g.aliases.join(', ')}` : g.name}
                    className="inline-flex items-center px-2.5 py-1 bg-breach-500/15 text-breach-400 rounded-lg text-sm hover:bg-breach-500/25 transition-colors border border-breach-500/30"
                  >
                    <span className="font-semibold">{g.id}</span>
                    {isKnown && <span className="ml-1.5 text-breach-300">· {g.name}</span>}
                  </Link>
                );
              })}
            </div>
          </div>
        )}
        {(detection.mitre_software?.length || 0) > 0 && (
          <div>
            <label className="block text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">
              Software / Malware
            </label>
            <div className="flex flex-wrap gap-2">
              {detection.mitre_software!.map((sid) => {
                const s = resolveSoftware(sid);
                const isKnown = s.name !== s.id;
                const tone =
                  s.type === 'malware'
                    ? 'bg-orange-500/15 text-orange-400 border-orange-500/30 hover:bg-orange-500/25'
                    : 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30 hover:bg-cyan-500/25';
                return (
                  <Link
                    key={sid}
                    to={`/detections?mitre_software=${s.id}`}
                    className={`inline-flex items-center px-2.5 py-1 rounded-lg text-sm transition-colors border ${tone}`}
                  >
                    <span className="font-semibold">{s.id}</span>
                    {isKnown && <span className="ml-1.5 opacity-80">· {s.name}</span>}
                  </Link>
                );
              })}
            </div>
          </div>
        )}
      </div>
    )}
    </>
  );
}
