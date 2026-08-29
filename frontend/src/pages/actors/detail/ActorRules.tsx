/** Rules section with the match-mode toggle (issue #34): DEDICATED
 * (wire `exact`) = rules built for the actor; COVERAGE = rules tagging
 * any technique it uses; REFERENCED (wire `mention`) = rules that only
 * cite it. Also hosts the Navigator export and open-in-catalog. */

import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { actorsApi } from '../../../services/api';
import { sourceTheme as sourceConfig, clipSm } from '../../../constants/style';
import { severityColor } from '../../intel/lib';
import { SectionHead } from './SectionHead';
import type { ActorMatchMode } from '../../../services/api';
import type { ActorDetail as ActorDetailData } from '../../../services/api';

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

export function ActorRules({ actor, matchMode, setMatchMode }: {
  actor: ActorDetailData;
  matchMode: ActorMatchMode;
  setMatchMode: (m: ActorMatchMode) => void;
}) {
  const navigate = useNavigate();
  const isGroup = actor.kind === 'group';
  const [exporting, setExporting] = useState(false);

  const exportLayer = async () => {
    if (!actor || exporting) return;
    setExporting(true);
    try {
      await actorsApi.downloadNavigatorLayer(actor.id, matchMode);
    } finally {
      setExporting(false);
    }
  };

  return (
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
  );
}
