/** Right pane for a selected technique: ATT&CK metadata, per-vendor
 * observables and actors from the technique profile, and the matching
 * rules grouped by source. */

import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useTechniqueProfile } from '../../hooks/useTechniqueProfile';
import { observableUrl, OBSERVABLE_KIND_LABEL, type ObservableKind } from '../../utils/observableLinks';
import { useDetections } from '../../hooks/useDetections';
import { useMitre } from '../../contexts/MitreContext';
import { MitreText } from '../../components/MitreText';
import { useAttackRouteResolver } from '../../hooks/useAttackRoutes';
import { useDocumentMeta } from '../../hooks/useDocumentMeta';
import { sourceTheme as sourceColors, clipSm as clipCornerSm, clipMd as clipCornerMd } from '../../constants/style';
import type { CoverageData } from './types';

const severityColors: Record<string, string> = {
  critical: 'text-breach-400 border-breach-500/30 bg-breach-500/10',
  high: 'text-orange-400 border-orange-500/30 bg-orange-500/10',
  medium: 'text-amber-400 border-amber-500/30 bg-amber-500/10',
  low: 'text-blue-400 border-blue-500/30 bg-blue-500/10',
  unknown: 'text-gray-500 border-gray-600/30 bg-void-800',
};

export function TechniqueDetailPane({
  techniqueId,
  coverageData,
}: {
  techniqueId: string;
  coverageData: CoverageData;
}) {
  const { techniques, tactics: allTactics, getTechniqueUrl } = useMitre();
  const tech = techniques[techniqueId];
  const resolveRoute = useAttackRouteResolver();
  useDocumentMeta(tech ? `${tech.id} ${tech.name}` : techniqueId, tech?.description);

  // Find coverage-matrix entry (for per-source counts)
  const coverageEntry = useMemo(() => {
    for (const t of coverageData.tactics) {
      const hit = t.techniques.find((x) => x.id === techniqueId);
      if (hit) return hit;
    }
    return undefined;
  }, [coverageData, techniqueId]);

  const parentId = techniqueId.includes('.') ? techniqueId.split('.')[0] : null;
  const parentTech = parentId ? techniques[parentId] : null;

  // Fetch matching rules — the backend's mitre_techniques filter already
  // matches both the technique and its sub-techniques via json contains.
  const { data: rulesData, isLoading: rulesLoading } = useDetections({
    mitre_techniques: [techniqueId],
    limit: 200,
  });

  // Profile: per-vendor observables, actors, momentum (technique page enrichment).
  const { data: profile } = useTechniqueProfile(techniqueId);

  // Hooks must run unconditionally -- these sat below the `!tech`
  // early return before (#45 rules-of-hooks finding), which would have
  // corrupted hook order the first time a technique id 404'd and then
  // resolved (e.g. MITRE data arriving after a deep link).
  const rules = useMemo(() => rulesData?.items ?? [], [rulesData]);
  const rulesBySource = useMemo(() => {
    const grouped: Record<string, typeof rules> = {};
    for (const r of rules) {
      (grouped[r.source] ||= []).push(r);
    }
    return grouped;
  }, [rules]);

  if (!tech) {
    return (
      <div className="bg-void-850 border border-void-700 p-8 text-center" style={clipCornerMd}>
        <p className="text-gray-500 font-mono text-sm">Technique {techniqueId} not found in MITRE data.</p>
        <Link to="/mitre" className="inline-block mt-3 text-matrix-500 hover:text-matrix-400 text-xs font-mono">
          [ BACK_TO_BROWSER ]
        </Link>
      </div>
    );
  }

  const totalDetections = coverageEntry?.total_detections ?? rules.length;
  const sourcesCovered = coverageEntry?.sources_with_coverage ?? Object.keys(rulesBySource).length;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="bg-void-850 border border-void-700 p-5" style={clipCornerMd}>
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 text-[10px] font-mono text-gray-500 mb-2">
              <Link to="/mitre" className="hover:text-matrix-500 transition-colors">MITRE</Link>
              <span>/</span>
              {parentTech && (
                <>
                  <Link to={`/mitre/${parentId}`} className="hover:text-matrix-500 transition-colors">
                    {parentId} {parentTech.name}
                  </Link>
                  <span>/</span>
                </>
              )}
              <span className="text-gray-300">{techniqueId}</span>
            </div>
            <h2 className="font-display text-xl font-bold text-white tracking-wide flex items-center gap-3 flex-wrap">
              <span className="font-mono text-matrix-500">{tech.id}</span>
              <span>{tech.name}</span>
              {tech.is_subtechnique && (
                <span className="text-[10px] font-mono text-gray-500 bg-void-800 border border-void-600 px-2 py-0.5">
                  SUB-TECHNIQUE
                </span>
              )}
            </h2>
            {tech.tactics && tech.tactics.length > 0 && (
              <div className="flex items-center gap-1.5 mt-2 flex-wrap">
                {tech.tactics.map((tacticId) => {
                  const t = allTactics[tacticId];
                  if (!t) return null;
                  return (
                    <span
                      key={tacticId}
                      className="text-[10px] font-mono uppercase tracking-wider text-matrix-400 bg-matrix-500/10 border border-matrix-500/30 px-2 py-0.5"
                    >
                      {t.name}
                    </span>
                  );
                })}
              </div>
            )}
          </div>
          <a
            href={getTechniqueUrl(techniqueId)}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs font-mono text-matrix-500 hover:text-matrix-400 border border-matrix-500/30 hover:border-matrix-500/60 px-3 py-1.5 transition-colors flex-shrink-0"
            style={clipCornerSm}
          >
            [ ATTACK.MITRE.ORG ↗ ]
          </a>
        </div>

        {/* Stat pills */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4">
          <div className="bg-void-900 border border-void-700 px-3 py-2" style={clipCornerSm}>
            <div className="text-[10px] font-mono text-gray-500 uppercase">Rules</div>
            <div className="text-lg font-display text-matrix-500">{totalDetections}</div>
          </div>
          <div className="bg-void-900 border border-void-700 px-3 py-2" style={clipCornerSm}>
            <div className="text-[10px] font-mono text-gray-500 uppercase">Sources</div>
            <div className="text-lg font-display text-white">{sourcesCovered} / {coverageData.sources.length}</div>
          </div>
          <div className="bg-void-900 border border-void-700 px-3 py-2" style={clipCornerSm}>
            <div className="text-[10px] font-mono text-gray-500 uppercase">Version</div>
            <div className="text-lg font-display text-gray-300">{tech.version || '—'}</div>
          </div>
          <div className="bg-void-900 border border-void-700 px-3 py-2" style={clipCornerSm} title="Catalog-wide rule count change vs the coverage snapshot 7 days ago">
            <div className="text-[10px] font-mono text-gray-500 uppercase">7d momentum</div>
            <div className={`text-lg font-display ${profile?.momentum.delta ? (profile.momentum.delta > 0 ? 'text-pulse-400' : 'text-breach-400') : 'text-gray-500'}`} data-testid="technique-momentum">
              {profile?.momentum.method === 'snapshot' && profile.momentum.delta !== null
                ? `${profile.momentum.delta > 0 ? '+' : ''}${profile.momentum.delta}`
                : '—'}
            </div>
          </div>
        </div>
      </div>

      {/* Description */}
      {tech.description && (
        <div className="bg-void-850 border border-void-700 p-5" style={clipCornerMd}>
          <h3 className="font-display text-sm text-white uppercase tracking-wider mb-2">Description</h3>
          <MitreText text={tech.description} resolveRoute={resolveRoute} />
        </div>
      )}

      {/* Platforms + Data Sources + Detection guidance */}
      <div className="grid md:grid-cols-2 gap-4">
        {tech.platforms && tech.platforms.length > 0 && (
          <div className="bg-void-850 border border-void-700 p-4" style={clipCornerMd}>
            <h3 className="font-display text-sm text-white uppercase tracking-wider mb-2">Platforms</h3>
            <div className="flex flex-wrap gap-1.5">
              {tech.platforms.map((p) => (
                <span
                  key={p}
                  className="text-xs font-mono text-matrix-400 bg-matrix-500/10 border border-matrix-500/30 px-2 py-0.5"
                >
                  {p}
                </span>
              ))}
            </div>
          </div>
        )}
        {tech.data_sources && tech.data_sources.length > 0 && (
          <div className="bg-void-850 border border-void-700 p-4" style={clipCornerMd}>
            <h3 className="font-display text-sm text-white uppercase tracking-wider mb-2">Data Sources</h3>
            <div className="flex flex-wrap gap-1.5">
              {tech.data_sources.map((d) => (
                <span
                  key={d}
                  className="text-xs font-mono text-sky-400 bg-sky-500/10 border border-sky-500/30 px-2 py-0.5"
                >
                  {d}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {tech.detection && (
        <div className="bg-void-850 border border-amber-500/20 p-5" style={clipCornerMd}>
          <h3 className="font-display text-sm text-amber-400 uppercase tracking-wider mb-2">MITRE Detection Guidance</h3>
          <MitreText text={tech.detection} resolveRoute={resolveRoute} />
        </div>
      )}

      {/* How each vendor detects it + who uses it (technique profile) */}
      {profile && Object.keys(profile.sources).length > 0 && (
        <div className="bg-void-850 border border-void-700 p-5" style={clipCornerMd}>
          <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
            <h3 className="font-display text-sm text-white uppercase tracking-wider">How each vendor detects it</h3>
            <span className="text-[10px] font-mono text-gray-500">what the rules key on, per source; click a value for every rule that uses it</span>
          </div>
          <div className="grid md:grid-cols-2 xl:grid-cols-3 gap-3">
            {Object.entries(profile.sources).map(([src, info]) => (
              <div key={src} className="bg-void-900 border border-void-700 p-3" style={clipCornerSm} data-testid={`vendor-${src}`}>
                <div className="flex items-center justify-between gap-2 mb-2">
                  <span className="text-xs font-mono text-matrix-400 uppercase">{src.replace(/_/g, ' ')}</span>
                  <span className="text-[10px] font-mono text-gray-500 tabular-nums">
                    {info.rules} {info.rules === 1 ? 'rule' : 'rules'}{info.hygiene_avg !== null ? ` / completeness ${info.hygiene_avg}` : ''}
                  </span>
                </div>
                {Object.keys(info.observables).length === 0 ? (
                  <p className="text-[10px] font-mono text-gray-600">no extracted observables</p>
                ) : (
                  <div className="space-y-1.5">
                    {Object.entries(info.observables).map(([kind, values]) => (
                      <div key={kind} className="flex flex-wrap items-baseline gap-1">
                        <span className="text-[9px] font-mono text-gray-600 uppercase w-14 shrink-0">{OBSERVABLE_KIND_LABEL[kind as ObservableKind] || kind}</span>
                        {values.map((v) => (
                          <Link key={v.value} to={observableUrl(kind as ObservableKind, v.value)} className="px-1 py-0.5 text-[10px] font-mono bg-void-800 border border-void-700 text-gray-300 hover:text-matrix-400 hover:border-matrix-500/40 break-all" title={`${v.rules} rule(s) here reference this`}>
                            {v.value}
                          </Link>
                        ))}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {profile && (profile.groups.length > 0 || profile.software.length > 0) && (
        <div className="bg-void-850 border border-void-700 p-5" style={clipCornerMd}>
          <h3 className="font-display text-sm text-white uppercase tracking-wider mb-2">Used by</h3>
          <p className="text-[10px] font-mono text-gray-500 mb-3">ATT&CK groups and software known to use this technique</p>
          <div className="flex flex-wrap gap-1.5">
            {profile.groups.map((g) => (
              <Link key={g.id} to={`/actors/${g.id}`} className="px-2 py-0.5 text-xs font-mono border border-breach-500/30 text-breach-300 hover:bg-breach-500/10" title={`${g.technique_count} techniques`}>
                {g.name}
              </Link>
            ))}
            {profile.software.map((sw) => (
              <Link key={sw.id} to={`/actors/${sw.id}`} className="px-2 py-0.5 text-xs font-mono border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/10" title={sw.type}>
                {sw.name}
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Matching rules */}
      <div className="bg-void-850 border border-void-700 p-5" style={clipCornerMd}>
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-display text-sm text-white uppercase tracking-wider">
            Matching Detection Rules
          </h3>
          <Link
            to={`/detections?mitre_techniques=${techniqueId}`}
            className="text-[10px] font-mono text-matrix-500 hover:text-matrix-400 transition-colors"
          >
            [ OPEN_IN_DETECTIONS ↗ ]
          </Link>
        </div>

        {rulesLoading ? (
          <div className="space-y-2">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="h-10 bg-void-800 animate-pulse rounded" />
            ))}
          </div>
        ) : rules.length === 0 ? (
          <div className="text-center py-8">
            <p className="text-gray-500 font-mono text-sm">No rules in the catalog match this technique yet.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {coverageData.sources.map((src) => {
              const srcRules = rulesBySource[src];
              if (!srcRules || srcRules.length === 0) return null;
              const colors = sourceColors[src] || sourceColors.sigma;
              return (
                <div key={src}>
                  <div className="flex items-center gap-2 mb-1.5">
                    <span className={`w-2 h-2 ${colors.dot}`} />
                    <span className={`text-[11px] font-mono uppercase tracking-wider ${colors.text}`}>
                      {colors.name || src}
                    </span>
                    <span className="text-[10px] font-mono text-gray-500">({srcRules.length})</span>
                  </div>
                  <div className="divide-y divide-void-700/50">
                    {srcRules.map((r) => (
                      <Link
                        key={r.id}
                        to={`/detections/${r.id}`}
                        className="flex items-center gap-2 px-2 py-1.5 hover:bg-void-800/70 transition-colors"
                      >
                        <span className={`text-[10px] font-mono uppercase px-1.5 py-0.5 border flex-shrink-0 ${severityColors[r.severity] || severityColors.unknown}`}>
                          {r.severity || 'unk'}
                        </span>
                        <span className="text-sm text-gray-300 truncate flex-1">{r.title}</span>
                      </Link>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
