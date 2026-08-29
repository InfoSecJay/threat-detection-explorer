import { useState, useMemo, useEffect } from 'react';
import { useTechniqueProfile } from '../hooks/useTechniqueProfile';
import { observableUrl, OBSERVABLE_KIND_LABEL, type ObservableKind } from '../utils/observableLinks';
import { Link, useParams, useNavigate } from 'react-router-dom';
import { useCoverageMatrix } from '../hooks/useCompare';
import { useDetections } from '../hooks/useDetections';
import { useMitre } from '../contexts/MitreContext';
import { MitreText } from '../components/MitreText';
import { useAttackRouteResolver } from '../hooks/useAttackRoutes';
import { sourceTheme as sourceColors, clipSm as clipCornerSm, clipMd as clipCornerMd } from '../constants/style';
import type { TechniqueCoverage, TacticCoverage } from '../services/api';

const severityColors: Record<string, string> = {
  critical: 'text-breach-400 border-breach-500/30 bg-breach-500/10',
  high: 'text-orange-400 border-orange-500/30 bg-orange-500/10',
  medium: 'text-amber-400 border-amber-500/30 bg-amber-500/10',
  low: 'text-blue-400 border-blue-500/30 bg-blue-500/10',
  unknown: 'text-gray-500 border-gray-600/30 bg-void-800',
};

// ── Summary stat card ─────────────────────────────────────────────────
function StatCard({ label, value, sublabel, accent }: { label: string; value: string; sublabel?: string; accent?: string }) {
  return (
    <div className={`bg-void-850 border ${accent || 'border-matrix-500/30'} p-4`} style={clipCornerSm}>
      <div className="text-[10px] font-mono text-gray-500 mb-1 uppercase tracking-wider">{label}</div>
      <div className={`text-2xl font-display font-bold ${accent ? 'text-white' : 'text-matrix-500'}`}>{value}</div>
      {sublabel && <div className="text-xs text-gray-500 font-mono mt-0.5">{sublabel}</div>}
    </div>
  );
}

// ── Left pane: tactic → technique tree ────────────────────────────────
function TacticGroup({
  tactic,
  selectedId,
  expanded,
  onToggle,
  filterCoverage,
  search,
}: {
  tactic: TacticCoverage;
  selectedId: string | undefined;
  expanded: boolean;
  onToggle: () => void;
  filterCoverage: 'all' | 'covered' | 'gaps';
  search: string;
}) {
  const navigate = useNavigate();

  // Group subtechniques under their parent technique.
  const grouped = useMemo(() => {
    const parents: TechniqueCoverage[] = [];
    const byParent: Record<string, TechniqueCoverage[]> = {};
    for (const t of tactic.techniques) {
      if (t.is_subtechnique) {
        const parentId = t.id.split('.')[0];
        (byParent[parentId] ||= []).push(t);
      } else {
        parents.push(t);
      }
    }
    return { parents, byParent };
  }, [tactic.techniques]);

  const matchesFilter = (t: TechniqueCoverage) => {
    if (filterCoverage === 'covered' && t.total_detections === 0) return false;
    if (filterCoverage === 'gaps' && t.total_detections > 0) return false;
    if (search) {
      const q = search.toLowerCase();
      if (!t.id.toLowerCase().includes(q) && !t.name.toLowerCase().includes(q)) return false;
    }
    return true;
  };

  // Filter parents, but keep them if any child subtechnique matches.
  const visibleParents = grouped.parents.filter((p) => {
    if (matchesFilter(p)) return true;
    const subs = grouped.byParent[p.id] || [];
    return subs.some(matchesFilter);
  });

  const coveredCount = tactic.techniques.filter((t) => t.total_detections > 0 && !t.is_subtechnique).length;
  const parentCount = grouped.parents.length;
  const coveragePercent = parentCount ? Math.round((coveredCount / parentCount) * 100) : 0;

  if (visibleParents.length === 0) return null;

  return (
    <div className="border border-void-700 bg-void-850" style={clipCornerSm}>
      <button
        onClick={onToggle}
        className="w-full px-3 py-2.5 flex items-center justify-between hover:bg-void-800/50 transition-colors"
      >
        <div className="flex items-center gap-2 min-w-0">
          <svg
            className={`w-3 h-3 text-gray-500 transition-transform flex-shrink-0 ${expanded ? 'rotate-90' : ''}`}
            fill="none" stroke="currentColor" viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
          </svg>
          <span className="font-display text-sm text-white uppercase tracking-wide truncate">
            {tactic.name}
          </span>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <span className="text-[10px] font-mono text-gray-500">
            {coveredCount}/{parentCount}
          </span>
          <span className="text-[10px] font-mono text-matrix-500 w-8 text-right">{coveragePercent}%</span>
        </div>
      </button>

      {expanded && (
        <div className="border-t border-void-700 divide-y divide-void-700/50">
          {visibleParents.map((p) => {
            const subs = (grouped.byParent[p.id] || []).filter(matchesFilter);
            const isSelected = selectedId === p.id;
            return (
              <div key={p.id}>
                <button
                  onClick={() => navigate(`/mitre/${p.id}`)}
                  className={`w-full text-left px-3 py-1.5 flex items-center gap-2 hover:bg-void-800/70 transition-colors ${
                    isSelected ? 'bg-matrix-500/10 border-l-2 border-l-matrix-500' : ''
                  }`}
                >
                  <span className={`font-mono text-[11px] ${p.total_detections > 0 ? 'text-matrix-500' : 'text-gray-600'}`}>
                    {p.id}
                  </span>
                  <span className={`text-xs truncate flex-1 ${p.total_detections > 0 ? 'text-gray-300' : 'text-gray-600'}`}>
                    {p.name}
                  </span>
                  <span className={`text-[10px] font-mono ${p.total_detections > 0 ? 'text-white' : 'text-gray-700'}`}>
                    {p.total_detections || '—'}
                  </span>
                </button>
                {subs.map((s) => {
                  const subSelected = selectedId === s.id;
                  return (
                    <button
                      key={s.id}
                      onClick={() => navigate(`/mitre/${s.id}`)}
                      className={`w-full text-left pl-8 pr-3 py-1 flex items-center gap-2 hover:bg-void-800/70 transition-colors ${
                        subSelected ? 'bg-matrix-500/10 border-l-2 border-l-matrix-500' : ''
                      }`}
                    >
                      <span className={`font-mono text-[10px] ${s.total_detections > 0 ? 'text-matrix-500/80' : 'text-gray-700'}`}>
                        {s.id}
                      </span>
                      <span className={`text-xs truncate flex-1 ${s.total_detections > 0 ? 'text-gray-400' : 'text-gray-700'}`}>
                        {s.name}
                      </span>
                      <span className={`text-[10px] font-mono ${s.total_detections > 0 ? 'text-gray-300' : 'text-gray-700'}`}>
                        {s.total_detections || '—'}
                      </span>
                    </button>
                  );
                })}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Right pane: default summary when no technique is selected ─────────
function SummaryPane({ data }: { data: NonNullable<ReturnType<typeof useCoverageMatrix>['data']> }) {
  const { summary, sources, tactics } = data;

  // Top gaps (parent techniques with zero detections) — cap at 12
  const gaps = useMemo(() => {
    const out: TechniqueCoverage[] = [];
    for (const t of tactics) {
      for (const tech of t.techniques) {
        if (!tech.is_subtechnique && tech.total_detections === 0) out.push(tech);
      }
    }
    return out.slice(0, 12);
  }, [tactics]);

  // Top covered (parent techniques, highest detection count)
  const topCovered = useMemo(() => {
    const out: TechniqueCoverage[] = [];
    for (const t of tactics) {
      for (const tech of t.techniques) {
        if (!tech.is_subtechnique && tech.total_detections > 0) out.push(tech);
      }
    }
    return out.sort((a, b) => b.total_detections - a.total_detections).slice(0, 10);
  }, [tactics]);

  return (
    <div className="space-y-4">
      {/* Headline stats */}
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        <StatCard
          label="Overall Coverage"
          value={`${summary.overall_coverage_percent}%`}
          sublabel={`${summary.techniques_with_any_coverage} / ${summary.total_techniques} techniques`}
        />
        <StatCard
          label="Techniques"
          value={String(summary.total_techniques)}
          sublabel={`${summary.total_tactics} tactics`}
          accent="border-void-700"
        />
        <StatCard
          label="Gaps"
          value={String(summary.total_techniques - summary.techniques_with_any_coverage)}
          sublabel="uncovered techniques"
          accent="border-breach-500/30"
        />
      </div>

      {/* Per-source coverage */}
      <div className="bg-void-850 border border-void-700 p-4" style={clipCornerMd}>
        <div className="flex items-center justify-between mb-3">
          <h3 className="font-display text-sm text-white uppercase tracking-wider">Coverage by Source</h3>
          <span className="text-[10px] font-mono text-gray-500">
            of {summary.total_techniques} techniques
          </span>
        </div>
        <div className="space-y-2">
          {sources.map((src) => {
            const sc = summary.source_coverage[src];
            const colors = sourceColors[src] || sourceColors.sigma;
            return (
              <div key={src} className="flex items-center gap-3">
                <div className="flex items-center gap-2 w-32 flex-shrink-0">
                  <span className={`w-2 h-2 ${colors.dot}`} />
                  <span className="text-xs text-gray-400">{sourceColors[src]?.name || src}</span>
                </div>
                <div className="flex-1 h-2 bg-void-900 rounded-sm overflow-hidden">
                  <div
                    className={`h-full ${colors.dot} transition-all`}
                    style={{ width: `${sc.coverage_percent}%` }}
                  />
                </div>
                <div className="flex items-baseline gap-2 w-24 justify-end">
                  <span className={`text-sm font-mono ${colors.text}`}>{sc.coverage_percent}%</span>
                  <span className="text-[10px] font-mono text-gray-500">({sc.covered_techniques})</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Top covered + gaps, side by side */}
      <div className="grid md:grid-cols-2 gap-4">
        <div className="bg-void-850 border border-void-700 p-4" style={clipCornerMd}>
          <h3 className="font-display text-sm text-white uppercase tracking-wider mb-3">Most-Covered</h3>
          <div className="space-y-1">
            {topCovered.map((t) => (
              <Link
                key={t.id}
                to={`/mitre/${t.id}`}
                className="flex items-center gap-2 px-2 py-1 text-xs hover:bg-void-800 transition-colors rounded-sm"
              >
                <span className="font-mono text-matrix-500 w-14">{t.id}</span>
                <span className="text-gray-300 flex-1 truncate">{t.name}</span>
                <span className="font-mono text-white">{t.total_detections}</span>
              </Link>
            ))}
          </div>
        </div>

        <div className="bg-void-850 border border-breach-500/20 p-4" style={clipCornerMd}>
          <h3 className="font-display text-sm text-breach-400 uppercase tracking-wider mb-3">Top Gaps</h3>
          {gaps.length === 0 ? (
            <div className="text-center py-8">
              <div className="text-matrix-500 text-3xl mb-2">✓</div>
              <p className="text-gray-400 font-display text-sm">Full coverage — no gaps.</p>
            </div>
          ) : (
            <div className="space-y-1">
              {gaps.map((t) => (
                <Link
                  key={t.id}
                  to={`/mitre/${t.id}`}
                  className="flex items-center gap-2 px-2 py-1 text-xs hover:bg-void-800 transition-colors rounded-sm"
                >
                  <span className="font-mono text-gray-500 w-14">{t.id}</span>
                  <span className="text-gray-500 flex-1 truncate">{t.name}</span>
                </Link>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Right pane: technique detail with MITRE metadata + matching rules ─
function TechniqueDetailPane({
  techniqueId,
  coverageData,
}: {
  techniqueId: string;
  coverageData: NonNullable<ReturnType<typeof useCoverageMatrix>['data']>;
}) {
  const { techniques, tactics: allTactics, getTechniqueUrl } = useMitre();
  const tech = techniques[techniqueId];
  const resolveRoute = useAttackRouteResolver();

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
                    {info.rules} {info.rules === 1 ? 'rule' : 'rules'}{info.hygiene_avg !== null ? ` / hygiene ${info.hygiene_avg}` : ''}
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

// ── Page root ─────────────────────────────────────────────────────────
export function MitreCoverage() {
  const { techniqueId } = useParams<{ techniqueId?: string }>();
  const selectedId = techniqueId?.toUpperCase();

  const [includeSubtechniques, setIncludeSubtechniques] = useState(true);
  const [filterCoverage, setFilterCoverage] = useState<'all' | 'covered' | 'gaps'>('all');
  const [search, setSearch] = useState('');
  const [expandedTactics, setExpandedTactics] = useState<Set<string>>(new Set());

  const { data, isLoading, error } = useCoverageMatrix({
    include_subtechniques: includeSubtechniques,
  });

  // If a technique is selected, auto-expand its parent tactic(s).
  const { techniques } = useMitre();
  useEffect(() => {
    if (!selectedId || !techniques[selectedId]) return;
    const tech = techniques[selectedId];
    setExpandedTactics((prev) => {
      const next = new Set(prev);
      for (const tId of tech.tactics || []) next.add(tId);
      return next;
    });
  }, [selectedId, techniques]);

  const toggleTactic = (tacticId: string) => {
    setExpandedTactics((prev) => {
      const next = new Set(prev);
      if (next.has(tacticId)) {
        next.delete(tacticId);
      } else {
        next.add(tacticId);
      }
      return next;
    });
  };
  const expandAll = () => data && setExpandedTactics(new Set(data.tactics.map((t) => t.id)));
  const collapseAll = () => setExpandedTactics(new Set());

  return (
    <div className="space-y-4">
      {/* Page Header */}
      <div className="flex items-end justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">
            MITRE ATT&amp;CK Browser
          </h1>
          <p className="text-xs text-gray-500 mt-1 font-mono">
            BROWSE_BY_TECHNIQUE // CROSS_VENDOR_COVERAGE // DRILL_TO_RULES
          </p>
        </div>
        {data && (
          <div className="flex items-center gap-3 text-xs font-mono text-gray-500">
            <span>
              <span className="text-matrix-500 font-bold">{data.summary.overall_coverage_percent}%</span>
              {' '}coverage
            </span>
            <span className="text-gray-700">·</span>
            <span>
              <span className="text-white font-bold">{data.summary.techniques_with_any_coverage}</span>
              <span className="text-gray-600"> / {data.summary.total_techniques}</span>
            </span>
            <span className="text-gray-700">·</span>
            <span>{data.sources.length} sources</span>
          </div>
        )}
      </div>

      {error && (
        <div className="bg-breach-500/10 border border-breach-500/30 p-4" style={clipCornerMd}>
          <p className="text-breach-400 font-mono text-sm">
            ERROR: Failed to load coverage matrix. The backend may still be redeploying.
          </p>
        </div>
      )}

      {/* Split layout */}
      <div className="grid lg:grid-cols-[360px_1fr] gap-4">
        {/* Left pane */}
        <aside className="space-y-3 lg:sticky lg:top-[72px] lg:self-start lg:max-h-[calc(100vh-96px)] lg:overflow-y-auto lg:pr-1">
          {/* Controls */}
          <div className="bg-void-850 border border-void-700 p-3 space-y-2" style={clipCornerSm}>
            <div className="relative">
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Filter T-ID or name…"
                className="w-full bg-void-900 border border-void-600 text-sm text-white placeholder-gray-600 px-3 py-1.5 focus:outline-none focus:border-matrix-500/50 font-mono"
              />
            </div>

            <div className="flex items-center gap-1">
              {(['all', 'covered', 'gaps'] as const).map((f, i, arr) => (
                <button
                  key={f}
                  onClick={() => setFilterCoverage(f)}
                  className={`flex-1 px-2 py-1 text-[10px] font-mono uppercase border ${
                    filterCoverage === f
                      ? 'bg-matrix-500/20 text-matrix-400 border-matrix-500/30'
                      : 'bg-void-800 text-gray-400 border-void-600 hover:text-white'
                  } ${i > 0 ? '-ml-px' : ''} ${i === 0 ? 'rounded-l-sm' : ''} ${i === arr.length - 1 ? 'rounded-r-sm' : ''}`}
                >
                  {f}
                </button>
              ))}
            </div>

            <label className="flex items-center gap-2 cursor-pointer text-xs text-gray-400">
              <input
                type="checkbox"
                checked={includeSubtechniques}
                onChange={(e) => setIncludeSubtechniques(e.target.checked)}
                className="w-3.5 h-3.5 text-matrix-500 bg-void-900 border-void-600 rounded focus:ring-matrix-500/50"
              />
              <span>Show sub-techniques</span>
            </label>

            <div className="flex items-center gap-2 pt-1 border-t border-void-700">
              <button
                onClick={expandAll}
                className="text-[10px] font-mono text-gray-500 hover:text-matrix-500 transition-colors"
              >
                [ EXPAND ]
              </button>
              <button
                onClick={collapseAll}
                className="text-[10px] font-mono text-gray-500 hover:text-matrix-500 transition-colors"
              >
                [ COLLAPSE ]
              </button>
            </div>
          </div>

          {/* Tactic tree */}
          {isLoading ? (
            <div className="space-y-2">
              {[...Array(8)].map((_, i) => (
                <div key={i} className="h-10 bg-void-800 animate-pulse rounded" />
              ))}
            </div>
          ) : (
            <div className="space-y-2">
              {data?.tactics.map((tactic) => (
                <TacticGroup
                  key={tactic.id}
                  tactic={tactic}
                  selectedId={selectedId}
                  expanded={expandedTactics.has(tactic.id)}
                  onToggle={() => toggleTactic(tactic.id)}
                  filterCoverage={filterCoverage}
                  search={search}
                />
              ))}
            </div>
          )}
        </aside>

        {/* Right pane */}
        <section className="min-w-0">
          {isLoading ? (
            <div className="space-y-3">
              <div className="h-24 bg-void-800 animate-pulse rounded" />
              <div className="h-48 bg-void-800 animate-pulse rounded" />
              <div className="h-32 bg-void-800 animate-pulse rounded" />
            </div>
          ) : !data ? null : selectedId ? (
            <TechniqueDetailPane techniqueId={selectedId} coverageData={data} />
          ) : (
            <SummaryPane data={data} />
          )}
        </section>
      </div>
    </div>
  );
}
