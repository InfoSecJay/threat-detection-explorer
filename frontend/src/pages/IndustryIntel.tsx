/**
 * Detection Intelligence — what's new across every upstream repo we
 * track. Composition-only. Four modules, top-to-bottom in the order a
 * returning DE scans them:
 *
 *   1. RepoHealthStrip   — freshness dashboard: rule count, last sync,
 *                          12-week new-rules sparkline per repo.
 *   2. PulseBanner       — total new + modified rules in the window,
 *                          with per-source bars scaled to *created*.
 *   3. UpstreamReleases  — GitHub Releases for sigma/splunk/elastic
 *                          (the only three sources that publish them;
 *                          audit of the other 8 confirmed no
 *                          reliable additional surfaces).
 *   4. What's New        — newest individual rules + three trending
 *                          tiles (techniques, platforms, use cases).
 *                          Inline period + source filter narrow all
 *                          four data hooks in this section together.
 *
 * Threat Spotlight (Phase 2, shipped): named ATT&CK Groups + Software
 * extracted from Sigma + LOLRMM `attack.g*` / `attack.s*` tags,
 * resolved to display names via app.services.mitre_lookup on the BE
 * and services/mitreLookup.ts on the FE.
 */

import { useState, useMemo } from 'react';
import type { ActivityFilters } from '../services/api';
import { clipSm } from '../constants/style';
import { sourceTheme as sourceConfig } from '../constants/style';
import { useFilterOptions } from '../hooks/useDetections';
import { Section } from './intel/Section';
import { RepoHealthStrip } from './intel/RepoHealthStrip';
import { PulseBanner } from './intel/PulseBanner';
import { ThreatSpotlightSection } from './intel/ThreatSpotlight';
import { UpstreamReleases } from './intel/UpstreamReleases';
import { NotableNewRulesSection } from './intel/NotableNewRules';
import {
  TrendingTechniquesList,
  TrendingPlatformsList,
  TrendingUseCasesList,
} from './intel/Trending';
import { periodOptions } from './intel/lib';

function SourceFilterChips({
  value,
  onChange,
}: {
  value: string[];
  onChange: (next: string[]) => void;
}) {
  const { data: options } = useFilterOptions();
  const sources = options?.sources || [];
  if (!sources.length) return null;

  const toggle = (src: string) => {
    onChange(value.includes(src) ? value.filter((s) => s !== src) : [...value, src]);
  };

  return (
    <div className="flex items-center gap-1 flex-wrap">
      <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider mr-1">src:</span>
      {sources.map((src) => {
        const cfg = sourceConfig[src];
        const active = value.includes(src);
        return (
          <button
            key={src}
            onClick={() => toggle(src)}
            className={`px-2 py-0.5 text-[10px] font-mono uppercase transition-colors border ${
              active
                ? `${cfg?.bg || 'bg-matrix-500/20'} ${cfg?.text || 'text-matrix-400'} ${cfg?.border || 'border-matrix-500/30'}`
                : 'bg-void-800 text-gray-400 border-void-600 hover:text-white'
            }`}
            title={cfg?.name || src}
          >
            {(cfg?.name || src).replace(' Protections', ' Prot').replace(' Hunting', ' Hunt')}
          </button>
        );
      })}
      {value.length > 0 && (
        <button
          onClick={() => onChange([])}
          className="ml-2 text-[10px] font-mono text-gray-500 hover:text-breach-400 uppercase tracking-wider"
        >
          [ clear ]
        </button>
      )}
    </div>
  );
}

function TrendingTile({
  title,
  accent,
  children,
}: {
  title: string;
  accent: 'matrix' | 'cyan' | 'amber';
  children: React.ReactNode;
}) {
  const accentText =
    accent === 'matrix' ? 'text-matrix-400' : accent === 'cyan' ? 'text-cyan-400' : 'text-amber-300';
  const accentBar =
    accent === 'matrix' ? 'bg-matrix-500' : accent === 'cyan' ? 'bg-cyan-500' : 'bg-amber-500';
  return (
    <div className="bg-void-850 border border-void-700 overflow-hidden" style={clipSm}>
      <div className="flex items-center gap-2 px-3 py-2 border-b border-void-700 bg-void-900/40">
        <span className={`w-0.5 h-3 ${accentBar}`} />
        <h3 className={`font-display font-semibold text-[11px] uppercase tracking-wider ${accentText}`}>
          {title}
        </h3>
      </div>
      <div className="p-2">{children}</div>
    </div>
  );
}

export function IndustryIntel() {
  // Single time-window control that drives Pulse, Threat Spotlight,
  // and the What's New section (both newest-rules cards and trending
  // tiles). Repo Health + Upstream Releases sit outside — those are
  // separate cadences (12-week trend, latest N GitHub releases).
  const [period, setPeriod] = useState(30);
  const [sourceFilter, setSourceFilter] = useState<string[]>([]);

  const filters = useMemo<ActivityFilters>(
    () => (sourceFilter.length ? { sources: sourceFilter } : {}),
    [sourceFilter],
  );

  return (
    <div className="space-y-8">
      {/* Page header — title + global period toggle. Every module
          below that respects a window uses `period`. */}
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">
            Detection Intelligence
          </h1>
          <p className="text-xs text-gray-500 mt-1 font-mono">
            what&apos;s new across every upstream detection-rule repo we track
          </p>
        </div>
        <div className="flex flex-col items-end gap-1">
          <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">
            time window
          </span>
          <div className="flex items-center gap-1" role="radiogroup" aria-label="Time window">
            {periodOptions.map((opt) => (
              <button
                key={opt.value}
                role="radio"
                aria-checked={period === opt.value}
                onClick={() => setPeriod(opt.value)}
                className={`px-3 py-1 text-xs font-mono uppercase tracking-wider transition-colors ${
                  period === opt.value
                    ? 'bg-matrix-500/20 text-matrix-400 border border-matrix-500/40'
                    : 'bg-void-900 text-gray-500 border border-void-700 hover:text-white'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      <Section title="Repo Health" subtitle="12-week trend per repo · click a card to filter the catalog">
        <RepoHealthStrip />
      </Section>

      <PulseBanner days={period} />

      <Section title="Threat Spotlight" subtitle="named actors + software active in vendor rules · sigma + lolrmm">
        <ThreatSpotlightSection days={period} />
      </Section>

      <Section title="Upstream Releases" subtitle="latest tagged releases · sigma · splunk · elastic">
        <UpstreamReleases />
      </Section>

      <Section
        title="What's New"
        subtitle="latest rules + trending patterns in the selected window"
      >
        <div className="space-y-3">
          <SourceFilterChips value={sourceFilter} onChange={setSourceFilter} />
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2">
              <NotableNewRulesSection filters={filters} days={period} />
            </div>
            <div className="space-y-3">
              <TrendingTile title="Trending Techniques" accent="matrix">
                <TrendingTechniquesList days={period} filters={filters} />
              </TrendingTile>
              <TrendingTile title="Trending Platforms" accent="cyan">
                <TrendingPlatformsList days={period} filters={filters} />
              </TrendingTile>
              <TrendingTile title="Trending Use Cases" accent="amber">
                <TrendingUseCasesList days={period} filters={filters} />
              </TrendingTile>
            </div>
          </div>
        </div>
      </Section>
    </div>
  );
}
