/**
 * Detection Intelligence — organized top-to-bottom by signal density:
 *
 *   RepoHealthStrip   Always current. 12-week new-rules sparkline
 *                     per repo. Answers "is this repo actively
 *                     developed?" -- a question that doesn't map
 *                     onto a 30/60/90 window.
 *
 *   ── ACTIVITY IN THE LAST [30/60/90] DAYS ─────────────────
 *     (the window toggle IS this group's header)
 *     PulseBanner       total new + modified rules in the window.
 *     What's New        newest rules + trending techniques /
 *                       platforms in the window. Inline source
 *                       filter narrows all three data hooks together.
 *
 *   UpstreamReleases  Latest tagged GitHub releases for
 *                     sigma/splunk/elastic. Big markdown bodies so
 *                     it lives at the very bottom -- the expanded
 *                     view is capped at 400px with an inner scroll
 *                     to avoid burying the sections above it.
 *
 * The visual band with the toggle in the middle of the page makes
 * it obvious which sections respect the window and which don't --
 * an earlier version put the toggle at the top-right and implied
 * (wrongly) that it controlled Repo Health.
 *
 * Threat Actor / Software drill-in lives on `/actors`, not here.
 */

import { useState, useMemo } from 'react';
import type { ActivityFilters } from '../services/api';
import { clipSm } from '../constants/style';
import { sourceTheme as sourceConfig } from '../constants/style';
import { useFilterOptions } from '../hooks/useDetections';
import { Section } from './intel/Section';
import { RepoHealthStrip } from './intel/RepoHealthStrip';
import { PulseBanner } from './intel/PulseBanner';
import { UpstreamReleases } from './intel/UpstreamReleases';
import { NotableNewRulesSection } from './intel/NotableNewRules';
import {
  TrendingTechniquesList,
  TrendingPlatformsList,
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

function GroupHeader({
  eyebrow,
  title,
  subtitle,
  right,
}: {
  eyebrow: string;
  title: string;
  subtitle?: string;
  right?: React.ReactNode;
}) {
  return (
    <div className="flex items-end justify-between gap-4 flex-wrap border-t border-void-700 pt-4">
      <div>
        <div className="text-[10px] font-mono text-matrix-400 uppercase tracking-[0.25em] mb-1">
          {eyebrow}
        </div>
        <h2 className="text-lg font-display font-bold text-white tracking-wider uppercase">
          {title}
        </h2>
        {subtitle && (
          <p className="text-[11px] text-gray-500 mt-0.5 font-mono">
            {subtitle}
          </p>
        )}
      </div>
      {right}
    </div>
  );
}

export function IndustryIntel() {
  // The window toggle controls only the Activity group below. Catalog
  // sections are unwindowed (fixed 12-week sparkline / latest-N
  // releases) — see the module docstring for the layout rationale.
  const [period, setPeriod] = useState(30);
  const [sourceFilter, setSourceFilter] = useState<string[]>([]);

  const filters = useMemo<ActivityFilters>(
    () => (sourceFilter.length ? { sources: sourceFilter } : {}),
    [sourceFilter],
  );

  const windowToggle = (
    <div
      className="flex items-center gap-1"
      role="radiogroup"
      aria-label="Time window for the Activity group"
    >
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
  );

  return (
    <div className="space-y-8">
      {/* Page header — no toggle here on purpose. The toggle only
          scopes the Activity group, so it lives with that group's
          header below, not up here where it would falsely imply
          it controls Repo Health. Subtitle folds in what used to
          be the CATALOG / CURRENT STATE eyebrow so the eye reaches
          real data after one heading, not four. */}
      <div>
        <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">
          Detection Intelligence
        </h1>
        <p className="text-xs text-gray-500 mt-1 font-mono">
          repo health + activity across every upstream detection-rule repo we track
        </p>
      </div>

      {/* Catalog: always-current, unwindowed. Was preceded by
          CATALOG / CURRENT STATE headings -- removed since the
          section title carries enough context on its own. */}
      <Section title="Repo Health" subtitle="12-week trend per repo · click a card to filter the catalog">
        <RepoHealthStrip />
      </Section>

      {/* ── ACTIVITY ── windowed sections ─────────────────────── */}
      <GroupHeader
        eyebrow="Activity"
        title={`In the last ${period} days`}
        subtitle="every section below is scoped to the selected window"
        right={windowToggle}
      />

      <PulseBanner days={period} />

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
            </div>
          </div>
        </div>
      </Section>

      {/* Upstream Releases lives at the very bottom -- large blocks
          of markdown release notes shouldn't push the higher-signal
          activity data off-screen. Expanded body is capped to 400px
          with an inner scroll so a long Elastic release note doesn't
          own the viewport. */}
      <Section title="Upstream Releases" subtitle="latest tagged releases · sigma · splunk · elastic">
        <UpstreamReleases />
      </Section>
    </div>
  );
}
