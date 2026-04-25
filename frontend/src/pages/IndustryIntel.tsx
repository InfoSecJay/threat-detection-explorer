/**
 * Detection Intelligence — what the industry is watching right now.
 *
 * This page is composition only. Each section lives in its own
 * sub-module under ./intel/ and owns its own data hooks. The page
 * itself just holds two pieces of state:
 *   - trendingPeriod: the time window threaded into every section
 *     that supports one (Pulse, Threat Pulse, Trending Techniques,
 *     Trending Platforms).
 *   - filters: the source/platform narrowing applied to the
 *     Notable New Rules + trending lists. Excluded from the
 *     platforms-trending query because that one would be circular.
 */

import { useState, useMemo } from 'react';
import type { ActivityFilters } from '../services/api';
import { clipSm } from '../constants/style';
import { Section } from './intel/Section';
import { PulseBanner } from './intel/PulseBanner';
import { ThreatPulseSection } from './intel/ThreatPulse';
import { UpstreamReleases } from './intel/UpstreamReleases';
import { NotableNewRulesSection } from './intel/NotableNewRules';
import { TrendingTechniquesList, TrendingPlatformsList } from './intel/Trending';
import { ActivityFilterBar } from './intel/ActivityFilterBar';
import { periodOptions } from './intel/lib';

export function IndustryIntel() {
  const [trendingPeriod, setTrendingPeriod] = useState(90);
  const [filters, setFilters] = useState<ActivityFilters>({});

  // The platforms-trending query intentionally drops its `platforms`
  // filter — it's the grouping key, filtering by it would collapse
  // the result to that one platform.
  const platformsTrendingFilters = useMemo(() => {
    const { platforms: _p, ...rest } = filters;
    return rest;
  }, [filters]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">
          Detection Intelligence
        </h1>
        <p className="text-xs text-gray-500 mt-0.5 font-mono">
          WHAT_THE_INDUSTRY_IS_WATCHING // NAMED_THREATS // CVE_COVERAGE // UPSTREAM_ACTIVITY
        </p>
      </div>

      <PulseBanner days={trendingPeriod} />

      <Section
        title="Threat Pulse"
        subtitle="named threats from vendor story tags · CVEs across all sources"
      >
        <ThreatPulseSection days={trendingPeriod} />
      </Section>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Section title="Upstream Releases" subtitle="sigma · splunk · elastic">
          <UpstreamReleases />
        </Section>

        <Section title="Notable New Rules" subtitle="latest across all sources">
          <NotableNewRulesSection filters={filters} />
        </Section>
      </div>

      <Section
        title="Catalog Activity"
        subtitle={`trending over last ${trendingPeriod}d — filter to narrow`}
        action={
          <div className="flex items-center gap-1">
            {periodOptions.map((opt) => (
              <button
                key={opt.value}
                onClick={() => setTrendingPeriod(opt.value)}
                className={`px-2 py-0.5 text-[10px] font-mono uppercase transition-colors ${
                  trendingPeriod === opt.value
                    ? 'bg-matrix-500/20 text-matrix-400 border border-matrix-500/30'
                    : 'bg-void-800 text-gray-500 border border-void-700 hover:text-white'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
        }
      >
        <div className="space-y-3">
          <ActivityFilterBar filters={filters} setFilters={setFilters} />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="bg-void-850 border border-void-700 p-3" style={clipSm}>
              <div className="flex items-center gap-2 mb-2">
                <span className="w-1.5 h-1.5 rounded-full bg-matrix-500" />
                <h3 className="font-display font-semibold text-[11px] uppercase tracking-wider text-matrix-400">
                  Trending MITRE Techniques
                </h3>
              </div>
              <TrendingTechniquesList days={trendingPeriod} filters={filters} />
            </div>
            <div className="bg-void-850 border border-void-700 p-3" style={clipSm}>
              <div className="flex items-center gap-2 mb-2">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-500" />
                <h3 className="font-display font-semibold text-[11px] uppercase tracking-wider text-cyan-400">
                  Trending Platforms
                </h3>
              </div>
              <TrendingPlatformsList days={trendingPeriod} filters={platformsTrendingFilters} />
            </div>
          </div>
        </div>
      </Section>
    </div>
  );
}
