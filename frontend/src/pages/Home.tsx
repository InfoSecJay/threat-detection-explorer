/**
 * Home -- a live console, not a brochure.
 *
 * The page's one job is to get a detection engineer into the catalog
 * with a real query and show that the corpus is alive. Top to bottom:
 *
 *   Hero + query bar   the search box is the first control, with
 *                      example queries that teach the field syntax
 *   Ticker             one status line: rules, net change this week,
 *                      newly covered, momentum, last sync (signature)
 *   This week          net change by source / just covered / momentum
 *   Where the gaps are top actors by uncovered distinctive TTPs
 *   Sources            one card per repo with its live numbers
 *   Hygiene            score-band bar for the whole corpus
 *   How it works       four lines + methodology link
 *
 * Every number on the page comes from an endpoint the Intel, Actors,
 * or Detections pages already use; nothing here is a separate
 * computation that could drift.
 */

import { Link } from 'react-router-dom';
import { ThreatRadar } from '../components/graphics/ThreatRadar';
import { useStatistics } from '../hooks/useDetections';
import { ALL_SOURCES } from '../constants/sources';
import { HeroSearch } from './home/HeroSearch';
import { Ticker } from './home/Ticker';
import { ThisWeek } from './home/ThisWeek';
import { GapSpotlight } from './home/GapSpotlight';
import { SourceGrid } from './home/SourceGrid';
import { HygieneBar } from './home/HygieneBar';

function SectionHeader({ title, subtitle, right }: { title: string; subtitle?: string; right?: React.ReactNode }) {
  return (
    <div className="flex items-end gap-4 mb-4">
      <div>
        <h2 className="text-lg font-display font-bold text-white tracking-wider uppercase">{title}</h2>
        {subtitle && <p className="text-[11px] font-mono text-gray-500 mt-0.5">{subtitle}</p>}
      </div>
      <div className="flex-1 h-px bg-gradient-to-r from-void-700 to-transparent mb-2" />
      {right}
    </div>
  );
}

const HOW_IT_WORKS: { step: string; text: string }[] = [
  { step: 'Aggregate', text: `Nightly clones of ${ALL_SOURCES.length} open detection repositories, pinned to a commit.` },
  { step: 'Normalize', text: 'Sigma, TOML, SPL, KQL, MQL, YARA-L and Python rules mapped to one schema and one platform / data-source / event-type taxonomy.' },
  { step: 'Extract', text: 'Process names, paths, registry keys, event IDs, API actions and indicators pulled from each rule\'s logic, typed and searchable.' },
  { step: 'Map', text: 'ATT&CK techniques, actors and software overlaid with coverage, gaps and momentum -- linked back to the upstream file.' },
];

export function Home() {
  const { data: stats, isLoading, error, refetch } = useStatistics();

  return (
    <div className="space-y-12">
      {/* Hero: thesis + the query bar */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 bg-hero-radial pointer-events-none" />
        <div className="absolute inset-0 bg-grid-pattern bg-grid opacity-30 pointer-events-none" />

        <div className="relative grid lg:grid-cols-[1fr_auto] gap-8 items-center pt-8 pb-6 lg:pt-12 lg:pb-8">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1.5 bg-void-800 border border-void-600 rounded mb-5">
              <span className="w-2 h-2 bg-pulse-500 rounded-full animate-pulse" />
              <span className="text-xs font-mono text-gray-400">
                <span className="text-pulse-400">OPERATIONAL</span> // {ALL_SOURCES.length} INTEL FEEDS ACTIVE
              </span>
            </div>
            <h1 className="text-3xl md:text-4xl lg:text-5xl font-display font-bold tracking-wider mb-3">
              <span className="text-white">THREAT </span>
              <span className="text-matrix-500 text-glow-sm">DETECTION </span>
              <span className="text-white">EXPLORER</span>
            </h1>
            <p className="text-base text-gray-400 max-w-2xl mb-6 font-sans">
              Every open-source detection rule, in one schema, with the observables and ATT&amp;CK coverage
              extracted so you can ask the questions vendors&apos; own repos can&apos;t answer.
            </p>
            <HeroSearch />
          </div>

          <div className="hidden lg:block relative w-64 h-64 xl:w-80 xl:h-80 justify-self-end">
            <ThreatRadar className="w-full h-full opacity-70" />
            <div className="absolute -top-2 left-1/2 -translate-x-1/2 text-[10px] font-mono text-matrix-500/60">THREAT_INTEL</div>
            <div className="absolute -bottom-2 left-1/2 -translate-x-1/2 text-[10px] font-mono text-matrix-500/60">COVERAGE_MAP</div>
          </div>
        </div>
      </section>

      {/* Signature: the status ticker */}
      <Ticker />

      {/* Statistics failed: say so instead of silently dropping sections (#51). */}
      {!isLoading && error && !stats && (
        <section
          className="bg-void-850 border border-breach-500/30 px-5 py-4 flex items-center justify-between gap-4 flex-wrap"
          role="alert"
        >
          <div>
            <div className="text-[10px] font-mono text-breach-400 uppercase tracking-[0.2em] mb-1">Corpus statistics</div>
            <div className="text-sm font-mono text-gray-300">Unavailable: {error.message}</div>
          </div>
          <button
            onClick={() => refetch()}
            className="px-3 py-1.5 text-xs font-mono uppercase tracking-wider border border-breach-500/40 text-breach-400 hover:bg-breach-500/10 transition-colors"
          >
            [ retry ]
          </button>
        </section>
      )}

      <section>
        <SectionHeader title="This week" subtitle="what changed across the corpus in the last 7 days" right={<Link to="/digest" className="text-[10px] font-mono text-gray-500 hover:text-matrix-400 uppercase tracking-wider mb-2">Weekly digest &#8594;</Link>} />
        <ThisWeek />
      </section>

      <section>
        <SectionHeader title="Where the gaps are" subtitle="actors with the most uncovered, distinctive techniques" right={<span className="flex gap-3 mb-2"><Link to="/actors/heatmap" className="text-[10px] font-mono text-gray-500 hover:text-matrix-400 uppercase tracking-wider">Heatmap &#8594;</Link><Link to="/actors" className="text-[10px] font-mono text-gray-500 hover:text-matrix-400 uppercase tracking-wider">All actors &#8594;</Link></span>} />
        <GapSpotlight />
      </section>

      <section>
        <SectionHeader title="Sources" subtitle="rule count, net change this week, hygiene average, last sync -- click a source to browse it" right={<Link to="/integrations" className="text-[10px] font-mono text-gray-500 hover:text-matrix-400 uppercase tracking-wider mb-2">Sync status &#8594;</Link>} />
        <div className="space-y-3">
          <SourceGrid />
          <HygieneBar />
        </div>
      </section>

      <section>
        <SectionHeader title="How it works" right={<Link to="/about" className="text-[10px] font-mono text-gray-500 hover:text-matrix-400 uppercase tracking-wider mb-2">What we count &#8594;</Link>} />
        <ol className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
          {HOW_IT_WORKS.map((h) => (
            <li key={h.step} className="bg-void-850 border border-void-700 px-4 py-3">
              <div className="text-[11px] font-display font-semibold uppercase tracking-wider text-matrix-400 mb-1">{h.step}</div>
              <p className="text-xs text-gray-400 leading-relaxed">{h.text}</p>
            </li>
          ))}
        </ol>
      </section>
    </div>
  );
}
