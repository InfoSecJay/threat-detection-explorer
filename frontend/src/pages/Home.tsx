/**
 * Home -- the table of contents, not a dashboard.
 *
 * Three things, in the order a first visit needs them:
 *
 *   Hero       one sentence of scope, the query bar, example queries,
 *              and four exact numbers (rules, repos, ATT&CK techniques
 *              covered, last sync)
 *   Sources    every repository we ingest, its live count and format
 *   Showcase   the three destinations beyond search -- ATT&CK coverage,
 *              actor gaps, repo intelligence -- each with one live fact
 *
 * Everything else (digest, observables, query reference, methodology)
 * is one line of links. No tickers, no feeds: numbers stand still.
 */

import { Link } from 'react-router-dom';
import { useStatistics } from '../hooks/useDetections';
import { ALL_SOURCES } from '../constants/sources';
import { HeroSearch } from './home/HeroSearch';
import { StatsStrip } from './home/StatsStrip';
import { SourcesBand } from './home/SourcesBand';
import { ShowcaseCards } from './home/ShowcaseCards';

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

const MORE: { to: string; label: string; hint: string }[] = [
  { to: '/digest', label: 'Weekly digest', hint: 'what shipped upstream this week, with RSS' },
  { to: '/observables', label: 'Observables', hint: 'the processes, event IDs, paths and indicators rules key on' },
  { to: '/query', label: 'Query reference', hint: 'every field the search bar understands' },
  { to: '/about', label: 'Methodology', hint: 'what we count and how' },
];

export function Home() {
  const { data: stats, isLoading, error, refetch } = useStatistics();

  return (
    <div className="space-y-14">
      {/* Hero: scope in one sentence, then the query bar */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 bg-hero-radial pointer-events-none" />
        <div className="absolute inset-0 bg-grid-pattern bg-grid opacity-30 pointer-events-none" />
        <div className="relative max-w-4xl pt-8 pb-2 lg:pt-12">
          <div className="text-[10px] font-mono text-matrix-500 uppercase tracking-[0.25em] mb-4">
            Open detection rules · one schema · ATT&amp;CK-mapped
          </div>
          <h1 className="text-3xl md:text-4xl lg:text-5xl font-display font-bold tracking-wider mb-4">
            <span className="text-matrix-500 text-glow-sm">DETECTION </span>
            <span className="text-white">EXPLORER</span>
          </h1>
          <p className="text-base md:text-lg text-gray-400 max-w-3xl mb-6 font-sans">
            {stats ? stats.total.toLocaleString() : 'Every'} detection rule{stats ? 's' : ''} from {ALL_SOURCES.length} open-source
            repositories, normalized to one schema, mapped to MITRE ATT&amp;CK, with the observables each rule keys on extracted
            and searchable.
          </p>
          <HeroSearch />
          <StatsStrip />
        </div>
      </section>

      {/* Statistics failed: say so instead of silently dropping numbers (#51). */}
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
        <SectionHeader
          title="What we ingest"
          subtitle="Sigma, TOML, SPL, KQL, EQL, ES|QL, MQL, YARA-L, OIE and Python rules, nightly, into one schema and one platform / data-source / event-type taxonomy"
          right={<Link to="/integrations" className="text-[10px] font-mono text-gray-500 hover:text-matrix-400 uppercase tracking-wider mb-2">Sync status &#8594;</Link>}
        />
        <SourcesBand />
      </section>

      <section>
        <SectionHeader title="Beyond search" subtitle="what the normalized corpus lets you ask" />
        <ShowcaseCards />
      </section>

      <section className="border-t border-void-800 pt-6">
        <ul className="flex flex-wrap gap-x-8 gap-y-3">
          {MORE.map((m) => (
            <li key={m.to}>
              <Link to={m.to} className="group text-sm">
                <span className="font-display font-semibold text-gray-200 group-hover:text-matrix-400 transition-colors uppercase tracking-wider text-xs">{m.label}</span>
                <span className="text-[11px] font-mono text-gray-600 ml-2">{m.hint}</span>
              </Link>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
