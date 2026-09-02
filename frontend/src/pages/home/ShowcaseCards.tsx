/**
 * The three destinations beyond search, as cards: a one-line value
 * proposition, one concrete live fact, and the link. A card is a
 * summary plus an entry point, not the page itself.
 */

import { Link } from 'react-router-dom';
import { useCoverageMatrix } from '../../hooks/useCompare';
import { useActorsQuery } from '../../hooks/useActors';
import { useSourceDeltas } from '../../hooks/useTrending';
import { clipMd } from '../../constants/style';
import { BAKED_SNAPSHOT } from '../../constants/snapshot';
import { countryFlag } from '../../utils/actorDisplay';

// Literal class names so Tailwind generates them (template strings are
// invisible to its scanner).
const ACCENTS = {
  matrix: { border: 'hover:border-matrix-500/50', text: 'text-matrix-400', hover: 'group-hover:text-matrix-300' },
  breach: { border: 'hover:border-breach-500/50', text: 'text-breach-400', hover: 'group-hover:text-breach-300' },
  pulse: { border: 'hover:border-pulse-500/50', text: 'text-pulse-400', hover: 'group-hover:text-pulse-300' },
} as const;

function Card({
  to, kicker, title, blurb, fact, cta, accent, testId,
}: {
  to: string;
  kicker: string;
  title: string;
  blurb: string;
  fact: React.ReactNode;
  cta: string;
  accent: keyof typeof ACCENTS;
  testId: string;
}) {
  const a = ACCENTS[accent];
  return (
    <Link
      to={to}
      className={`group relative flex flex-col bg-void-850 border border-void-700 ${a.border} p-5 transition-colors`}
      style={clipMd}
      data-testid={testId}
    >
      <div className={`text-[10px] font-mono uppercase tracking-[0.2em] ${a.text} mb-2`}>{kicker}</div>
      <h3 className="text-lg font-display font-bold text-white tracking-wider uppercase mb-2">{title}</h3>
      <p className="text-sm text-gray-400 leading-relaxed mb-4">{blurb}</p>
      <div className="mt-auto pt-3 border-t border-void-800 text-xs font-mono text-gray-300" data-testid={`${testId}-fact`}>
        {fact}
      </div>
      <div className={`mt-3 text-[11px] font-mono uppercase tracking-wider ${a.text} ${a.hover}`}>
        {cta} &#8594;
      </div>
    </Link>
  );
}

export function ShowcaseCards() {
  const { data: coverage } = useCoverageMatrix({ include_subtechniques: false });
  const { data: gaps } = useActorsQuery({ kind: 'groups', sort: 'weighted_gap', order: 'desc', page: 1, per_page: 1 });
  const { data: deltas } = useSourceDeltas(7);

  const top = gaps?.items?.[0];
  // Live summary first; the build-time snapshot only bridges the first
  // paint (#82 S2.7).
  const coverageFact = coverage
    ? { percent: coverage.summary.overall_coverage_percent, covered: coverage.summary.techniques_with_any_coverage, total: coverage.summary.total_techniques }
    : BAKED_SNAPSHOT?.coverage ?? null;
  const netWeek = deltas ? Object.values(deltas.by_source).reduce((n, s) => n + (s.delta ?? 0), 0) : null;

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      <Card
        to="/mitre"
        kicker="MITRE ATT&CK"
        title="Coverage browser"
        blurb="Every tactic and technique with the rules behind it, per vendor. See which technique each source detects and how, and where the whole ecosystem is blind."
        fact={
          coverageFact
            ? <><span className="text-white">{coverageFact.percent}%</span> of parent techniques have at least one rule · {coverageFact.covered} / {coverageFact.total}</>
            : 'loading coverage…'
        }
        cta="Browse ATT&CK"
        accent="matrix"
        testId="card-mitre"
      />
      <Card
        to="/actors"
        kicker="Threat actors & software"
        title="Coverage gaps"
        blurb="Every ATT&CK group and tool ranked by the distinctive techniques nobody has a rule for, with per-vendor heatmaps and Navigator layer export."
        fact={
          top
            ? <>Biggest gap right now: <span className="text-white">{top.origin_country ? `${countryFlag(top.origin_country)} ` : ''}{top.name}</span> · {top.gap_count} of {top.technique_count} techniques uncovered</>
            : 'loading ranking…'
        }
        cta="Explore actors"
        accent="breach"
        testId="card-actors"
      />
      <Card
        to="/intel"
        kicker="Detection intelligence"
        title="Repo health & activity"
        blurb="What changed across every upstream repo: new and modified rules, trending techniques and platforms, newly covered techniques, and each repo's twelve-week pulse."
        fact={
          netWeek !== null
            ? <><span className="text-white">{netWeek > 0 ? '+' : ''}{netWeek.toLocaleString()}</span> rules net across all repos in the last 7 days</>
            : 'loading activity…'
        }
        cta="See what changed"
        accent="pulse"
        testId="card-intel"
      />
    </div>
  );
}
