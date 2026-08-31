/**
 * /methodology (#90 / teardown F15): the site's strongest trust
 * artifact -- what we count and why -- promoted from the bottom of
 * /about to its own URL, linked from the nav and from headline
 * numbers. The table itself renders from /api/methodology, which
 * reads the ingester's own discovery config, so it cannot drift from
 * what the nightly sync actually does.
 */

import { Link } from 'react-router-dom';
import { MethodologySection } from '../components/MethodologySection';
import { useDocumentMeta } from '../hooks/useDocumentMeta';
import { clipMd } from '../constants/style';

function Principle({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-void-850 border border-void-700 p-5" style={clipMd}>
      <h3 className="text-sm font-display font-bold text-white tracking-wider uppercase mb-2">{title}</h3>
      <p className="text-sm text-gray-400">{children}</p>
    </div>
  );
}

export function Methodology() {
  useDocumentMeta(
    'Methodology',
    'What Detection Explorer counts and why: pinned commits, discovery globs, exclusions, drift alerting, scoring, and permalink guarantees.',
  );
  return (
    <div className="space-y-8 max-w-6xl mx-auto" data-testid="methodology-page">
      <div>
        <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">Methodology</h1>
        <p className="text-sm text-gray-400 mt-2 max-w-3xl">
          Every headline number on this site is reproducible. This page states the scope choices behind the
          counts, how the corpus stays honest between syncs, and what you can rely on when you link here.
        </p>
      </div>

      <MethodologySection />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Principle title="Nightly sync">
          Every source is re-cloned at its pinned branch nightly; rules are re-parsed, re-normalized and
          re-scored from scratch. After each sync the upstream tree is re-fetched via the GitHub API and our
          discovered count is checked against it, alerting past 5% drift.
        </Principle>
        <Principle title="Canonical taxonomy">
          Vendor logsources resolve to one platform / data-source / event-type vocabulary through per-vendor
          mapping files; rules the resolver cannot place show <span className="font-mono">unknown</span>{' '}
          rather than a guess. The mapping files and their drift reports are public in the repo.
        </Principle>
        <Principle title="Metadata completeness score">
          Deterministic checks over documentation, ATT&amp;CK mapping, specificity and testability -- scored
          only against what each rule format can express, renormalized to 100 over the applicable points.
          It measures rule metadata, never detection accuracy, and no page ranks sources against each other
          on it.
        </Principle>
        <Principle title="Observables">
          Process names, event IDs, registry keys, API actions, paths and network indicators are extracted
          from the detection logic itself by per-language parsers; negated values, wildcards and placeholders
          never reach the observable surfaces.
        </Principle>
      </div>

      <div className="bg-void-850 border border-void-700 p-5" style={clipMd} data-testid="permalink-guarantee">
        <h3 className="text-sm font-display font-bold text-white tracking-wider uppercase mb-2">Permalink guarantee</h3>
        <p className="text-sm text-gray-400">
          Rule URLs are stable for the life of the site. Each rule&apos;s id derives deterministically from its
          source and the id its vendor publishes, so links survive upstream file moves, renames and full
          rebuilds. Links using a vendor&apos;s own rule id redirect to the same page, and ids from before this
          guarantee redirect permanently to their new home.
        </p>
      </div>

      <div className="bg-void-850 border border-void-700 p-5" style={clipMd}>
        <h3 className="text-sm font-display font-bold text-white tracking-wider uppercase mb-2">Licensing</h3>
        <p className="text-sm text-gray-400">
          Detection Explorer itself is Apache-2.0 (
          <a
            href="https://github.com/InfoSecJay/threat-detection-explorer"
            target="_blank"
            rel="noopener noreferrer"
            className="text-matrix-500 hover:text-matrix-400"
          >
            source on GitHub
          </a>
          ). The rules it indexes remain under their upstream repositories&apos; own licenses -- check the
          source repo before redistributing rule content, especially into commercial or managed-service
          contexts.
        </p>
      </div>

      <p className="text-xs font-mono text-gray-600">
        Questions about a specific count?{' '}
        <a
          href="https://github.com/InfoSecJay/threat-detection-explorer/issues"
          target="_blank"
          rel="noopener noreferrer"
          className="text-matrix-500 hover:text-matrix-400"
        >
          Open an issue
        </a>
        {' '}· more about the project on the <Link to="/about" className="text-matrix-500 hover:text-matrix-400">About page</Link>.
      </p>
    </div>
  );
}
