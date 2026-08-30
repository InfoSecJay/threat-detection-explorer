/** Hygiene score (issue #10): five dimensions, 20 points each, 100
 * total. It measures rule HYGIENE -- is the rule documented, mapped,
 * specific and testable -- not whether it catches the attacker.
 *
 * Every check is listed with its points so the number is explainable:
 * the backend returns per-dimension score + the issues that failed;
 * the rubric text below mirrors backend/app/services/quality_score.py
 * (RUBRIC_VERSION 1) and marks a check failed when its issue string
 * is present. */

import { useState } from 'react';
import type { Detection } from '../../types';

type Check = { label: string; points: string; issue?: string | string[] };

const DIMENSIONS: Record<string, { title: string; meaning: string; checks: Check[] }> = {
  metadata: {
    title: 'Metadata',
    meaning: 'Can the rule be identified, attributed and traced?',
    checks: [
      { label: 'Title of 10+ characters', points: '4', issue: 'title missing or trivial' },
      { label: 'Description of 20+ characters', points: '4', issue: 'no meaningful description' },
      { label: 'Stable rule id', points: '3', issue: 'no stable rule id' },
      { label: 'Author', points: '3', issue: 'no author' },
      { label: 'At least one reference', points: '3', issue: 'no references' },
      { label: 'Creation or modification date', points: '3', issue: 'no creation/modification date' },
    ],
  },
  mitre: {
    title: 'MITRE ATT&CK',
    meaning: 'Is the rule mapped to what it detects?',
    checks: [
      { label: 'At least one technique', points: '8', issue: 'no ATT&CK technique mapping' },
      { label: 'Two or more techniques', points: '3' },
      { label: 'Sub-technique precision (Txxxx.yyy)', points: '3', issue: 'no sub-technique precision' },
      { label: 'Tactic', points: '4', issue: 'no ATT&CK tactic' },
      { label: 'Threat actor or software tag', points: '2' },
    ],
  },
  specificity: {
    title: 'Specificity',
    meaning: 'How much telemetry does the logic actually constrain?',
    checks: [
      { label: 'Query complexity: simple 4, moderate 8, complex 12', points: 'up to 12', issue: 'query complexity unknown' },
      { label: 'Telemetry fields the logic tests (1 each)', points: 'up to 8', issue: 'no telemetry fields extracted' },
    ],
  },
  documentation: {
    title: 'Documentation',
    meaning: 'Would an analyst know what fired and what to do?',
    checks: [
      { label: 'Description length: 20+ chars 2, 80+ 5, 200+ 8', points: 'up to 8', issue: 'description too short to guide triage' },
      { label: 'Concrete false-positive analysis (boilerplate scores 3)', points: '8', issue: ['no false-positive analysis', 'false positives are boilerplate, not analysis'] },
      { label: 'Investigation guidance in the text (verify, check, review...)', points: '4', issue: 'no investigation guidance' },
    ],
  },
  testability: {
    title: 'Testability',
    meaning: 'Can the rule be triggered and its rationale reproduced?',
    checks: [
      { label: 'Atomic Red Team reference', points: '8', issue: 'no Atomic Red Team reference' },
      { label: 'Threat-research reference (vendor labs, blogs, papers)', points: '6', issue: 'no threat-research reference' },
      { label: 'Emulation / detonation mention', points: '3' },
      { label: 'Embedded test cases in the rule file', points: '3', issue: 'no embedded test cases' },
    ],
  },
};

function bandClass(score: number, of: number): string {
  if (score >= of * 0.75) return 'bg-green-500';
  if (score >= of * 0.4) return 'bg-amber-500';
  return 'bg-red-500';
}

export function HygieneBars({ details }: { details: NonNullable<Detection['quality_details']> }) {
  const [open, setOpen] = useState(false);
  const applicable = details.applicable_points ?? 100;
  return (
    <div data-testid="hygiene">
      {/* The caveat leads (teardown F09): say what this is NOT before showing a number. */}
      <p className="text-[11px] text-gray-500 mb-1.5">
        Measures how completely the rule is documented, mapped and testable{' '}
        <span className="text-gray-400">within what its format can express</span> -- not whether it
        catches the attacker.
      </p>
      <div className="flex items-baseline gap-3 mb-2 flex-wrap">
        <label className="text-xs font-medium text-gray-500 uppercase tracking-wide">Metadata completeness</label>
        <span className="text-lg font-mono font-bold text-white tabular-nums">{details.total}<span className="text-gray-500 text-sm">/100</span></span>
        {applicable < 100 && (
          <span className="text-[11px] text-gray-500" data-testid="hygiene-applicable">
            scored over the {applicable} points this format can express
          </span>
        )}
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          className="text-[11px] font-mono text-matrix-500 hover:text-matrix-400 uppercase tracking-wider ml-auto"
          aria-expanded={open}
          data-testid="hygiene-explain"
        >
          {open ? '[ hide scoring ]' : '[ how is this scored? ]'}
        </button>
      </div>

      {/* Fixed columns so rows line up whether or not a dimension has issues. */}
      <div className="space-y-1.5">
        {Object.entries(details.dimensions).map(([name, dim]) => {
          const meta = DIMENSIONS[name];
          return (
            <div key={name} className="grid grid-cols-[8rem_minmax(0,1fr)_3.5rem_4.5rem] items-center gap-3" data-testid={`hygiene-${name}`}>
              <span className="text-[11px] font-mono text-gray-400 uppercase truncate" title={meta?.meaning}>
                {meta?.title || name}
              </span>
              <div className="h-1.5 bg-void-800 rounded overflow-hidden">
                <div className={`h-full ${bandClass(dim.score, dim.of)}`} style={{ width: `${(dim.score / dim.of) * 100}%` }} />
              </div>
              <span className="text-[11px] font-mono text-gray-300 tabular-nums text-right">{dim.score}/{dim.of}</span>
              <span className="text-[10px] font-mono text-gray-600 text-right cursor-help" title={dim.issues.join('\n') || 'all checks passed'}>
                {dim.issues.length > 0 ? `${dim.issues.length} issue${dim.issues.length > 1 ? 's' : ''}` : 'complete'}
              </span>
            </div>
          );
        })}
      </div>

      {open && (
        <div className="mt-3 border border-void-700 bg-void-900/60 p-3 space-y-3" data-testid="hygiene-rubric">
          <p className="text-xs text-gray-400">
            Dimensions are weighted so no single concern dominates. Checks a rule&apos;s format cannot express -- an
            MQL email rule has no ATT&amp;CK tag field, Sentinel YAML has no false-positive field -- are excluded
            from both sides of the score and shown as <span className="text-gray-500 font-mono">n/a</span>, so
            formats are graded on their own rubric, not each other&apos;s schema. Checks are deterministic (same
            rule, same score, no models). Failed checks are listed under each dimension; unlisted checks passed or
            are bonuses that do not report when missing.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {Object.entries(details.dimensions).map(([name, dim]) => {
              const meta = DIMENSIONS[name];
              if (!meta) return null;
              return (
                <div key={name}>
                  <div className="flex items-baseline justify-between">
                    <span className="text-[11px] font-mono text-gray-300 uppercase">{meta.title}</span>
                    <span className="text-[11px] font-mono text-gray-500 tabular-nums">{dim.score}/{dim.of}</span>
                  </div>
                  <p className="text-[11px] text-gray-500 mb-1">{meta.meaning}</p>
                  <ul className="space-y-0.5">
                    {meta.checks.map((c) => {
                      const issues = c.issue === undefined ? [] : Array.isArray(c.issue) ? c.issue : [c.issue];
                      const na = issues.some((i) => (dim.na ?? []).includes(i));
                      const failed = !na && issues.some((i) => dim.issues.includes(i));
                      const bonus = issues.length === 0;
                      if (na) {
                        return (
                          <li key={c.label} className="flex items-baseline justify-between gap-2 text-[11px] opacity-50">
                            <span className="text-gray-600 line-through decoration-void-600">{c.label}</span>
                            <span className="font-mono text-gray-600 shrink-0">n/a</span>
                          </li>
                        );
                      }
                      return (
                        <li key={c.label} className="flex items-baseline gap-2 text-[11px]">
                          <span className={`font-mono w-3 shrink-0 ${failed ? 'text-red-400' : bonus ? 'text-gray-600' : 'text-green-400'}`}>
                            {failed ? 'x' : bonus ? '+' : 'ok'}
                          </span>
                          <span className={`flex-1 ${failed ? 'text-gray-300' : 'text-gray-500'}`}>{c.label}</span>
                          <span className="font-mono text-gray-600 tabular-nums shrink-0">{c.points}</span>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
