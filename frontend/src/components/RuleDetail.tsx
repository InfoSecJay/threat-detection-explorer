/** Single-rule page, laid out like an Elastic rule: header with the
 * identity chips, then ABOUT (what it is, who wrote it, how to triage
 * it) on the left and DEFINITION (where it reads from, the query, the
 * fields and observables it keys on) on the right. "View source"
 * swaps the definition for the upstream file as-is. Sections live in
 * components/ruledetail/. */

import { parseApiDate } from '../utils/dates';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import type { Detection } from '../types';
import { ObservablesPanel } from './ObservablesPanel';
import { useEventIds } from '../hooks/useEventIds';
import { CopyButton } from './ruledetail/CopyButton';
import { CodeBlock } from './ruledetail/CodeBlock';
import { AttackSection } from './ruledetail/AttackSection';
import { HygieneBars } from './ruledetail/HygieneBars';
import { RelatedRules } from './ruledetail/RelatedRules';
import { useDocumentMeta } from '../hooks/useDocumentMeta';
import { sourceTheme } from '../constants/style';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

interface RuleDetailProps {
  detection: Detection;
}

const severityColors: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-green-500/20 text-green-400 border-green-500/30',
  unknown: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};

const statusColors: Record<string, string> = {
  stable: 'bg-green-500/20 text-green-400 border-green-500/30',
  test: 'bg-sky-500/20 text-sky-400 border-sky-500/30',
  experimental: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  deprecated: 'bg-red-500/20 text-red-400 border-red-500/30',
  unsupported: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  unknown: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};

const LANGUAGE_LABEL: Record<string, string> = {
  sigma: 'Sigma', spl: 'SPL', eql: 'EQL', kql: 'KQL', esql: 'ES|QL', mql: 'MQL', yaral: 'YARA-L',
  oie: 'Okta expression', python: 'Python', panther: 'Panther declarative', panther_correlation: 'Panther correlation',
};

function fmt(iso: string | null | undefined): string {
  if (!iso) return 'unknown';
  const d = parseApiDate(iso);
  return isNaN(d.getTime()) ? 'unknown' : d.toLocaleDateString();
}

/** Label / value row, Elastic style. */
function Row({ label, children, testId }: { label: string; children: React.ReactNode; testId?: string }) {
  return (
    <div className="grid grid-cols-[9rem_minmax(0,1fr)] gap-3 py-2 border-b border-void-800 last:border-b-0" data-testid={testId}>
      <div className="text-xs font-semibold text-gray-400 pt-0.5">{label}</div>
      <div className="text-sm text-gray-200 min-w-0">{children}</div>
    </div>
  );
}

function Chips({ items, tone, unknownTone = false }: { items: string[] | undefined | null; tone: string; unknownTone?: boolean }) {
  if (!items || items.length === 0) return <span className="text-gray-600 text-xs italic">none</span>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((v) => (
        <span key={v} className={`inline-flex px-2 py-0.5 rounded text-xs font-mono border ${unknownTone && v === 'unknown' ? 'bg-gray-500/20 text-gray-400 border-gray-500/30 italic' : tone}`}>{v}</span>
      ))}
    </div>
  );
}

function Card({ title, children, right, testId }: { title: string; children: React.ReactNode; right?: React.ReactNode; testId?: string }) {
  return (
    <section className="bg-void-850 rounded-xl border border-void-700" data-testid={testId}>
      <div className="px-5 py-3 border-b border-void-700 flex items-center justify-between gap-3 flex-wrap">
        <h2 className="text-lg font-display font-bold text-white tracking-wider uppercase">{title}</h2>
        {right}
      </div>
      <div className="px-5 py-2">{children}</div>
    </section>
  );
}

export function RuleDetail({ detection }: RuleDetailProps) {
  const { labels: eventIdLabels } = useEventIds();
  useDocumentMeta(detection.title, detection.description);
  const [aboutTab, setAboutTab] = useState<'details' | 'guide'>('details');
  const [viewSource, setViewSource] = useState(false);
  const src = sourceTheme[detection.source];
  const language = LANGUAGE_LABEL[(detection.language || '').toLowerCase()] || (detection.language || 'unknown');
  const hasObservables = (detection.extracted_observables?.length ?? 0) > 0 || (detection.extracted_source_tables?.length ?? 0) > 0;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="bg-void-850 rounded-xl border border-void-700 overflow-hidden">
        <div className={`h-1 ${src?.dot || 'bg-gray-500'}`} />
        <div className="px-6 py-4">
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 mb-2 flex-wrap">
                <span className={`px-2 py-0.5 rounded text-xs font-semibold uppercase border ${src?.bg || 'bg-void-700'} ${src?.text || 'text-gray-300'} ${src?.border || 'border-void-600'}`}>
                  {src?.name || detection.source}
                </span>
                <span className="px-2 py-0.5 bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 rounded text-xs font-semibold">{language}</span>
                <span className={`px-2 py-0.5 rounded text-xs font-semibold capitalize border ${severityColors[detection.severity] || severityColors.unknown}`}>{detection.severity}</span>
                <span className={`px-2 py-0.5 rounded text-xs font-semibold capitalize border ${statusColors[detection.status] || statusColors.unknown}`}>{detection.status}</span>
                {detection.is_building_block && (
                  <span className="px-2 py-0.5 rounded text-xs font-semibold border bg-fuchsia-500/20 text-fuchsia-300 border-fuchsia-500/30" title="Building block: emits signal for other rules to correlate on; does not alert on its own">
                    Building block
                  </span>
                )}
              </div>
              <h1 className="text-xl font-bold text-white">{detection.title}</h1>
              <p className="text-xs text-gray-500 mt-1 font-mono" data-testid="rule-byline">
                Created by {detection.author || 'unknown'} on {fmt(detection.rule_created_date)} · Updated {fmt(detection.rule_modified_date)} · Synced {fmt(detection.updated_at)}
              </p>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={() => setViewSource((v) => !v)}
                aria-pressed={viewSource}
                className={`px-3 py-1.5 rounded-lg text-sm font-medium border transition-colors ${viewSource ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40' : 'bg-void-700 text-gray-300 border-transparent hover:bg-void-600 hover:text-white'}`}
                data-testid="view-source"
              >
                {viewSource ? 'View definition' : 'View source'}
              </button>
              {detection.source_rule_url && (
                <a href={detection.source_rule_url} target="_blank" rel="noopener noreferrer" className="px-3 py-1.5 bg-void-700 hover:bg-void-600 text-gray-300 hover:text-white rounded-lg text-sm font-medium transition-colors">
                  Upstream &#8599;
                </a>
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)] gap-4 items-start">
        {/* ABOUT */}
        <Card
          title="About"
          testId="about-card"
          right={
            <div className="flex gap-1 text-xs" role="tablist" aria-label="About tabs">
              {([['details', 'Details'], ['guide', 'Investigation guide']] as const).map(([k, label]) => (
                <button key={k} role="tab" aria-selected={aboutTab === k} onClick={() => setAboutTab(k)}
                  className={`px-3 py-1 rounded-md font-medium transition-colors ${aboutTab === k ? 'bg-cyan-500/20 text-cyan-300' : 'text-gray-400 hover:text-white'}`}>
                  {label}
                </button>
              ))}
            </div>
          }
        >
          {aboutTab === 'guide' ? (
            detection.investigation_guide ? (
              <div className="py-3 prose prose-invert prose-sm max-w-none prose-headings:font-display prose-headings:uppercase prose-headings:tracking-wider prose-a:text-cyan-400 prose-code:text-matrix-300 prose-pre:bg-void-900" data-testid="guide-markdown">
                <p className="not-prose text-[10px] font-mono text-gray-500 uppercase tracking-wider mb-3">Vendor-authored guide, from the upstream rule</p>
                <ReactMarkdown remarkPlugins={[remarkGfm]}>{detection.investigation_guide}</ReactMarkdown>
              </div>
            ) : (
              <div className="py-6 text-center" data-testid="guide-placeholder">
                <p className="text-sm text-gray-300">No investigation guide for this rule.</p>
                <p className="text-xs text-gray-500 mt-1">
                  Elastic rules ship one upstream (shown here when present); guides for the other sources will be generated per rule from its logic, observables and references. Until then, the description and false-positive notes under Details are the triage material.
                </p>
              </div>
            )
          ) : (
            <div>
              {detection.description && (
                <p className="text-sm text-gray-300 leading-relaxed py-2 border-b border-void-800">{detection.description}</p>
              )}
              <Row label="Author">{detection.author || <span className="text-gray-600 italic text-xs">unknown</span>}</Row>
              <Row label="Severity"><span className="capitalize">{detection.severity}</span></Row>
              <Row label="Status"><span className="capitalize">{detection.status}</span></Row>
              <Row label="Rule ID"><span className="font-mono text-xs break-all">{detection.rule_id || 'N/A'}</span></Row>
              {detection.quality_details && (
                <div className="py-3 border-b border-void-800"><HygieneBars details={detection.quality_details} /></div>
              )}
              <Row label="Reference URLs">
                {detection.references && detection.references.length > 0 ? (
                  <ul className="space-y-1">
                    {detection.references.map((ref, i) => (
                      <li key={i}>
                        {ref.startsWith('http') ? (
                          <a href={ref} target="_blank" rel="noopener noreferrer" className="text-xs text-cyan-400 hover:text-cyan-300 hover:underline break-all">{ref}</a>
                        ) : (
                          <span className="text-xs text-gray-400">{ref}</span>
                        )}
                      </li>
                    ))}
                  </ul>
                ) : <span className="text-gray-600 text-xs italic">none</span>}
              </Row>
              <Row label="False positive examples">
                {detection.false_positives && detection.false_positives.length > 0 ? (
                  <ul className="space-y-1 list-disc pl-4">
                    {detection.false_positives.map((fp, i) => <li key={i} className="text-xs text-gray-300">{fp}</li>)}
                  </ul>
                ) : <span className="text-gray-600 text-xs italic">none documented</span>}
              </Row>
              <div className="py-2 border-b border-void-800">
                <AttackSection detection={detection} />
              </div>
              {(detection.use_cases?.length ?? 0) > 0 && (
                <Row label="Use cases"><Chips items={detection.use_cases} tone="bg-void-700 text-gray-300 border-void-600" /></Row>
              )}
              <Row label="Tags">
                {detection.tags.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {detection.tags.slice(0, 16).map((t) => <span key={t} className="px-2 py-0.5 bg-void-700 text-gray-400 rounded text-xs">{t}</span>)}
                    {detection.tags.length > 16 && <span className="px-2 py-0.5 text-gray-500 text-xs">+{detection.tags.length - 16} more</span>}
                  </div>
                ) : <span className="text-gray-600 text-xs italic">none</span>}
              </Row>
              <Row label="Source file"><span className="font-mono text-xs text-gray-400 break-all">{detection.source_file}</span></Row>
            </div>
          )}
        </Card>

        {/* DEFINITION */}
        <div className="space-y-4">
          <Card
            title={viewSource ? 'Source' : 'Definition'}
            testId="definition-card"
            right={
              viewSource
                ? (detection.raw_content ? <CopyButton text={detection.raw_content} label="Copy source" /> : null)
                : (detection.detection_logic ? <CopyButton text={detection.detection_logic} label="Copy query" /> : null)
            }
          >
            {viewSource ? (
              <div className="py-2" data-testid="raw-source">
                <CodeBlock language={detection.language} code={detection.raw_content} fallback="No raw content available" />
              </div>
            ) : (
              <div>
                <Row label="Source tables / indices" testId="def-tables"><Chips items={detection.extracted_source_tables} tone="bg-emerald-500/15 text-emerald-300 border-emerald-500/30" /></Row>
                <Row label="Data sources"><Chips items={detection.data_sources} tone="bg-emerald-500/15 text-emerald-300 border-emerald-500/30" unknownTone /></Row>
                <Row label="Platforms"><Chips items={detection.platforms} tone="bg-cyan-500/15 text-cyan-300 border-cyan-500/30" unknownTone /></Row>
                <Row label="Event types"><Chips items={detection.event_types} tone="bg-orange-500/15 text-orange-300 border-orange-500/30" unknownTone /></Row>
                <Row label="Rule type"><span className="text-xs">{language}{detection.query_complexity ? <span className="text-gray-500"> · {detection.query_complexity} complexity</span> : null}</span></Row>
                <div className="py-3 border-b border-void-800" data-testid="def-query">
                  <div className="text-xs font-semibold text-gray-400 mb-2">Query</div>
                  <CodeBlock language={detection.language} code={detection.detection_logic} fallback="No detection logic available" />
                </div>
                <Row label="Required fields" testId="def-fields">
                  <Chips items={detection.extracted_fields_used} tone="bg-void-700 text-gray-300 border-void-600" />
                </Row>
              </div>
            )}
          </Card>

          {!viewSource && hasObservables && (
            <Card title="Observables" testId="observables-card">
              <div className="py-2">
                <ObservablesPanel
                  observables={detection.extracted_observables || []}
                  sourceTables={detection.extracted_source_tables || []}
                  complexity={detection.query_complexity}
                  eventIdLabels={eventIdLabels}
                />
              </div>
            </Card>
          )}

          {!viewSource && <RelatedRules id={detection.id} source={detection.source} />}
        </div>
      </div>

      <div className="flex justify-center pt-2">
        <Link
          to={detection.mitre_techniques.length > 0
            ? `/detections?mitre_techniques=${detection.mitre_techniques[0]}`
            : `/detections?search=${encodeURIComponent(detection.title.split(' ').slice(0, 3).join(' '))}`}
          className="inline-flex items-center gap-2 px-6 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-400 hover:to-blue-400 text-white rounded-lg font-medium transition-all shadow-glow-cyan"
        >
          Find related detections
        </Link>
      </div>
    </div>
  );
}
