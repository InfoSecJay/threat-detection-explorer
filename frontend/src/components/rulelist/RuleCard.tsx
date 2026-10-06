/** Compact card for the detections list under 640px (teardown R18 / #116).
 * The table shows only the Title column on a phone; the card keeps
 * source, severity and completeness on screen. Bulk-select and the
 * inline preview are desktop affordances -- the detail page is one tap
 * away, so the whole card just navigates. */

import { useNavigate } from 'react-router-dom';
import { severityLabel, sourceColors, sourceLabelsShort as sourceLabels } from '../../constants/sources';
import type { Detection } from '../../types';
import { severityColors, qualityBand, formatRelativeDate } from './format';
import { whereItApplies } from '../../constants/taxonomy';

export function RuleCard({ detection }: { detection: Detection }) {
  const navigate = useNavigate();
  const sevColors = severityColors[detection.severity] || severityColors.unknown;
  const sourceColor = sourceColors[detection.source] || '#6b7280';
  const lang =
    detection.language && detection.language !== 'unknown'
      ? detection.language.toUpperCase()
      : null;
  const meta = [whereItApplies(detection)[0], detection.data_sources?.[0], formatRelativeDate(detection.rule_created_date)]
    .filter(Boolean)
    .join(' · ');

  return (
    <button
      type="button"
      onClick={() => navigate(`/detections/${detection.id}`)}
      className="block w-full text-left px-3 py-2.5 hover:bg-void-800/50 transition-colors"
      data-testid={`rule-card-${detection.id}`}
    >
      <div className="text-sm font-medium text-matrix-500 leading-snug line-clamp-2">
        {detection.title}
      </div>
      {detection.content_snippet && (
        <div className="mt-1 text-[11px] font-mono text-gray-500 line-clamp-2" data-testid="card-snippet">
          {detection.content_snippet.negated && (
            <span
              className="mr-1.5 px-1 rounded border border-amber-500/30 text-amber-300 font-sans text-[10px] uppercase tracking-wide"
              title="The term appears only inside an exclusion (NOT / allowlist); this rule does not detect it"
            >
              excluded
            </span>
          )}
          {detection.content_snippet.before}
          <mark className="bg-cyan-500/20 text-cyan-300 rounded px-0.5">{detection.content_snippet.match}</mark>
          {detection.content_snippet.after}
        </div>
      )}
      <div className="mt-1.5 flex items-center gap-2 flex-wrap">
        <span
          className="px-1.5 py-0.5 text-[10px] font-mono font-medium border"
          style={{
            backgroundColor: `${sourceColor}15`,
            color: sourceColor,
            borderColor: `${sourceColor}40`,
          }}
        >
          {sourceLabels[detection.source] || detection.source.toUpperCase()}
          {lang && <span className="opacity-60"> · {lang}</span>}
        </span>
        <span
          className={`px-1.5 py-0.5 text-[10px] font-mono font-medium border ${sevColors.bg} ${sevColors.text} ${sevColors.border}`}
          title={detection.severity === 'unknown' ? 'The source publishes no severity for this rule' : undefined}
        >
          {severityLabel(detection.severity).toUpperCase()}
        </span>
        {typeof detection.quality_score === 'number' && (
          <span
            className={`px-1.5 py-0.5 text-[10px] font-mono border tabular-nums ${qualityBand(detection.quality_score)}`}
            title="Metadata completeness"
          >
            {detection.quality_score}
          </span>
        )}
      </div>
      {meta && (
        <div className="mt-1 text-[11px] font-mono text-dim-400 truncate">{meta}</div>
      )}
    </button>
  );
}
