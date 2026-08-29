/** One catalog row plus its optional inline preview. */

import { Fragment } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { sourceColors, sourceLabelsShort as sourceLabels } from '../../constants/sources';
import type { Detection } from '../../types';
import { severityColors, qualityBand, formatRelativeDate, formatDate } from './format';
import { TagList } from './TagList';
import { RulePreview } from './RulePreview';

interface RuleRowProps {
  detection: Detection;
  enableSelection: boolean;
  selected: boolean;
  expanded: boolean;
  onToggleSelect: (e: React.MouseEvent) => void;
  onToggleExpand: (e: React.MouseEvent) => void;
}

export function RuleRow({ detection, enableSelection, selected, expanded, onToggleSelect, onToggleExpand }: RuleRowProps) {
  const navigate = useNavigate();
  const sevColors = severityColors[detection.severity] || severityColors.unknown;
  const sourceColor = sourceColors[detection.source] || '#6b7280';
  // SOURCE · LANG merged chip. The language suffix only carries
  // information when it is a real value -- lolrmm and freshly-ingested
  // rules have language "unknown".
  const lang =
    detection.language && detection.language !== 'unknown'
      ? detection.language.toUpperCase()
      : null;

  return (
    <Fragment>
      <tr
        className={`hover:bg-void-800/50 cursor-pointer transition-colors ${
          selected ? 'bg-matrix-500/5' : ''
        }`}
        onClick={() => navigate(`/detections/${detection.id}`)}
      >
        {enableSelection && (
          <td className="px-3 py-3" onClick={(e) => e.stopPropagation()}>
            <input
              type="checkbox"
              checked={selected}
              onChange={() => {}}
              onClick={(e) => onToggleSelect(e)}
                      className="w-3.5 h-3.5 rounded-sm bg-void-900 border-void-600 text-matrix-500 focus:ring-matrix-500/50 disabled:opacity-50"
            />
          </td>
        )}
        <td className="px-2 py-3" onClick={(e) => e.stopPropagation()}>
          <button
            onClick={(e) => onToggleExpand(e)}
            className="p-1 text-gray-500 hover:text-matrix-500 transition-colors"
            aria-expanded={expanded}
            aria-label={expanded ? 'Collapse rule preview' : 'Expand rule preview'}
            title={expanded ? 'Collapse preview' : 'Preview query logic, references, FP notes'}
          >
            <svg
              className={`w-4 h-4 transition-transform ${expanded ? 'rotate-180' : ''}`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
        </td>
        <td className="px-4 py-3 max-w-md">
          <Link
            to={`/detections/${detection.id}`}
            className="text-sm font-medium text-matrix-500 hover:text-matrix-400 transition-colors"
            onClick={(e) => e.stopPropagation()}
            title={detection.description || undefined}
          >
            {detection.title}
          </Link>
          {detection.is_building_block && (
            <span
              className="ml-2 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide border bg-fuchsia-500/15 text-fuchsia-300 border-fuchsia-500/30 align-middle"
              title="Building block: feeds other rules, does not alert on its own"
            >
              BB
            </span>
          )}
        </td>
        <td className="px-3 py-3 whitespace-nowrap">
          <span
            className="px-2 py-1 text-xs font-mono font-medium border"
            style={{
              backgroundColor: `${sourceColor}15`,
              color: sourceColor,
              borderColor: `${sourceColor}40`,
            }}
          >
            {sourceLabels[detection.source] || detection.source.toUpperCase()}
            {lang && <span className="opacity-60"> · {lang}</span>}
          </span>
        </td>
        <td className="px-3 py-3 whitespace-nowrap">
          <span
            className={`px-2 py-1 text-xs font-mono font-medium border ${sevColors.bg} ${sevColors.text} ${sevColors.border}`}
          >
            {detection.severity.toUpperCase()}
          </span>
        </td>
        <td className="px-3 py-3">
          <TagList
            items={detection.platforms}
            colorClass="bg-cyan-500/10 text-cyan-300 border-cyan-500/30"
          />
        </td>
        <td className="px-3 py-3">
          <TagList
            items={detection.data_sources}
            colorClass="bg-emerald-500/10 text-emerald-300 border-emerald-500/30"
          />
        </td>
        <td className="px-3 py-3">
          <TagList
            items={detection.event_types}
            colorClass="bg-orange-500/10 text-orange-300 border-orange-500/30"
          />
        </td>
        <td className="px-3 py-3 whitespace-nowrap">
          <span
            className="text-xs font-mono text-gray-400"
            title={formatDate(detection.rule_created_date)}
          >
            {formatRelativeDate(detection.rule_created_date)}
          </span>
        </td>
        <td className="px-3 py-3 whitespace-nowrap">
          <span
            className="text-xs font-mono text-gray-400"
            title={formatDate(detection.rule_modified_date)}
          >
            {formatRelativeDate(detection.rule_modified_date)}
          </span>
        </td>
        <td className="px-3 py-3 whitespace-nowrap">
          {typeof detection.quality_score === 'number' ? (
            <span
              className={`px-1.5 py-0.5 text-xs font-mono border tabular-nums ${qualityBand(detection.quality_score)}`}
              title="Hygiene score (0-100): rule hygiene, not detection accuracy"
            >
              {detection.quality_score}
            </span>
          ) : (
            <span className="text-xs text-gray-600">-</span>
          )}
        </td>
      </tr>
      {expanded && <RulePreview detection={detection} lang={lang} colSpan={enableSelection ? 11 : 10} />}
    </Fragment>
  );
}
