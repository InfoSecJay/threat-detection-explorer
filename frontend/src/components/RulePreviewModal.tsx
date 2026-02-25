import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism';
import type { Detection } from '../types';
import { sourceColors, sourceLabels, severityTailwind } from '../constants/sources';
import { useMitre } from '../contexts/MitreContext';

const languageMap: Record<string, string> = {
  sigma: 'yaml',
  yaml: 'yaml',
  eql: 'sql',
  kql: 'sql',
  esql: 'sql',
  spl: 'sql',
  splunk: 'sql',
  mql: 'javascript',
  yara: 'c',
  lucene: 'javascript',
  json: 'json',
  unknown: 'yaml',
};

interface RulePreviewModalProps {
  detection: Detection | null;
  isOpen: boolean;
  onClose: () => void;
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async (e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      onClick={handleCopy}
      className="px-2 py-1 text-[10px] font-mono border border-void-600 text-gray-400 hover:text-matrix-500 hover:border-matrix-500/30 transition-colors"
    >
      {copied ? 'COPIED' : 'COPY'}
    </button>
  );
}

function BadgePill({
  text,
  className,
}: {
  text: string;
  className: string;
}) {
  return (
    <span
      className={`inline-block px-2 py-0.5 text-[11px] font-mono border ${className}`}
    >
      {text}
    </span>
  );
}

export function RulePreviewModal({
  detection,
  isOpen,
  onClose,
}: RulePreviewModalProps) {
  const { getTechniqueName, getTacticName, getTechniqueUrl } = useMitre();

  // Escape key to close
  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  // Prevent body scroll when open
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
    return () => {
      document.body.style.overflow = '';
    };
  }, [isOpen]);

  if (!isOpen || !detection) return null;

  const sourceColor = sourceColors[detection.source] || '#6b7280';
  const prismLang =
    languageMap[detection.language || 'unknown'] || 'yaml';

  const hasObservables =
    (detection.extracted_event_ids?.length || 0) > 0 ||
    (detection.extracted_process_names?.length || 0) > 0 ||
    (detection.extracted_api_actions?.length || 0) > 0 ||
    (detection.extracted_source_tables?.length || 0) > 0 ||
    (detection.extracted_file_paths?.length || 0) > 0 ||
    (detection.extracted_network_indicators?.length || 0) > 0 ||
    (detection.extracted_registry_keys?.length || 0) > 0 ||
    (detection.extracted_target_resources?.length || 0) > 0;

  return (
    <div
      className="fixed inset-0 bg-black/75 flex items-start justify-center z-50 p-4 pt-8 overflow-y-auto"
      onClick={onClose}
    >
      <div
        className="bg-void-900 border border-void-600 w-full max-w-5xl relative"
        style={{
          clipPath:
            'polygon(0 0, calc(100% - 20px) 0, 100% 20px, 100% 100%, 20px 100%, 0 calc(100% - 20px))',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Source color accent bar */}
        <div
          className="h-1"
          style={{
            background: `linear-gradient(to right, ${sourceColor}, ${sourceColor}80, transparent)`,
          }}
        />

        {/* ── Header ──────────────────────────────────────────────────────── */}
        <div className="px-6 pt-4 pb-3 border-b border-void-700">
          <div className="flex items-start justify-between gap-4">
            <div className="flex-1 min-w-0">
              {/* Badges row */}
              <div className="flex items-center gap-2 flex-wrap mb-2">
                <span
                  className="px-2 py-0.5 text-[11px] font-mono font-semibold uppercase"
                  style={{
                    backgroundColor: `${sourceColor}20`,
                    color: sourceColor,
                    border: `1px solid ${sourceColor}50`,
                  }}
                >
                  {sourceLabels[detection.source] || detection.source}
                </span>
                <BadgePill
                  text={detection.severity.toUpperCase()}
                  className={
                    severityTailwind[detection.severity] ||
                    severityTailwind.unknown
                  }
                />
                {detection.language && detection.language !== 'unknown' && (
                  <BadgePill
                    text={detection.language.toUpperCase()}
                    className="bg-indigo-500/15 text-indigo-400 border-indigo-500/30"
                  />
                )}
                {detection.platform && (
                  <BadgePill
                    text={detection.platform.toUpperCase()}
                    className="bg-cyan-500/15 text-cyan-400 border-cyan-500/30"
                  />
                )}
                {detection.status && detection.status !== 'unknown' && (
                  <BadgePill
                    text={detection.status.toUpperCase()}
                    className={
                      detection.status === 'stable'
                        ? 'bg-green-500/15 text-green-400 border-green-500/30'
                        : detection.status === 'experimental'
                          ? 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30'
                          : 'bg-gray-500/15 text-gray-400 border-gray-500/30'
                    }
                  />
                )}
                {detection.query_complexity &&
                  detection.query_complexity !== 'unknown' && (
                    <BadgePill
                      text={detection.query_complexity.toUpperCase()}
                      className="bg-purple-500/15 text-purple-400 border-purple-500/30"
                    />
                  )}
              </div>

              {/* Title */}
              <h2 className="text-lg font-display font-bold text-white leading-tight">
                {detection.title}
              </h2>
            </div>

            {/* Close button */}
            <button
              onClick={onClose}
              className="text-gray-500 hover:text-white transition-colors flex-shrink-0 p-1"
            >
              <svg
                className="w-5 h-5"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M6 18L18 6M6 6l12 12"
                />
              </svg>
            </button>
          </div>
        </div>

        {/* ── Body (scrollable) ───────────────────────────────────────────── */}
        <div className="px-6 py-4 space-y-5 max-h-[70vh] overflow-y-auto">
          {/* Description */}
          {detection.description && (
            <div>
              <p className="text-sm text-gray-300 leading-relaxed line-clamp-4">
                {detection.description}
              </p>
            </div>
          )}

          {/* Metadata row */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {detection.author && (
              <div>
                <span className="text-[10px] font-mono text-gray-600 uppercase block">
                  Author
                </span>
                <span className="text-xs text-gray-300">
                  {detection.author}
                </span>
              </div>
            )}
            {detection.rule_created_date && (
              <div>
                <span className="text-[10px] font-mono text-gray-600 uppercase block">
                  Created
                </span>
                <span className="text-xs text-gray-300">
                  {new Date(detection.rule_created_date).toLocaleDateString()}
                </span>
              </div>
            )}
            {detection.rule_modified_date && (
              <div>
                <span className="text-[10px] font-mono text-gray-600 uppercase block">
                  Modified
                </span>
                <span className="text-xs text-gray-300">
                  {new Date(detection.rule_modified_date).toLocaleDateString()}
                </span>
              </div>
            )}
            {detection.event_category && (
              <div>
                <span className="text-[10px] font-mono text-gray-600 uppercase block">
                  Event Category
                </span>
                <span className="text-xs text-gray-300">
                  {detection.event_category}
                </span>
              </div>
            )}
          </div>

          {/* MITRE ATT&CK */}
          {(detection.mitre_techniques?.length > 0 ||
            detection.mitre_tactics?.length > 0) && (
            <div>
              <h3 className="text-[10px] font-mono text-gray-600 uppercase mb-2">
                MITRE ATT&CK
              </h3>
              <div className="space-y-2">
                {detection.mitre_techniques?.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {detection.mitre_techniques.map((tech) => {
                      const name = getTechniqueName(tech);
                      const url = getTechniqueUrl(tech);
                      return (
                        <a
                          key={tech}
                          href={url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 px-2 py-0.5 bg-blue-500/10 text-blue-400 border border-blue-500/20 text-[11px] font-mono hover:bg-blue-500/20 transition-colors"
                          onClick={(e) => e.stopPropagation()}
                        >
                          {tech}
                          {name && (
                            <span className="text-blue-400/60 text-[10px]">
                              {name}
                            </span>
                          )}
                        </a>
                      );
                    })}
                  </div>
                )}
                {detection.mitre_tactics?.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {detection.mitre_tactics.map((tactic) => {
                      const name = getTacticName(tactic);
                      return (
                        <span
                          key={tactic}
                          className="px-2 py-0.5 bg-purple-500/10 text-purple-400 border border-purple-500/20 text-[11px] font-mono"
                        >
                          {name || tactic}
                        </span>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Extracted Observables */}
          {hasObservables && (
            <div>
              <h3 className="text-[10px] font-mono text-gray-600 uppercase mb-2">
                Extracted Observables
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {detection.extracted_event_ids?.length > 0 && (
                  <ObservableGroup
                    label="Event IDs"
                    items={detection.extracted_event_ids}
                    color="amber"
                  />
                )}
                {detection.extracted_process_names?.length > 0 && (
                  <ObservableGroup
                    label="Process Names"
                    items={detection.extracted_process_names}
                    color="green"
                  />
                )}
                {detection.extracted_api_actions?.length > 0 && (
                  <ObservableGroup
                    label="API Actions"
                    items={detection.extracted_api_actions}
                    color="cyan"
                  />
                )}
                {detection.extracted_source_tables?.length > 0 && (
                  <ObservableGroup
                    label="Source Tables"
                    items={detection.extracted_source_tables}
                    color="indigo"
                  />
                )}
                {detection.extracted_file_paths?.length > 0 && (
                  <ObservableGroup
                    label="File Paths"
                    items={detection.extracted_file_paths}
                    color="orange"
                  />
                )}
                {detection.extracted_network_indicators?.length > 0 && (
                  <ObservableGroup
                    label="Network Indicators"
                    items={detection.extracted_network_indicators}
                    color="rose"
                  />
                )}
                {detection.extracted_registry_keys?.length > 0 && (
                  <ObservableGroup
                    label="Registry Keys"
                    items={detection.extracted_registry_keys}
                    color="yellow"
                  />
                )}
                {detection.extracted_target_resources?.length > 0 && (
                  <ObservableGroup
                    label="Target Resources"
                    items={detection.extracted_target_resources}
                    color="pink"
                  />
                )}
              </div>
            </div>
          )}

          {/* Detection Logic */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-[10px] font-mono text-gray-600 uppercase">
                Detection Logic
                {detection.language && (
                  <span className="ml-2 text-gray-500">
                    ({detection.language})
                  </span>
                )}
              </h3>
              <CopyButton text={detection.detection_logic || ''} />
            </div>
            <div className="max-h-72 overflow-y-auto border border-void-700 rounded">
              <SyntaxHighlighter
                language={prismLang}
                style={oneDark}
                showLineNumbers
                customStyle={{
                  margin: 0,
                  padding: '12px',
                  fontSize: '12px',
                  lineHeight: '1.5',
                  background: '#0d1117',
                }}
                lineNumberStyle={{
                  color: '#333',
                  fontSize: '10px',
                  paddingRight: '12px',
                }}
              >
                {detection.detection_logic || ''}
              </SyntaxHighlighter>
            </div>
          </div>
        </div>

        {/* ── Footer ──────────────────────────────────────────────────────── */}
        <div className="px-6 py-3 border-t border-void-700 flex items-center justify-between">
          <div className="flex items-center gap-3">
            {detection.source_rule_url && (
              <a
                href={detection.source_rule_url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[11px] font-mono text-gray-500 hover:text-matrix-500 transition-colors"
              >
                VIEW SOURCE
              </a>
            )}
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={onClose}
              className="px-3 py-1.5 text-xs font-mono text-gray-400 border border-void-600 hover:text-white hover:border-void-500 transition-colors"
            >
              CLOSE
            </button>
            <Link
              to={`/detections/${detection.id}`}
              className="px-3 py-1.5 text-xs font-mono font-semibold bg-matrix-500/15 text-matrix-500 border border-matrix-500/30 hover:bg-matrix-500/25 transition-colors"
            >
              VIEW FULL DETAIL
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Observable Group Sub-component ──────────────────────────────────────────

const colorMap: Record<string, string> = {
  amber: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  green: 'bg-green-500/10 text-green-400 border-green-500/20',
  cyan: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
  indigo: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20',
  orange: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  rose: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
  yellow: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  pink: 'bg-pink-500/10 text-pink-400 border-pink-500/20',
};

function ObservableGroup({
  label,
  items,
  color,
}: {
  label: string;
  items: string[];
  color: string;
}) {
  const cls = colorMap[color] || colorMap.cyan;
  const maxShow = 6;
  const shown = items.slice(0, maxShow);
  const remaining = items.length - maxShow;

  return (
    <div>
      <span className="text-[10px] font-mono text-gray-600 block mb-1">
        {label}
      </span>
      <div className="flex flex-wrap gap-1">
        {shown.map((item) => (
          <span
            key={item}
            className={`px-1.5 py-0.5 text-[10px] font-mono border ${cls}`}
          >
            {item}
          </span>
        ))}
        {remaining > 0 && (
          <span className="text-[10px] font-mono text-gray-600 py-0.5">
            +{remaining} more
          </span>
        )}
      </div>
    </div>
  );
}
