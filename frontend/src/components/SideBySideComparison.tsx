import { useState } from 'react';
import { Link } from 'react-router-dom';
import { sourceColors, sourceLabelsShort as sourceLabels } from '../constants/sources';
import type { Detection, SideBySideResponse } from '../types';

function CopyButton({ text, label = 'COPY' }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback for older browsers
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <button
      onClick={handleCopy}
      className={`flex items-center gap-1 px-2 py-1 rounded text-[10px] font-mono transition-all ${
        copied
          ? 'bg-matrix-500/20 text-matrix-400'
          : 'bg-white/5 text-gray-500 hover:bg-white/10 hover:text-gray-300'
      }`}
      title={copied ? 'Copied!' : `Copy ${label.toLowerCase()}`}
    >
      {copied ? (
        <>
          <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
          COPIED
        </>
      ) : (
        <>
          <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
          </svg>
          {label}
        </>
      )}
    </button>
  );
}

interface SideBySideComparisonProps {
  data: SideBySideResponse;
}

const severityConfig: Record<string, { color: string; glow: string }> = {
  critical: { color: '#ef4444', glow: '0 0 20px rgba(239, 68, 68, 0.4)' },
  high: { color: '#f97316', glow: '0 0 20px rgba(249, 115, 22, 0.4)' },
  medium: { color: '#eab308', glow: '0 0 20px rgba(234, 179, 8, 0.4)' },
  low: { color: '#22c55e', glow: '0 0 20px rgba(34, 197, 94, 0.4)' },
  unknown: { color: '#6b7280', glow: 'none' },
};

interface RulePanelProps {
  detection: Detection;
}

function RulePanel({ detection }: RulePanelProps) {
  const sourceColor = sourceColors[detection.source] || '#6b7280';
  const severity = severityConfig[detection.severity] || severityConfig.unknown;

  return (
    <div
      className="relative flex flex-col h-full overflow-hidden"
      style={{
        background: 'linear-gradient(180deg, rgba(15, 23, 42, 0.95) 0%, rgba(10, 15, 30, 0.98) 100%)',
        borderRadius: '2px',
      }}
    >
      {/* Top accent line with source color */}
      <div
        className="absolute top-0 left-0 right-0 h-[3px]"
        style={{
          background: `linear-gradient(90deg, ${sourceColor} 0%, ${sourceColor}40 50%, transparent 100%)`,
        }}
      />

      {/* Subtle corner accents */}
      <div
        className="absolute top-0 right-0 w-16 h-16 opacity-20"
        style={{
          background: `radial-gradient(circle at top right, ${sourceColor}40 0%, transparent 70%)`,
        }}
      />

      {/* Header Section */}
      <div className="relative px-5 pt-5 pb-4 border-b border-white/5">
        {/* Source Badge */}
        <div className="flex items-center justify-between mb-3">
          <div
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-sm"
            style={{
              backgroundColor: `${sourceColor}15`,
              border: `1px solid ${sourceColor}30`,
            }}
          >
            <div
              className="w-2 h-2 rounded-full animate-pulse"
              style={{ backgroundColor: sourceColor, boxShadow: `0 0 8px ${sourceColor}` }}
            />
            <span
              className="text-xs font-mono font-bold tracking-wider"
              style={{ color: sourceColor }}
            >
              {sourceLabels[detection.source] || detection.source.toUpperCase()}
            </span>
          </div>

          {/* Severity Indicator */}
          <div
            className="flex items-center gap-2 px-2 py-1"
            style={{
              backgroundColor: `${severity.color}10`,
              borderRadius: '2px',
            }}
          >
            <div
              className="w-1.5 h-1.5 rounded-full"
              style={{
                backgroundColor: severity.color,
                boxShadow: severity.glow,
              }}
            />
            <span
              className="text-[10px] font-mono uppercase tracking-wider"
              style={{ color: severity.color }}
            >
              {detection.severity}
            </span>
          </div>
        </div>

        {/* Title */}
        <Link
          to={`/detections/${detection.id}`}
          className="block group"
        >
          <h3
            className="text-base font-semibold text-gray-100 leading-tight group-hover:text-white transition-colors line-clamp-2"
            title={detection.title}
          >
            {detection.title}
          </h3>
          <div className="mt-1 h-px w-0 group-hover:w-full transition-all duration-300" style={{ backgroundColor: sourceColor }} />
        </Link>

        {/* Platform Badge */}
        {detection.platform && (
          <div className="mt-3 flex items-center gap-2">
            <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">PLATFORM</span>
            <span className="text-xs font-mono text-gray-400">{detection.platform}</span>
          </div>
        )}
      </div>

      {/* Description Section */}
      <div className="px-5 py-4 border-b border-white/5">
        <div className="flex items-center gap-2 mb-2">
          <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">DESCRIPTION</span>
        </div>
        <p className="text-sm text-gray-400 leading-relaxed line-clamp-4">
          {detection.description || 'No description available'}
        </p>
      </div>

      {/* Detection Logic - The Main Event */}
      <div
        className="flex-1 overflow-auto"
        style={{ scrollbarGutter: 'stable' }}
      >
        <div className="px-5 py-4">
          {/* Logic Header */}
          <div className="flex items-center justify-between mb-3 sticky top-0 bg-inherit py-2 -my-2">
            <div className="flex items-center gap-1.5">
              <svg className="w-4 h-4 text-matrix-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
              </svg>
              <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">DETECTION LOGIC</span>
            </div>
            <div className="flex items-center gap-2">
              {detection.detection_logic && (
                <CopyButton text={detection.detection_logic} label="COPY" />
              )}
              <span
                className="text-[10px] font-mono px-2 py-1 rounded"
                style={{
                  backgroundColor: `${sourceColor}15`,
                  color: sourceColor,
                }}
              >
                {detection.language?.toUpperCase() || 'UNKNOWN'}
              </span>
            </div>
          </div>

          {/* Code Block */}
          <div
            className="relative rounded overflow-hidden"
            style={{
              background: 'linear-gradient(135deg, rgba(0, 0, 0, 0.4) 0%, rgba(0, 0, 0, 0.2) 100%)',
              border: '1px solid rgba(255, 255, 255, 0.05)',
            }}
          >
            {/* Code gutter effect */}
            <div
              className="absolute left-0 top-0 bottom-0 w-1 opacity-50"
              style={{ backgroundColor: sourceColor }}
            />

            <pre
              className="p-4 pl-5 text-[13px] font-mono text-gray-300 overflow-x-auto whitespace-pre-wrap leading-relaxed"
              style={{
                fontFamily: "'JetBrains Mono', 'Fira Code', 'SF Mono', Consolas, monospace",
                tabSize: 2,
              }}
            >
              {detection.detection_logic || 'No detection logic available'}
            </pre>
          </div>
        </div>
      </div>

      {/* Bottom Status Bar */}
      <div
        className="px-5 py-2 border-t border-white/5 flex items-center justify-between"
        style={{ backgroundColor: 'rgba(0, 0, 0, 0.2)' }}
      >
        <div className="flex items-center gap-3">
          <span className="text-[10px] font-mono text-gray-600">
            {detection.detection_logic?.split('\n').length || 0} lines
          </span>
          <span className="text-gray-700">•</span>
          <span className="text-[10px] font-mono text-gray-600">
            {detection.detection_logic?.length || 0} chars
          </span>
        </div>
        <Link
          to={`/detections/${detection.id}`}
          className="text-[10px] font-mono text-gray-500 hover:text-matrix-400 transition-colors"
        >
          VIEW FULL →
        </Link>
      </div>
    </div>
  );
}

export function SideBySideComparison({ data }: SideBySideComparisonProps) {
  const numPanels = data.detections.length;

  // Calculate grid columns based on number of detections
  const getGridStyle = () => {
    if (numPanels === 2) return { gridTemplateColumns: 'repeat(2, 1fr)' };
    if (numPanels === 3) return { gridTemplateColumns: 'repeat(3, 1fr)' };
    if (numPanels <= 4) return { gridTemplateColumns: 'repeat(2, 1fr)' };
    return { gridTemplateColumns: 'repeat(3, 1fr)' };
  };

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div
        className="flex items-center justify-between px-5 py-4 rounded"
        style={{
          background: 'linear-gradient(90deg, rgba(0, 255, 204, 0.05) 0%, transparent 50%, rgba(0, 255, 204, 0.05) 100%)',
          border: '1px solid rgba(0, 255, 204, 0.1)',
        }}
      >
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <svg className="w-5 h-5 text-matrix-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
            </svg>
            <h2 className="text-lg font-display font-bold text-white tracking-wide">
              COMPARISON
            </h2>
          </div>
          <div className="flex items-center gap-1 px-3 py-1 bg-void-800 rounded">
            <span className="text-matrix-500 font-mono text-sm font-bold">{numPanels}</span>
            <span className="text-gray-500 font-mono text-xs">RULES</span>
          </div>
        </div>
      </div>

      {/* Comparison Grid */}
      <div
        className="grid gap-4"
        style={{
          ...getGridStyle(),
          height: 'calc(100vh - 260px)',
          minHeight: '500px'
        }}
      >
        {data.detections.map((detection) => (
          <RulePanel
            key={detection.id}
            detection={detection}
          />
        ))}
      </div>
    </div>
  );
}
