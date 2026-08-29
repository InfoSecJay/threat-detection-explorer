/**
 * Upstream Releases — hero feed of GitHub releases from sigma /
 * splunk / elastic. Each card expands to show the full markdown
 * release notes inline.
 */

import { parseApiDate } from '../../utils/dates';
import { useState, useMemo } from 'react';
import ReactMarkdown from 'react-markdown';
import { useReleases } from '../../hooks/useReleases';
import { sourceTheme as sourceConfig, clipSm } from '../../constants/style';
import { SkeletonRow } from './Section';
import { formatRelDate, type ReleaseWithSource } from './lib';

export function UpstreamReleases() {
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const { data: sigmaReleases, isLoading: sigmaLoading } = useReleases('sigma', 3);
  const { data: elasticReleases, isLoading: elasticLoading } = useReleases('elastic', 3);
  const { data: splunkReleases, isLoading: splunkLoading } = useReleases('splunk', 3);
  const isLoading = sigmaLoading || elasticLoading || splunkLoading;

  const releases = useMemo<ReleaseWithSource[]>(() => {
    const all: ReleaseWithSource[] = [];
    if (sigmaReleases) all.push(...sigmaReleases.map((r) => ({ ...r, source: 'sigma' })));
    if (elasticReleases) all.push(...elasticReleases.map((r) => ({ ...r, source: 'elastic' })));
    if (splunkReleases) all.push(...splunkReleases.map((r) => ({ ...r, source: 'splunk' })));
    return all
      .sort((a, b) => parseApiDate(b.published_at).getTime() - parseApiDate(a.published_at).getTime())
      .slice(0, 6);
  }, [sigmaReleases, elasticReleases, splunkReleases]);

  if (isLoading) {
    return (
      <div className="space-y-2">
        {[...Array(3)].map((_, i) => <SkeletonRow key={i} height="h-16" />)}
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {releases.map((release) => {
        const cfg = sourceConfig[release.source] || sourceConfig.sigma;
        const expanded = expandedId === release.id;
        return (
          <div
            key={`${release.source}-${release.id}`}
            className={`bg-void-850 border transition-colors ${
              expanded ? cfg.border : 'border-void-700 hover:border-void-600'
            }`}
            style={clipSm}
          >
            <button
              onClick={() => setExpandedId(expanded ? null : release.id)}
              className="w-full px-3 py-2.5 text-left flex items-center gap-2.5"
            >
              <span className={`px-1.5 py-0.5 text-[10px] font-mono uppercase tracking-wider shrink-0 ${cfg.bg} ${cfg.text} border ${cfg.border}`}>
                {cfg.name}
              </span>
              <span className="font-mono text-xs text-matrix-500 shrink-0">{release.tag_name}</span>
              <span className="text-sm text-gray-200 flex-1 truncate min-w-0">
                {release.name || release.tag_name}
              </span>
              <span className="text-[10px] text-gray-500 font-mono shrink-0">
                {formatRelDate(release.published_at)}
              </span>
              <svg
                className={`w-3 h-3 text-gray-500 transition-transform shrink-0 ${expanded ? 'rotate-180' : ''}`}
                fill="none" stroke="currentColor" viewBox="0 0 24 24"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>
            {expanded && release.body && (
              <div className="px-3 pb-3 border-t border-void-700">
                {/* Cap the markdown body at ~400px with its own
                    scrollbar so a long release note (Elastic's are
                    routinely thousands of lines) doesn't dominate the
                    viewport and force the reader to scroll past it to
                    reach the next release. Author + GitHub link stay
                    OUTSIDE the scroll container so they remain reachable
                    without hunting to the end of the notes. */}
                <div className="mt-2.5 max-h-[400px] overflow-y-auto pr-2 prose prose-invert prose-sm max-w-none prose-headings:text-white prose-headings:font-display prose-headings:mt-2 prose-headings:mb-1 prose-h2:text-xs prose-h3:text-xs prose-p:text-gray-300 prose-p:my-1 prose-a:text-matrix-500 prose-a:no-underline hover:prose-a:underline prose-strong:text-white prose-code:text-matrix-400 prose-code:bg-void-800 prose-code:px-1 prose-code:rounded prose-code:text-xs prose-ul:my-1 prose-ul:pl-4 prose-ol:my-1 prose-ol:pl-4 prose-li:text-gray-300 prose-li:my-0 prose-li:marker:text-matrix-500">
                  <ReactMarkdown>{release.body}</ReactMarkdown>
                </div>
                <div className="mt-2 pt-2 border-t border-void-700 flex items-center justify-between">
                  <span className="text-[10px] font-mono text-gray-500">
                    {release.author && `by ${release.author}`}
                  </span>
                  <a
                    href={release.html_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[10px] font-mono text-matrix-500 hover:text-matrix-400"
                  >
                    VIEW_ON_GITHUB ↗
                  </a>
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
