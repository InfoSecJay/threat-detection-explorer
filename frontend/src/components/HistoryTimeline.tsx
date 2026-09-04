/**
 * Rule history timeline (#127): the rule's lifecycle from real upstream
 * commits, newest first. Each touch is the author and date of a commit
 * that changed the rule file, linked to the commit for provenance.
 * "Created" comes from the rule's own created date (embedded or git)
 * when it predates the captured touches -- history is capped upstream
 * at the last ten, so the timeline says when it is truncated.
 */

import type { UpstreamTouch } from '../types';

function commitUrl(repoUrl: string | null | undefined, sha: string): string | null {
  if (!repoUrl) return null;
  const m = repoUrl.match(/^https?:\/\/github\.com\/([^/]+)\/([^/#?]+?)(?:\.git)?\/?$/i);
  return m ? `https://github.com/${m[1]}/${m[2]}/commit/${sha}` : null;
}

function relDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const days = Math.round((Date.now() - d.getTime()) / 86_400_000);
  if (days < 1) return 'today';
  if (days < 30) return `${days}d ago`;
  if (days < 365) return `${Math.round(days / 30)}mo ago`;
  return `${Math.round(days / 365)}y ago`;
}

function absDate(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().slice(0, 10);
}

export interface HistoryTimelineProps {
  touches: UpstreamTouch[] | undefined | null;
  createdDate: string | null | undefined;
  repoUrl: string | null | undefined;
  /** Shown as a final entry for rules removed upstream (tombstones). */
  removedAt?: string | null;
}

export function HistoryTimeline({ touches, createdDate, repoUrl, removedAt }: HistoryTimelineProps) {
  const list = (touches || []).filter((t) => t && t.sha && t.date);
  if (list.length === 0 && !createdDate) {
    return (
      <div className="py-6 text-center" data-testid="history-empty">
        <p className="text-sm text-gray-300">No upstream history captured for this rule yet.</p>
        <p className="text-xs text-gray-500 mt-1">History is read from the upstream repository at each nightly sync.</p>
      </div>
    );
  }

  const oldestTouch = list.length ? list[list.length - 1] : null;
  const createdBeforeHistory =
    !!createdDate && (!oldestTouch || new Date(createdDate).getTime() < new Date(oldestTouch.date).getTime() - 60_000);
  const truncated = list.length >= 10 && createdBeforeHistory;

  type Entry = { key: string; label: string; date: string; who?: string; subject?: string; href?: string | null; tone: string };
  const entries: Entry[] = [];
  if (removedAt) {
    entries.push({ key: 'removed', label: 'Removed upstream', date: removedAt, tone: 'bg-breach-500' });
  }
  list.forEach((t, i) => {
    const isLatest = i === 0 && !removedAt;
    const isFirst = i === list.length - 1 && !createdBeforeHistory;
    entries.push({
      key: t.sha,
      label: isLatest ? 'Last updated' : isFirst ? 'Created' : 'Changed',
      date: t.date,
      who: t.author,
      subject: t.subject,
      href: commitUrl(repoUrl, t.sha),
      tone: isLatest ? 'bg-matrix-500' : isFirst ? 'bg-cyan-500' : 'bg-gray-500',
    });
  });
  if (createdBeforeHistory && createdDate) {
    entries.push({ key: 'created', label: truncated ? 'Created (earlier changes not shown)' : 'Created', date: createdDate, tone: 'bg-cyan-500' });
  }

  return (
    <ol className="py-3 space-y-0" data-testid="history-timeline" aria-label="Rule history, newest first">
      {entries.map((e, i) => (
        <li key={e.key} className="relative pl-6 pb-4 last:pb-1">
          {i < entries.length - 1 && <span className="absolute left-[7px] top-4 bottom-0 w-px bg-void-700" aria-hidden="true" />}
          <span className={`absolute left-1 top-1.5 w-2 h-2 rounded-full ${e.tone}`} aria-hidden="true" />
          <div className="flex flex-wrap items-baseline gap-x-2">
            <span className="text-xs font-semibold text-gray-200">{e.label}</span>
            <span className="text-[11px] font-mono text-gray-500" title={e.date}>{absDate(e.date)} · {relDate(e.date)}</span>
          </div>
          {(e.who || e.subject) && (
            <div className="text-xs text-gray-400 mt-0.5 truncate">
              {e.who && <span className="text-gray-300">{e.who}</span>}
              {e.who && e.subject && <span className="text-gray-600"> · </span>}
              {e.subject && (
                e.href
                  ? <a href={e.href} target="_blank" rel="noopener noreferrer" className="hover:text-cyan-300 underline decoration-dotted" title="Open the upstream commit">{e.subject}</a>
                  : <span>{e.subject}</span>
              )}
            </div>
          )}
        </li>
      ))}
      {truncated && (
        <li className="pl-6 text-[10px] font-mono text-gray-600">Showing the last {list.length} upstream changes.</li>
      )}
    </ol>
  );
}
