import { useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { RuleDetail } from '../components/RuleDetail';
import { HistoryTimeline } from '../components/HistoryTimeline';
import type { UpstreamTouch } from '../types';
import { useDetection } from '../hooks/useDetections';
import { useDocumentMeta } from '../hooks/useDocumentMeta';
import { upstreamRef } from '../utils/upstreamRef';
import { clipMd } from '../constants/style';

/** Tell JS-executing crawlers this URL is not a page (bots that fetch
 * without JS already get a real 404 from the prerender endpoint). */
function useNoindex() {
  useEffect(() => {
    if (typeof document === 'undefined') return;
    const meta = document.createElement('meta');
    meta.name = 'robots';
    meta.content = 'noindex';
    document.head.appendChild(meta);
    return () => { meta.remove(); };
  }, []);
}

/** DX-19 / #161: an id that is not in the catalog and has no tombstone
 * used to render the raw client error ("Request failed with status
 * code 404"). Vendor ids and legacy ids resolve on their own (#86), so
 * a 404 here means the link is mistyped or predates tombstoning. */
function RuleNotFound({ id }: { id: string }) {
  useDocumentMeta('Rule not found', 'No rule with this id is in the catalog.');
  useNoindex();
  return (
    <div className="max-w-3xl space-y-4" data-testid="rule-not-found">
      <Link to="/detections" className="text-cyan-400 hover:text-cyan-300 hover:underline flex items-center gap-1">
        <span>&larr;</span> Back to list
      </Link>
      <div className="bg-void-850 border border-void-700 p-6" style={clipMd}>
        <div className="text-[10px] font-mono text-breach-400 uppercase tracking-[0.25em] mb-2">404 · no such rule</div>
        <h1 className="text-2xl font-display font-bold text-white tracking-wide">No rule with this id</h1>
        <p className="text-sm text-gray-400 mt-3">
          <span className="font-mono text-gray-200 break-all">{id}</span> is not in the catalog and is not a rule this
          site has tracked. Vendor rule ids and older ids redirect to the current page on their own, so this link is
          most likely mistyped, or from a rule that was removed before tombstones were kept.
        </p>
        <ul className="mt-5 flex flex-wrap gap-x-6 gap-y-2 text-xs font-mono uppercase tracking-wider">
          <li><Link to="/detections" className="text-matrix-500 hover:text-matrix-400">Search the catalog</Link></li>
          <li><Link to="/digest" className="text-matrix-500 hover:text-matrix-400">Removed this week</Link></li>
          <li><Link to="/methodology" className="text-gray-400 hover:text-white">How rules are indexed</Link></li>
        </ul>
      </div>
    </div>
  );
}

interface Tombstone {
  removed: true;
  id: string;
  rule_id: string | null;
  source: string;
  source_file: string;
  title: string;
  severity: string | null;
  mitre_techniques: string[];
  first_seen_at: string | null;
  removed_at: string | null;
  last_seen: Record<string, unknown>;
  successors: { id: string; title: string; source: string; severity: string | null }[];
}

function TombstonePage({ t }: { t: Tombstone }) {
  useDocumentMeta(`${t.title} (removed)`, `This ${t.source} rule was removed upstream.`);
  const day = (iso: string | null) => (iso ? iso.slice(0, 10) : '?');
  const lastLogic = typeof t.last_seen.detection_logic === 'string' ? t.last_seen.detection_logic : '';
  // Rule history (#127) survives on the preserved row: the last upstream
  // touches plus the removal itself as the newest entry.
  const touches = Array.isArray(t.last_seen.upstream_history) ? (t.last_seen.upstream_history as UpstreamTouch[]) : [];
  const createdDate = typeof t.last_seen.rule_created_date === 'string' ? t.last_seen.rule_created_date : t.first_seen_at;
  const repoUrl = typeof t.last_seen.source_repo_url === 'string' ? t.last_seen.source_repo_url : null;
  // DX-15 pays off here: a link pinned to the commit we last indexed
  // still resolves on GitHub after the file is deleted, so the tombstone
  // can point at the exact last version. A branch link would 404.
  const lastUrl = typeof t.last_seen.source_rule_url === 'string' ? t.last_seen.source_rule_url : null;
  const lastRef = upstreamRef(lastUrl);
  return (
    <div className="max-w-4xl space-y-5" data-testid="tombstone">
      <Link to="/detections" className="text-cyan-400 hover:text-cyan-300 hover:underline flex items-center gap-1">
        <span>&larr;</span> Back to list
      </Link>
      <div className="bg-void-850 border border-amber-500/40 p-6">
        <div className="text-[10px] font-mono text-amber-300 uppercase tracking-[0.25em] mb-2">removed upstream</div>
        <h1 className="text-2xl font-display font-bold text-white tracking-wide">{t.title}</h1>
        <p className="text-sm text-gray-400 mt-3">
          Tracked from <span className="text-gray-200 font-mono">{day(t.first_seen_at)}</span> until{' '}
          <span className="text-gray-200 font-mono">{day(t.removed_at)}</span>, when it was removed from the{' '}
          <span className="text-gray-200">{t.source}</span> repository ({t.source_file}). This URL preserves the
          last version we saw -- a record only this site keeps.
        </p>
        {lastUrl && lastRef?.pinned && (
          <a
            href={lastUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-block mt-3 text-xs font-mono text-matrix-500 hover:text-matrix-400"
            title="The file at the commit this site last indexed; the commit outlives the deletion on GitHub"
            data-testid="tombstone-upstream"
          >
            last indexed version upstream (commit {lastRef.ref.slice(0, 7)}) &#8599;
          </a>
        )}
        {t.mitre_techniques.length > 0 && (
          <p className="text-xs font-mono text-gray-500 mt-2">
            ATT&amp;CK:{' '}
            {t.mitre_techniques.map((tid) => (
              <Link key={tid} to={`/mitre/${tid}`} className="text-matrix-500 hover:text-matrix-400 mr-2">{tid}</Link>
            ))}
          </p>
        )}
      </div>
      <div className="bg-void-850 border border-void-700 p-5" data-testid="tombstone-history">
        <h2 className="text-sm font-display font-bold text-white uppercase tracking-wider mb-1">History</h2>
        <HistoryTimeline touches={touches} createdDate={createdDate} repoUrl={repoUrl} removedAt={t.removed_at} />
      </div>
      {t.successors.length > 0 && (
        <div className="bg-void-850 border border-void-700 p-5">
          <h2 className="text-sm font-display font-bold text-white uppercase tracking-wider mb-2">Current rules covering the same technique</h2>
          <ul className="space-y-1">
            {t.successors.map((s) => (
              <li key={s.id} className="text-sm">
                <Link to={`/detections/${s.id}`} className="text-gray-200 hover:text-matrix-400">{s.title}</Link>
                <span className="text-[10px] font-mono text-gray-500 ml-2 uppercase">{s.source}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {lastLogic && (
        <div className="bg-void-850 border border-void-700 p-5">
          <h2 className="text-sm font-display font-bold text-white uppercase tracking-wider mb-2">Last version we saw</h2>
          <pre className="text-xs font-mono text-gray-300 bg-void-900 border border-void-800 p-3 overflow-x-auto whitespace-pre-wrap max-h-96 overflow-y-auto">{lastLogic}</pre>
        </div>
      )}
    </div>
  );
}

export function DetectionDetail() {
  const { id } = useParams<{ id: string }>();
  const { data: detection, isLoading, error } = useDetection(id || '');

  // Alias routes (legacy id, vendor rule_id) resolve to the same rule but
  // leave the alias in the address bar, so visitors copy non-canonical
  // links onward (teardown R23). Swap in the canonical id silently;
  // replaceState keeps back/forward history intact and doesn't remount.
  useEffect(() => {
    if (detection && id && detection.id !== id) {
      window.history.replaceState(window.history.state, '', `/detections/${detection.id}`);
    }
  }, [detection, id]);

  if (isLoading) {
    return (
      <div className="text-center py-8">
        <div className="animate-spin h-8 w-8 border-4 border-cyan-500 border-t-transparent rounded-full mx-auto"></div>
        <p className="mt-2 text-gray-400">Loading detection...</p>
      </div>
    );
  }

  if (error) {
    // Tombstone (#87 / teardown F11): a rule removed upstream answers
    // 410 with its history -- render the record, never a dead end.
    const resp = (error as { response?: { status?: number; data?: Tombstone } }).response;
    if (resp?.status === 410 && resp.data?.removed) {
      return <TombstonePage t={resp.data} />;
    }
    if (resp?.status === 404) {
      return <RuleNotFound id={id || ''} />;
    }
    // Anything else is the network or the API, not the reader's link.
    return (
      <div className="bg-red-500/20 text-red-400 border border-red-500/30 p-4 rounded-lg" role="alert" data-testid="rule-load-error">
        This rule could not be loaded{resp?.status ? ` (HTTP ${resp.status})` : ''}. Reload the page, or{' '}
        <Link to="/detections" className="underline hover:text-red-300">go back to the catalog</Link>.
      </div>
    );
  }

  if (!detection) {
    return (
      <div className="text-center py-8">
        <p className="text-gray-400">Detection not found</p>
        <Link to="/detections" className="text-cyan-400 hover:text-cyan-300 hover:underline mt-2 inline-block">
          Back to list
        </Link>
      </div>
    );
  }

  return (
    <div>
      <div className="mb-4">
        <Link
          to="/detections"
          className="text-cyan-400 hover:text-cyan-300 hover:underline flex items-center gap-1"
        >
          <span>&larr;</span> Back to list
        </Link>
      </div>

      <RuleDetail detection={detection} />

      {/* Related detections suggestion */}
      {detection.mitre_techniques.length > 0 && (
        <div className="mt-6 bg-void-850 rounded-lg border border-void-700 p-4">
          <h3 className="font-semibold text-white mb-2">Find Related Detections</h3>
          <div className="flex flex-wrap gap-2">
            {detection.mitre_techniques.slice(0, 5).map((tech) => (
              <Link
                key={tech}
                to={`/mitre/${tech}`}
                className="px-3 py-1 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-full text-sm hover:bg-cyan-500/30 transition-colors"
              >
                Browse {tech} on MITRE
              </Link>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
