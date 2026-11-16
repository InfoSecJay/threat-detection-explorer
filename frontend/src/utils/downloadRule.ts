/** Rule file download (#128): the original upstream file, byte-for-byte
 * (for GitLab TLDR, the rule's own Sigma document from that file). */

import type { Detection } from '../types';

/** Upstream basename for the downloaded file, so a Sigma rule saves as
 * its .yml and a Panther rule as its .py. Falls back to the rule id
 * when source_file is pathological. */
export function ruleFileName(detection: Detection): string {
  const base = (detection.source_file || '').split(/[\\/]/).pop() || '';
  // GitLab TLDR: several Sigma rules live in one Markdown file and the
  // source shown for each is its own YAML, so the download is a .yml
  // named after the file plus the start of the rule's Sigma id.
  if (detection.source === 'gitlab' && /^[\w.\- ]+\.md$/i.test(base)) {
    const stem = base.replace(/\.md$/i, '');
    const rid = (detection.rule_id || '').replace(/[^0-9a-f]/gi, '').slice(0, 8);
    return rid ? `${stem}.${rid}.yml` : `${stem}.yml`;
  }
  return /^[\w.\- ]+$/.test(base) && base.includes('.') ? base : `${detection.id}.txt`;
}

export function downloadRuleFile(detection: Detection): void {
  const blob = new Blob([detection.raw_content || ''], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = ruleFileName(detection);
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
