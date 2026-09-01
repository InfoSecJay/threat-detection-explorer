/** Rule file download (#128): the original upstream file, byte-for-byte. */

import type { Detection } from '../types';

/** Upstream basename for the downloaded file, so a Sigma rule saves as
 * its .yml and a Panther rule as its .py. Falls back to the rule id
 * when source_file is pathological. */
export function ruleFileName(detection: Detection): string {
  const base = (detection.source_file || '').split(/[\\/]/).pop() || '';
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
