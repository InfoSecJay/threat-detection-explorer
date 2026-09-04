/**
 * The compare matrix as Markdown, for Slack / a PR description / a
 * tuning ticket. Same rows the page shows: observables first, then the
 * metadata axes. Cells: `x` present, `NOT` exclusion, `-` absent; the
 * field name follows the mark so the vendor mapping travels with it.
 */

import type { CompareDiffAxis, CompareDiffResponse } from '../services/api';

export const AXIS_LABEL: Record<CompareDiffAxis, string> = {
  mitre_techniques: 'ATT&CK techniques',
  mitre_tactics: 'ATT&CK tactics',
  data_sources: 'Data sources',
  platforms: 'Platforms',
  domains: 'Domains',
  products: 'Products',
  event_types: 'Event types',
  source_tables: 'Source tables',
  fields: 'Fields tested',
};

const AXIS_ORDER: CompareDiffAxis[] = [
  'mitre_techniques', 'mitre_tactics', 'data_sources', 'platforms', 'domains', 'products', 'event_types', 'source_tables', 'fields',
];

function cell(s: string): string {
  return s.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

export function diffToMarkdown(d: CompareDiffResponse, origin: string, sourceName: (s: string) => string = (s) => s): string {
  const L: string[] = [];
  const ids = d.rules.map((r) => r.id);
  const shortName = (i: number) => `R${i + 1}`;
  L.push(`# Rule comparison: ${d.rules.length} rules`);
  L.push('');
  d.rules.forEach((r, i) => {
    L.push(`- **${shortName(i)}** [${cell(r.title)}](${origin}/detections/${r.id}) — ${sourceName(r.source)} · ${r.severity} · ${r.language}${r.quality_score !== null ? ` · completeness ${r.quality_score}` : ''}`);
  });
  L.push('');
  L.push(`${d.summary.observables} observables, ${d.summary.shared_by_all} shared by all` +
    (ids.length ? `; unique: ${ids.map((id, i) => `${shortName(i)} ${d.summary.unique_by_rule[id] ?? 0}`).join(', ')}` : ''));
  if (d.summary.contradictions.length) {
    L.push('');
    L.push('**Contradictions** (matched by one rule, excluded by another):');
    for (const c of d.summary.contradictions) {
      const named = (xs: string[]) => xs.map((x) => shortName(ids.indexOf(x))).join(', ');
      L.push(`- \`${cell(c.value)}\` (${c.type}/${c.subtype}): matched in ${named(c.matched_in)}, excluded in ${named(c.excluded_in)}`);
    }
  }
  const header = `| Observable | ${ids.map((_, i) => shortName(i)).join(' | ')} |`;
  const sep = `|---|${ids.map(() => '---').join('|')}|`;
  if (d.observables.length) {
    L.push('');
    L.push('## Observables');
    L.push('');
    L.push(header);
    L.push(sep);
    for (const o of d.observables) {
      const cells = ids.map((id) => {
        if (!o.present_in.includes(id)) return '-';
        const mark = o.negated_in.includes(id) ? 'NOT' : 'x';
        const fields = o.fields[id]?.length ? ` \`${cell(o.fields[id].join(', '))}\`` : '';
        return `${mark}${fields}`;
      });
      L.push(`| ${o.type}/${o.subtype} \`${cell(o.value)}\` | ${cells.join(' | ')} |`);
    }
  }
  for (const axis of AXIS_ORDER) {
    const rows = d.axes[axis] ?? [];
    if (!rows.length) continue;
    L.push('');
    L.push(`## ${AXIS_LABEL[axis]}`);
    L.push('');
    L.push(`| Value | ${ids.map((_, i) => shortName(i)).join(' | ')} |`);
    L.push(sep);
    for (const row of rows) {
      const value = axis === 'mitre_techniques' ? `[${row.value}](${origin}/mitre/${row.value})` : `\`${cell(row.value)}\``;
      L.push(`| ${value} | ${ids.map((id) => (row.present_in.includes(id) ? 'x' : '-')).join(' | ')} |`);
    }
  }
  L.push('');
  L.push(`_[${origin.replace(/^https?:\/\//, '')}/compare?ids=${ids.join(',')}](${origin}/compare?ids=${ids.map(encodeURIComponent).join(',')})_`);
  return L.join('\n');
}
