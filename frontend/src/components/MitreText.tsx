/**
 * Renderer for MITRE ATT&CK description text (actors, software,
 * techniques). STIX descriptions carry a narrow markup subset that we
 * handle explicitly instead of piping through a full markdown engine:
 *
 *   - [text](url) links — attack.mitre.org entity links route to our
 *     internal page when the caller supplies a `resolveRoute` that
 *     knows the object exists in the catalog; every other link is an
 *     external anchor to its real URL
 *   - (Citation: Foo) markers — numbered superscript markers, matched
 *     against the STIX object's external_references by source_name.
 *     Matched markers link to the source; unmatched ones render as a
 *     plain marker with no link. `resolveCitations` gives pages the
 *     same numbering for their References list.
 *   - <code>...</code> spans — rendered as styled inline code
 *
 * react-markdown is the wrong tool here: it escapes the raw <code>
 * HTML MITRE uses.
 */

import { Fragment } from 'react';
import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';

const CITATION_RE = /\s*\(Citation:\s*([^)]*?)\s*\)/g;
const LINK_RE = /\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g;
const CODE_RE = /<code>(.*?)<\/code>/g;
const TOKEN_RE = new RegExp(
  `${LINK_RE.source}|${CODE_RE.source}|${CITATION_RE.source}`,
  'g'
);

export interface MitreRef {
  source_name: string;
  url: string;
  description?: string;
}

export interface CitationEntry {
  /** 1-based marker number, ordered by first appearance in the text. */
  num: number;
  source_name: string;
  /** Matched external reference, or null when MITRE cites a source it
   *  doesn't list (renders as a plain marker with no link). */
  ref: MitreRef | null;
}

/** Case/whitespace-insensitive key for matching citation tokens to refs. */
function citeKey(name: string): string {
  return name.trim().replace(/\s+/g, ' ').toLowerCase();
}

/**
 * Number every distinct (Citation: X) in `text` by first appearance and
 * match each against `references` by source_name. Pages use this to
 * render a numbered References list that agrees with the markers
 * MitreText renders inline.
 */
// eslint-disable-next-line react-refresh/only-export-components -- pure helper co-located with the renderer it must agree with; HMR-only concern
export function resolveCitations(
  text: string,
  references: MitreRef[] = []
): CitationEntry[] {
  const byKey = new Map<string, MitreRef>();
  for (const r of references) {
    if (r.source_name) byKey.set(citeKey(r.source_name), r);
  }
  const seen = new Map<string, CitationEntry>();
  for (const m of (text || '').matchAll(CITATION_RE)) {
    const name = m[1].trim();
    if (!name) continue;
    const key = citeKey(name);
    if (seen.has(key)) continue;
    seen.set(key, {
      num: seen.size + 1,
      source_name: name,
      ref: byKey.get(key) ?? null,
    });
  }
  return [...seen.values()];
}

/**
 * Plain-text form of MITRE description markup, for title tooltips and
 * other contexts that can't render elements: links collapse to their
 * label, citations are dropped, code tags are unwrapped.
 */
// eslint-disable-next-line react-refresh/only-export-components -- same as resolveCitations
export function stripMitreMarkup(text: string): string {
  return text
    .replace(CITATION_RE, '')
    .replace(LINK_RE, '$1')
    .replace(CODE_RE, '$1')
    .replace(/[ \t]{2,}/g, ' ')
    .trim();
}

function renderInline(
  text: string,
  citations: Map<string, CitationEntry>,
  resolveRoute?: (url: string) => string | null
): ReactNode[] {
  const out: ReactNode[] = [];
  let last = 0;
  let key = 0;
  for (const m of text.matchAll(TOKEN_RE)) {
    const idx = m.index ?? 0;
    if (idx > last) out.push(text.slice(last, idx));
    const [, label, url, code, citation] = m;
    if (code !== undefined) {
      out.push(
        <code
          key={key++}
          className="font-mono text-[0.85em] text-cyan-300 bg-void-900 border border-void-700 px-1"
        >
          {code}
        </code>
      );
    } else if (citation !== undefined) {
      const entry = citations.get(citeKey(citation));
      if (entry) {
        out.push(
          <sup key={key++} className="text-[0.7em] font-mono">
            {entry.ref?.url ? (
              <a
                href={entry.ref.url}
                target="_blank"
                rel="noopener noreferrer"
                title={entry.source_name}
                className="text-matrix-500 hover:text-matrix-400 transition-colors"
              >
                [{entry.num}]
              </a>
            ) : (
              <span title={entry.source_name} className="text-gray-500">
                [{entry.num}]
              </span>
            )}
          </sup>
        );
      }
      // Unresolvable (empty name) citations drop silently.
    } else if (url !== undefined) {
      const internal = resolveRoute?.(url) ?? null;
      if (internal) {
        out.push(
          <Link
            key={key++}
            to={internal}
            className="text-matrix-500 hover:text-matrix-400 underline decoration-matrix-500/40 underline-offset-2 transition-colors"
          >
            {label}
          </Link>
        );
      } else {
        out.push(
          <a
            key={key++}
            href={url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-matrix-500 hover:text-matrix-400 underline decoration-matrix-500/40 underline-offset-2 transition-colors"
          >
            {label}
          </a>
        );
      }
    }
    last = idx + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

/**
 * MITRE description body: paragraphs split on blank lines, single
 * newlines preserved (MITRE uses them for bullet-style lists), inline
 * links / code / citation markers rendered.
 *
 * (Citation: X) tokens always render as numbered superscript markers.
 * Pass `references` (the STIX object's external_references) to link
 * matched markers to their source; unmatched ones stay plain.
 */
export function MitreText({
  text,
  className,
  references,
  resolveRoute,
}: {
  text: string;
  className?: string;
  references?: MitreRef[];
  resolveRoute?: (url: string) => string | null;
}) {
  if (!text) return null;
  const entries = resolveCitations(text, references ?? []);
  const citations = new Map(entries.map((e) => [citeKey(e.source_name), e]));
  const paragraphs = text
    .split(/\n{2,}/)
    .map((p) => p.trim())
    .filter(Boolean);
  return (
    <div className={className ?? 'space-y-2'}>
      {paragraphs.map((p, i) => (
        <p key={i} className="text-sm text-gray-300 leading-relaxed whitespace-pre-line">
          {p.split('\n').map((line, j) => (
            <Fragment key={j}>
              {j > 0 && '\n'}
              {renderInline(line, citations, resolveRoute)}
            </Fragment>
          ))}
        </p>
      ))}
    </div>
  );
}

/**
 * Numbered references list matching MitreText's citation markers, with
 * any uncited references appended unnumbered. Render directly under
 * the description it annotates.
 */
export function MitreReferences({
  citations,
  references,
}: {
  citations: CitationEntry[];
  references?: MitreRef[];
}) {
  const citedUrls = new Set(
    citations.filter((c) => c.ref?.url).map((c) => c.ref!.url)
  );
  const citedNames = new Set(citations.map((c) => citeKey(c.source_name)));
  const uncited = (references ?? []).filter(
    (r) => !citedUrls.has(r.url) && !citedNames.has(citeKey(r.source_name))
  );
  if (citations.length === 0 && uncited.length === 0) return null;
  return (
    <ol className="space-y-1.5">
      {citations.map((c) => (
        <li key={`c-${c.num}`} className="text-xs flex gap-2">
          <span className="text-gray-600 font-mono tabular-nums shrink-0">[{c.num}]</span>
          {c.ref?.url ? (
            <span className="min-w-0">
              <a
                href={c.ref.url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-matrix-500 hover:text-matrix-400 break-all"
              >
                {c.source_name}
              </a>
              {c.ref.description && (
                <span className="text-gray-500 ml-2">— {c.ref.description}</span>
              )}
            </span>
          ) : (
            <span className="text-gray-500">{c.source_name}</span>
          )}
        </li>
      ))}
      {uncited.map((r, i) => (
        <li key={`u-${i}`} className="text-xs flex gap-2">
          <span className="text-gray-700 font-mono shrink-0">[·]</span>
          <span className="min-w-0">
            <a
              href={r.url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-matrix-500 hover:text-matrix-400 break-all"
            >
              {r.source_name || r.url}
            </a>
            {r.description && (
              <span className="text-gray-500 ml-2">— {r.description}</span>
            )}
          </span>
        </li>
      ))}
    </ol>
  );
}
