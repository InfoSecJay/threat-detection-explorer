/**
 * Renderer for MITRE ATT&CK description text (actors, software,
 * techniques). STIX descriptions carry a narrow markup subset that we
 * handle explicitly instead of piping through a full markdown engine:
 *
 *   - [text](url) links — routed internally when the URL is an
 *     attack.mitre.org group/software/technique we have a page for,
 *     external anchor otherwise
 *   - (Citation: Foo) markers — stripped; the sources they point at are
 *     already listed in each page's References section
 *   - <code>...</code> spans — rendered as styled inline code
 *
 * react-markdown is the wrong tool here: it escapes the raw <code>
 * HTML MITRE uses and can't rewrite MITRE URLs onto our routes.
 */

import { Fragment } from 'react';
import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';

const CITATION_RE = /\s*\(Citation:[^)]*\)/g;
const LINK_RE = /\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g;
const CODE_RE = /<code>(.*?)<\/code>/g;
const TOKEN_RE = new RegExp(`${LINK_RE.source}|${CODE_RE.source}`, 'g');

/**
 * Plain-text form of MITRE description markup, for title tooltips and
 * other contexts that can't render elements: links collapse to their
 * label, citations are dropped, code tags are unwrapped.
 */
export function stripMitreMarkup(text: string): string {
  return text
    .replace(CITATION_RE, '')
    .replace(LINK_RE, '$1')
    .replace(CODE_RE, '$1')
    .replace(/[ \t]{2,}/g, ' ')
    .trim();
}

/** Maps an attack.mitre.org URL onto our own route, if we have one. */
function internalPath(url: string): string | null {
  const m = url.match(
    /^https?:\/\/attack\.mitre\.org\/(?:wiki\/)?(groups|software|techniques)\/([A-Z]+\d+)(?:\/(\d+))?\/?$/i
  );
  if (!m) return null;
  const kind = m[1].toLowerCase();
  const id = m[2].toUpperCase();
  if (kind === 'groups' || kind === 'software') return `/actors/${id}`;
  if (kind === 'techniques') return `/mitre/${m[3] ? `${id}.${m[3]}` : id}`;
  return null;
}

function renderInline(text: string): ReactNode[] {
  const out: ReactNode[] = [];
  let last = 0;
  let key = 0;
  for (const m of text.matchAll(TOKEN_RE)) {
    const idx = m.index ?? 0;
    if (idx > last) out.push(text.slice(last, idx));
    const [, label, url, code] = m;
    if (code !== undefined) {
      out.push(
        <code
          key={key++}
          className="font-mono text-[0.85em] text-cyan-300 bg-void-900 border border-void-700 px-1"
        >
          {code}
        </code>
      );
    } else {
      const to = internalPath(url);
      const cls =
        'text-matrix-500 hover:text-matrix-400 underline decoration-matrix-500/40 underline-offset-2 transition-colors';
      out.push(
        to ? (
          <Link key={key++} to={to} className={cls}>
            {label}
          </Link>
        ) : (
          <a key={key++} href={url} target="_blank" rel="noopener noreferrer" className={cls}>
            {label}
          </a>
        )
      );
    }
    last = idx + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

/**
 * MITRE description body: paragraphs split on blank lines, single
 * newlines preserved (MITRE uses them for bullet-style lists), inline
 * links / code rendered.
 */
export function MitreText({ text, className }: { text: string; className?: string }) {
  if (!text) return null;
  const paragraphs = text
    .replace(CITATION_RE, '')
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
              {renderInline(line)}
            </Fragment>
          ))}
        </p>
      ))}
    </div>
  );
}
