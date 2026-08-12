/**
 * Universal search bar — Lucene-syntax input with typeahead + inline
 * parse-error rendering. Replaces the sidebar-first filtering model
 * on the Detections page.
 *
 * Field aliases come from `/query/fields` (kept in sync with the
 * backend parser); value suggestions come from the existing
 * `/detections/filters` facets so users see real known values,
 * not a hardcoded list.
 *
 * Errors surfaced from the API (HTTP 400 with our custom parse-
 * error detail) render below the bar with a position underline
 * and — if the backend offered a Levenshtein match — a "did you
 * mean" chip that swaps the offending field on click.
 *
 * Bar syntax is optional. Bare text with no colon falls through to
 * a multi-field substring match on the backend, so casual users can
 * still just type "powershell" and get results.
 */

import { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { useQueryFields } from '../hooks/useQueryFields';
import { useFilterOptions } from '../hooks/useDetections';
import { useMitre } from '../contexts/MitreContext';
import { clipSm } from '../constants/style';
import type { QueryFieldSpec, QueryParseErrorDetail } from '../services/api';

const PLACEHOLDERS = [
  'source:sigma AND severity:high',
  'actor:APT29',
  'tech:T1059.001 platform:windows',
  'title:"cobalt strike"',
  'software:Mimikatz OR software:"Cobalt Strike"',
  'usecase:Ransomware source:splunk',
];

interface Suggestion {
  value: string;      // What gets inserted at the cursor position
  label: string;      // Display text
  hint?: string;      // Right-side hint (description or count)
  kind: 'field' | 'value';
}

/** Parse `field:` prefix and remainder from the current token under the cursor. */
function currentToken(text: string, caret: number): {
  before: string;             // text before the current token
  token: string;              // the current token being typed
  after: string;              // text after the current token
  field: string | null;       // field alias if the token has `field:` prefix
  value: string;              // portion after the colon (or whole token if no colon)
} {
  const upto = text.slice(0, caret);
  // A "token" ends at whitespace or a paren, and is bounded on the
  // right by more of the same or end of text. Balanced parens /
  // quoted strings would be nicer; this is deliberately simple.
  const tokenStart = Math.max(
    upto.lastIndexOf(' ') + 1,
    upto.lastIndexOf('(') + 1,
  );
  const rest = text.slice(caret);
  const nextBreak = rest.search(/[\s)]/);
  const tokenEnd = nextBreak === -1 ? text.length : caret + nextBreak;
  const token = text.slice(tokenStart, tokenEnd);
  const colonIdx = token.indexOf(':');
  return {
    before: text.slice(0, tokenStart),
    token,
    after: text.slice(tokenEnd),
    field: colonIdx === -1 ? null : token.slice(0, colonIdx),
    value: colonIdx === -1 ? token : token.slice(colonIdx + 1),
  };
}

/** Rank suggestion candidates by prefix > infix > alpha. */
function rank<T extends { label: string }>(items: T[], query: string): T[] {
  const q = query.toLowerCase();
  if (!q) return items.slice(0, 20);
  const scored = items.map((it) => {
    const l = it.label.toLowerCase();
    let score = 999;
    if (l.startsWith(q)) score = 0;
    else if (l.includes(q)) score = 1;
    return { it, score };
  }).filter((x) => x.score < 999);
  scored.sort((a, b) => a.score - b.score || a.it.label.localeCompare(b.it.label));
  return scored.slice(0, 20).map((x) => x.it);
}

interface SearchBarProps {
  value: string;
  onSubmit: (value: string) => void;
  error?: QueryParseErrorDetail | null;
  autoFocus?: boolean;
}

export function SearchBar({ value, onSubmit, error, autoFocus }: SearchBarProps) {
  const [draft, setDraft] = useState(value);
  const [caret, setCaret] = useState(0);
  const [focused, setFocused] = useState(false);
  const [activeIdx, setActiveIdx] = useState(0);
  const [placeholderIdx, setPlaceholderIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);

  // Rotate placeholder text every 4s while unfocused/empty so users
  // discover the syntax passively.
  useEffect(() => {
    if (focused || draft) return;
    const id = setInterval(
      () => setPlaceholderIdx((i) => (i + 1) % PLACEHOLDERS.length),
      4000,
    );
    return () => clearInterval(id);
  }, [focused, draft]);

  // Keep draft in sync when the URL-driven value changes externally
  // (e.g. removing a chip elsewhere).
  useEffect(() => {
    setDraft(value);
  }, [value]);

  const { data: fieldsResp } = useQueryFields();
  const { data: filterOpts } = useFilterOptions();
  const { techniques } = useMitre();

  const fields: QueryFieldSpec[] = fieldsResp?.fields || [];

  // Build the value-suggestion index once from filter facets + MITRE.
  const valueIndex = useMemo(() => {
    const idx: Record<string, Suggestion[]> = {};
    const add = (aliases: string[], list: { value: string; count?: number; label?: string }[]) => {
      const items = list.map((v) => ({
        value: v.value,
        label: v.label || v.value,
        hint: v.count !== undefined ? String(v.count) : undefined,
        kind: 'value' as const,
      }));
      for (const a of aliases) idx[a] = items;
    };
    if (filterOpts) {
      add(['source'], (filterOpts.sources || []).map((v) => ({ value: v })));
      add(['sev', 'severity'], (filterOpts.severities || []).map((v) => ({ value: v })));
      add(['status'], (filterOpts.statuses || []).map((v) => ({ value: v })));
      add(['lang', 'language'], (filterOpts.languages || []).map((v) => ({ value: v })));
      add(['platform'], filterOpts.platforms || []);
      add(['data', 'datasource'], filterOpts.data_sources || []);
      add(['event', 'eventtype'], filterOpts.event_types || []);
      add(['usecase', 'story', 'use_case'], filterOpts.use_cases || []);
      // For actor / software: the facet gives us IDs (G0016 etc). Users
      // can also type names — the backend resolves either way.
      add(['actor', 'group'], filterOpts.mitre_groups || []);
      add(['software', 'tool', 'malware'], filterOpts.mitre_software || []);
    }
    if (techniques && Object.keys(techniques).length) {
      const techItems = Object.values(techniques)
        .filter((t) => !t.deprecated)
        .map((t) => ({ value: t.id, label: `${t.id} · ${t.name}` }));
      for (const a of ['tech', 'technique']) idx[a] = techItems.map((t) => ({
        value: t.value, label: t.label, kind: 'value' as const,
      }));
    }
    return idx;
  }, [filterOpts, techniques]);

  // Compute the current suggestion list.
  const { suggestions, tokenInfo } = useMemo(() => {
    const info = currentToken(draft, caret);
    if (info.field === null) {
      // No colon yet — suggesting field names. Offer each field's
      // canonical (first) alias only; secondary aliases (`malware:`,
      // `sev:`, …) still parse and still surface once the user starts
      // typing one, but don't clutter the default list.
      const typed = info.value.toLowerCase();
      const fieldSug: Suggestion[] = fields.flatMap((f) =>
        f.aliases
          .filter((a, i) => i === 0 || (typed.length > 0 && a.startsWith(typed)))
          .map((a) => ({
            value: `${a}:`,
            label: `${a}:`,
            hint: f.description,
            kind: 'field' as const,
          })),
      );
      return { suggestions: rank(fieldSug, info.value), tokenInfo: info };
    }
    // Have `field:` — suggest values for it (if we know any).
    const values = valueIndex[info.field.toLowerCase()] || [];
    return { suggestions: rank(values, info.value), tokenInfo: info };
  }, [draft, caret, fields, valueIndex]);

  const showDropdown = focused && suggestions.length > 0;

  useEffect(() => {
    // Reset highlighted item whenever the visible list changes.
    setActiveIdx(0);
  }, [draft, caret]);

  const applySuggestion = (sug: Suggestion) => {
    let insertion = sug.value;
    // If we're completing a value and it contains a space, quote it.
    if (sug.kind === 'value' && /\s/.test(insertion) && !insertion.startsWith('"')) {
      insertion = `"${insertion}"`;
    }
    // Replace the current token's value slot (or the whole token for
    // field completions).
    let next: string;
    if (sug.kind === 'field') {
      next = `${tokenInfo.before}${insertion}${tokenInfo.after}`;
    } else {
      const fieldPrefix = tokenInfo.field ? `${tokenInfo.field}:` : '';
      next = `${tokenInfo.before}${fieldPrefix}${insertion}${tokenInfo.after}`;
    }
    setDraft(next);
    // Reposition caret after the insertion, then refocus.
    const newCaret = (tokenInfo.before + (sug.kind === 'field' ? insertion : `${tokenInfo.field}:${insertion}`)).length;
    requestAnimationFrame(() => {
      if (inputRef.current) {
        inputRef.current.focus();
        inputRef.current.setSelectionRange(newCaret, newCaret);
        setCaret(newCaret);
      }
    });
  };

  const submit = () => {
    onSubmit(draft.trim());
    inputRef.current?.blur();
    setFocused(false);
  };

  const onKeyDown: React.KeyboardEventHandler<HTMLInputElement> = (e) => {
    if (showDropdown) {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setActiveIdx((i) => Math.min(i + 1, suggestions.length - 1));
        return;
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        setActiveIdx((i) => Math.max(i - 1, 0));
        return;
      }
      if (e.key === 'Tab' || (e.key === 'Enter' && suggestions[activeIdx])) {
        // Enter with a highlighted suggestion accepts it, not submits.
        if (suggestions[activeIdx]) {
          e.preventDefault();
          applySuggestion(suggestions[activeIdx]);
          return;
        }
      }
    }
    if (e.key === 'Enter') {
      e.preventDefault();
      submit();
    }
    if (e.key === 'Escape') {
      setFocused(false);
      inputRef.current?.blur();
    }
  };

  return (
    <div className="relative">
      <div
        className={`flex items-center gap-2 bg-void-900 border ${focused ? 'border-matrix-500/60 shadow-[0_0_20px_rgba(0,255,65,0.08)]' : error ? 'border-breach-500/40' : 'border-void-700'} px-3 py-2 transition-colors`}
        style={clipSm}
      >
        <span className="text-matrix-500 font-mono text-sm select-none" aria-hidden="true">&gt;</span>
        <input
          ref={inputRef}
          type="text"
          value={draft}
          onChange={(e) => {
            setDraft(e.target.value);
            setCaret(e.target.selectionStart || 0);
          }}
          onKeyDown={onKeyDown}
          onKeyUp={(e) => setCaret(e.currentTarget.selectionStart || 0)}
          onClick={(e) => setCaret(e.currentTarget.selectionStart || 0)}
          onFocus={() => setFocused(true)}
          onBlur={() => {
            // Delay so click on suggestion still fires before blur closes the list.
            setTimeout(() => setFocused(false), 150);
          }}
          placeholder={PLACEHOLDERS[placeholderIdx]}
          autoFocus={autoFocus}
          spellCheck={false}
          autoComplete="off"
          className="flex-1 bg-transparent text-sm font-mono text-white placeholder:text-gray-600 focus:outline-none min-w-0"
          aria-label="Search rules"
          aria-autocomplete="list"
          aria-controls="searchbar-suggestions"
        />
        {draft && (
          <button
            onClick={() => {
              setDraft('');
              onSubmit('');
              inputRef.current?.focus();
            }}
            className="text-gray-500 hover:text-white text-xs font-mono shrink-0"
            aria-label="Clear query"
            title="Clear query (Esc)"
          >
            ✕
          </button>
        )}
        <Link
          to="/query"
          className="text-[10px] font-mono text-gray-500 hover:text-matrix-500 uppercase tracking-wider shrink-0 border border-void-700 hover:border-matrix-500/40 px-1.5 py-0.5"
          title="Query syntax reference"
        >
          ?
        </Link>
      </div>

      {/* Inline error */}
      {error && (
        <div className="mt-1.5 text-xs font-mono text-breach-400 flex items-center gap-2 flex-wrap">
          <span className="text-breach-500">⚠</span>
          <span>{error.message}</span>
          {error.suggestion && (
            <button
              onClick={() => {
                // Best-effort auto-fix: replace the first occurrence of the
                // typo'd field name with the suggestion.
                const suggested = draft.replace(
                  new RegExp(`\\b(\\w+):`, 'i'),
                  (m, name) => (fields.some((f) => f.aliases.includes(name.toLowerCase())) ? m : `${error.suggestion}:`),
                );
                setDraft(suggested);
                onSubmit(suggested);
              }}
              className="text-matrix-500 hover:text-matrix-400 border-b border-dotted border-matrix-500/50"
            >
              use &quot;{error.suggestion}&quot;
            </button>
          )}
        </div>
      )}

      {/* Typeahead dropdown */}
      {showDropdown && (
        <ul
          ref={listRef}
          id="searchbar-suggestions"
          role="listbox"
          className="absolute z-40 top-full left-0 right-0 mt-1 bg-void-900 border border-void-700 max-h-80 overflow-y-auto"
          style={clipSm}
        >
          {suggestions.map((sug, i) => {
            const active = i === activeIdx;
            return (
              <li
                key={`${sug.kind}-${sug.value}-${i}`}
                role="option"
                aria-selected={active}
                onMouseDown={(e) => {
                  // mousedown fires before blur so we don't lose the click.
                  e.preventDefault();
                  applySuggestion(sug);
                }}
                onMouseEnter={() => setActiveIdx(i)}
                className={`px-3 py-1.5 cursor-pointer flex items-center gap-3 text-xs font-mono ${active ? 'bg-matrix-500/10 text-white' : 'text-gray-300 hover:bg-void-800'}`}
              >
                <span className={`shrink-0 uppercase text-[9px] tracking-wider ${sug.kind === 'field' ? 'text-cyan-400' : 'text-matrix-500'}`}>
                  {sug.kind === 'field' ? 'FIELD' : 'VAL'}
                </span>
                <span className="truncate">{sug.label}</span>
                {sug.hint && (
                  <span className="ml-auto text-gray-500 text-[10px] truncate max-w-[50%]">
                    {sug.hint}
                  </span>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
