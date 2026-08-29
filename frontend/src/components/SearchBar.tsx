/**
 * Universal search bar — Lucene-syntax input with typeahead + inline
 * parse-error rendering. Replaces the sidebar-first filtering model
 * on the Detections page.
 *
 * Field aliases come from `/query/fields` (kept in sync with the
 * backend parser); value suggestions come from the existing
 * `/detections/filters` facets so users see real known values,
 * not a hardcoded list. The pure typeahead logic lives in
 * searchbar/suggestions.ts; the panels in searchbar/.
 *
 * Errors surfaced from the API (HTTP 400 with our custom parse-
 * error detail) render below the bar and — if the backend offered a
 * Levenshtein match — a "did you mean" chip that swaps the offending
 * field on click.
 *
 * Bar syntax is optional. Bare text with no colon falls through to
 * a multi-field substring match on the backend, so casual users can
 * still just type "powershell" and get results.
 */

import { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { useQueryFields } from '../hooks/useQueryFields';
import { useFilterOptions } from '../hooks/useDetections';
import { useSavedQueries } from '../hooks/useSavedQueries';
import { useMitre } from '../contexts/MitreContext';
import { clipSm } from '../constants/style';
import type { QueryFieldSpec, QueryParseErrorDetail } from '../services/api';
import {
  PLACEHOLDERS, buildValueIndex, suggestFor, applyTo, fixUnknownField, type Suggestion,
} from './searchbar/suggestions';
import { SavedQueriesPanel } from './searchbar/SavedQueriesPanel';
import { SuggestionList } from './searchbar/SuggestionList';

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
  // -1 = nothing highlighted: Enter submits the query. Arrow keys
  // highlight a suggestion, and only then does Enter accept it.
  const [activeIdx, setActiveIdx] = useState(-1);
  const [placeholderIdx, setPlaceholderIdx] = useState(0);
  // Saved/recent queries panel (#14) — toggled by the bookmark button.
  const [queriesOpen, setQueriesOpen] = useState(false);
  const { recent, saved, recordRecent, star, unstar, rename, clearRecent } =
    useSavedQueries();
  const inputRef = useRef<HTMLInputElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);

  // Close the queries panel on outside click.
  useEffect(() => {
    if (!queriesOpen) return;
    const onDown = (e: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
        setQueriesOpen(false);
      }
    };
    document.addEventListener('mousedown', onDown);
    return () => document.removeEventListener('mousedown', onDown);
  }, [queriesOpen]);

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

  // Memoized so the suggestion index below is not rebuilt every render
  // while the fields query is still loading (fresh [] each time).
  const fields: QueryFieldSpec[] = useMemo(() => fieldsResp?.fields ?? [], [fieldsResp]);
  const valueIndex = useMemo(() => buildValueIndex(filterOpts, techniques), [filterOpts, techniques]);
  const { suggestions, tokenInfo } = useMemo(
    () => suggestFor(draft, caret, fields, valueIndex),
    [draft, caret, fields, valueIndex],
  );

  const showDropdown = focused && suggestions.length > 0;

  useEffect(() => {
    // Reset to "nothing highlighted" whenever the visible list
    // changes, so Enter submits by default.
    setActiveIdx(-1);
  }, [draft, caret]);

  const applySuggestion = (sug: Suggestion) => {
    const { next, caret: newCaret } = applyTo(tokenInfo, sug);
    setDraft(next);
    // Reposition caret after the insertion, then refocus.
    requestAnimationFrame(() => {
      if (inputRef.current) {
        inputRef.current.focus();
        inputRef.current.setSelectionRange(newCaret, newCaret);
        setCaret(newCaret);
      }
    });
  };

  const submit = () => {
    const q = draft.trim();
    if (q) recordRecent(q);
    onSubmit(q);
    inputRef.current?.blur();
    setFocused(false);
  };

  const runQuery = (q: string) => {
    setDraft(q);
    recordRecent(q);
    onSubmit(q);
    setQueriesOpen(false);
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
        // Back past the top returns to "nothing highlighted".
        setActiveIdx((i) => Math.max(i - 1, -1));
        return;
      }
      if (e.key === 'Tab' && suggestions.length > 0) {
        // Tab always completes (top suggestion if none highlighted).
        e.preventDefault();
        applySuggestion(suggestions[Math.max(activeIdx, 0)]);
        return;
      }
      if (e.key === 'Enter' && activeIdx >= 0 && suggestions[activeIdx]) {
        // Enter accepts only an explicitly highlighted suggestion;
        // otherwise it falls through and submits the query.
        e.preventDefault();
        applySuggestion(suggestions[activeIdx]);
        return;
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
        <button
          onClick={() => setQueriesOpen((o) => !o)}
          className={`text-[10px] font-mono uppercase tracking-wider shrink-0 border px-1.5 py-0.5 transition-colors ${
            queriesOpen
              ? 'text-matrix-400 border-matrix-500/40'
              : 'text-gray-500 hover:text-matrix-500 border-void-700 hover:border-matrix-500/40'
          }`}
          title="Saved and recent queries"
          aria-label="Saved and recent queries"
          aria-expanded={queriesOpen}
        >
          ★
        </button>
        <Link
          to="/query"
          className="text-[10px] font-mono text-gray-500 hover:text-matrix-500 uppercase tracking-wider shrink-0 border border-void-700 hover:border-matrix-500/40 px-1.5 py-0.5"
          title="Query syntax reference"
        >
          ?
        </Link>
      </div>

      {queriesOpen && (
        <SavedQueriesPanel
          panelRef={panelRef}
          saved={saved}
          recent={recent}
          onRun={runQuery}
          onStar={star}
          onUnstar={unstar}
          onRename={rename}
          onClearRecent={clearRecent}
        />
      )}

      {/* Inline error */}
      {error && (
        <div className="mt-1.5 text-xs font-mono text-breach-400 flex items-center gap-2 flex-wrap">
          <span className="text-breach-500">⚠</span>
          <span>{error.message}</span>
          {error.suggestion && (
            <button
              onClick={() => {
                const suggested = fixUnknownField(draft, fields, error.suggestion as string);
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

      {showDropdown && (
        <SuggestionList suggestions={suggestions} activeIdx={activeIdx} onPick={applySuggestion} />
      )}
    </div>
  );
}
