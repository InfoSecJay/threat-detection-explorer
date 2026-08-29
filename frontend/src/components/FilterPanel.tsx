import { useState, useMemo } from 'react';
import { useFacets } from '../hooks/useDetections';
import { useEventIds } from '../hooks/useEventIds';
import { useMitre } from '../contexts/MitreContext';
import { ALL_SOURCES, sourceColors, sourceLabels } from '../constants/sources';
import { TelemetryFilter, Facet } from './TelemetryFilter';
import { TagInputFilter } from './TagInputFilter';
import type { SearchFilters } from '../types';
import { clipMd } from '../constants/style';
import { countActiveFilters } from '../utils/filterUtils';

interface FilterPanelProps {
  filters: SearchFilters;
  onFiltersChange: (filters: SearchFilters) => void;
}

/** [{value, count}] -> {value: count} lookup. */
function countMap(facet?: Array<{ value: string; count: number }>): Record<string, number> {
  const map: Record<string, number> = {};
  for (const f of facet || []) map[f.value] = f.count;
  return map;
}

/** Display labels for query languages. Unlisted values render raw —
 * the facet decides what exists, this only prettifies. */
const LANGUAGE_LABELS: Record<string, string> = {
  sigma: 'Sigma',
  spl: 'SPL (Splunk)',
  eql: 'EQL (Elastic)',
  esql: 'ES|QL (Elastic)',
  // Both Sentinel analytic rules and Kibana KQL rules carry `kql`;
  // the old "KQL (Kibana)" label misdescribed 3,000+ Sentinel rules.
  kql: 'KQL (Sentinel / Kibana)',
  mql: 'MQL (Sublime)',
  yaral: 'YARA-L (Chronicle)',
  oie: 'OIE (Okta)',
  python: 'Python (Panther)',
  panther_correlation: 'Panther Correlation',
  panther: 'Panther Declarative',
  osquery: 'osquery',
  ml: 'ML',
  threat_match: 'Threat Match',
};

/** Count badge rendered on every facet option — shows how many rules
 * the option matches under the current query, dimmed when zero so
 * users stop clicking into empty result sets. */
function FacetCount({ count }: { count: number | undefined }) {
  return (
    <span
      className={`ml-auto text-[10px] font-mono shrink-0 ${
        count ? 'text-gray-600' : 'text-gray-700'
      }`}
    >
      {(count || 0).toLocaleString()}
    </span>
  );
}

export function FilterPanel({ filters, onFiltersChange }: FilterPanelProps) {
  const { tactics, techniques } = useMitre();

  // Facet counts scoped to the active query — every section below
  // renders live "what would this click yield" numbers from these.
  const { data: facets } = useFacets(filters);
  const { labels: eventIdLabels } = useEventIds();
  const sourceCounts = useMemo(() => countMap(facets?.sources), [facets]);
  const severityCounts = useMemo(() => countMap(facets?.severities), [facets]);
  const languageCounts = useMemo(() => countMap(facets?.languages), [facets]);

  // Language options come from the live facet (like Source) so the list
  // can't drift from the corpus: no dead options (`lucene` shipped for
  // months with zero rules), and new query languages appear on ingest.
  const languageOptions = useMemo(
    () =>
      (facets?.languages || []).map((f) => ({
        value: f.value,
        label: LANGUAGE_LABELS[f.value] || f.value,
      })),
    [facets],
  );
  const tacticCounts = useMemo(() => countMap(facets?.mitre_tactics), [facets]);

  // Convert tactics from context into sorted options array
  const tacticOptions = useMemo(() => {
    const options = Object.values(tactics).map((tactic) => ({
      value: tactic.id,
      label: tactic.name,
    }));
    // Sort by tactic ID to maintain consistent order
    return options.sort((a, b) => a.value.localeCompare(b.value));
  }, [tactics]);

  // MITRE technique suggestions for the autocomplete filter — built
  // from the live facet so users only see techniques that actually
  // have rules under the current query, with match counts inline.
  const techniqueSuggestions = useMemo(
    () =>
      (facets?.mitre_techniques || []).map((f) => {
        const t = techniques[f.value];
        return {
          value: f.value,
          label: `${t?.name || 'Unknown technique'} · ${f.count.toLocaleString()}`,
        };
      }),
    [facets, techniques],
  );
  const [showAllTactics, setShowAllTactics] = useState(false);
  const [expandedSections, setExpandedSections] = useState<Set<string>>(
    new Set(['source', 'severity', 'telemetry'])
  );

  const toggleSection = (section: string) => {
    const newExpanded = new Set(expandedSections);
    if (newExpanded.has(section)) {
      newExpanded.delete(section);
    } else {
      newExpanded.add(section);
    }
    setExpandedSections(newExpanded);
  };

  const handleMultiSelect = (
    field: keyof SearchFilters,
    value: string,
    checked: boolean
  ) => {
    const current = (filters[field] as string[]) || [];
    const updated = checked
      ? [...current, value]
      : current.filter((v) => v !== value);
    onFiltersChange({ ...filters, [field]: updated, offset: 0 });
  };

  const clearFilters = () => {
    onFiltersChange({
      search: filters.search, // Preserve search when clearing filters
      offset: 0,
      limit: filters.limit,
      sort_by: filters.sort_by,
      sort_order: filters.sort_order,
    });
  };

  const hasActiveFilters = countActiveFilters(filters) > 0;

  const visibleTactics = showAllTactics ? tacticOptions : tacticOptions.slice(0, 5);

  // Section header component
  const SectionHeader = ({ title, section, count }: { title: string; section: string; count?: number }) => (
    <button
      onClick={() => toggleSection(section)}
      className="w-full flex items-center justify-between py-2 text-left group"
    >
      <span className="text-xs font-display font-semibold text-gray-400 uppercase tracking-wider group-hover:text-matrix-500 transition-colors">
        {title}
        {count !== undefined && count > 0 && (
          <span className="ml-2 text-matrix-500">({count})</span>
        )}
      </span>
      <svg
        className={`w-4 h-4 text-gray-500 transition-transform ${expandedSections.has(section) ? 'rotate-180' : ''}`}
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
      >
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
      </svg>
    </button>
  );

  return (
    <div
      className="bg-void-850 border border-void-700 p-4"
      style={clipMd}
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-4 pb-3 border-b border-void-700">
        <div className="flex items-center gap-2">
          <svg className="w-4 h-4 text-matrix-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z" />
          </svg>
          <h3 className="font-display font-semibold text-white text-sm uppercase tracking-wider">Filters</h3>
        </div>
        {hasActiveFilters && (
          <button
            onClick={clearFilters}
            className="text-xs font-mono text-breach-400 hover:text-breach-300 transition-colors"
          >
            CLEAR
          </button>
        )}
      </div>

      {/* Source filter */}
      <div className="mb-3">
        <SectionHeader title="Source" section="source" count={filters.sources?.length} />
        {expandedSections.has('source') && (
          <div className="space-y-1 mt-2">
            {/* Sources come from the live facet (scoped to the active
                query) so new upstream repos appear automatically
                without a code change. Preserves the intentional
                ALL_SOURCES ordering as the render order so
                long-standing sources stay in their familiar visual
                position. Unknown-to-ALL_SOURCES values (e.g. right
                after ingest of a new source that predates the FE
                deploy) append at the bottom. Sources with zero
                matches under the current query stay listed (their
                own selection is excluded from the count, and the
                query may change) but render dimmed. */}
            {(() => {
              const facetValues = (facets?.sources || []).map((f) => f.value);
              const ordered: string[] = [];
              for (const s of ALL_SOURCES) {
                if (facetValues.includes(s)) ordered.push(s);
              }
              for (const s of facetValues) {
                if (!ordered.includes(s)) ordered.push(s);
              }
              return ordered.map((value) => (
                <label
                  key={value}
                  className="flex items-center gap-2 py-1.5 px-2 rounded cursor-pointer hover:bg-void-800 transition-colors group"
                >
                  <input
                    type="checkbox"
                    checked={filters.sources?.includes(value) || false}
                    onChange={(e) =>
                      handleMultiSelect('sources', value, e.target.checked)
                    }
                    className="w-3.5 h-3.5 rounded-sm bg-void-900 border-void-600 text-matrix-500 focus:ring-matrix-500/50 focus:ring-offset-void-900"
                  />
                  <span
                    className="w-2 h-2 rounded-full"
                    style={{ backgroundColor: sourceColors[value] }}
                  />
                  <span className="text-sm text-gray-400 group-hover:text-white transition-colors">
                    {sourceLabels[value] || value}
                  </span>
                  <FacetCount count={sourceCounts[value]} />
                </label>
              ));
            })()}
          </div>
        )}
      </div>

      {/* Severity filter */}
      <div className="mb-3">
        <SectionHeader title="Severity" section="severity" count={filters.severities?.length} />
        {expandedSections.has('severity') && (
          <div className="space-y-1 mt-2">
            {[
              { value: 'critical', label: 'Critical', color: '#ff0040' },
              { value: 'high', label: 'High', color: '#ff9500' },
              { value: 'medium', label: 'Medium', color: '#fbbf24' },
              { value: 'low', label: 'Low', color: '#00ff41' },
              { value: 'unknown', label: 'Unknown', color: '#6b7280' },
            ].map((severity) => (
              <label
                key={severity.value}
                className="flex items-center gap-2 py-1.5 px-2 rounded cursor-pointer hover:bg-void-800 transition-colors group"
              >
                <input
                  type="checkbox"
                  checked={filters.severities?.includes(severity.value) || false}
                  onChange={(e) =>
                    handleMultiSelect('severities', severity.value, e.target.checked)
                  }
                  className="w-3.5 h-3.5 rounded-sm bg-void-900 border-void-600 text-matrix-500 focus:ring-matrix-500/50 focus:ring-offset-void-900"
                />
                <span
                  className="w-2 h-2 rounded-full"
                  style={{ backgroundColor: severity.color }}
                />
                <span className="text-sm text-gray-400 group-hover:text-white transition-colors capitalize">
                  {severity.label}
                </span>
                <FacetCount count={severityCounts[severity.value]} />
              </label>
            ))}
          </div>
        )}
      </div>

      {/* Language filter */}
      <div className="mb-3">
        <SectionHeader title="Language" section="language" count={filters.languages?.length} />
        {expandedSections.has('language') && (
          <div className="space-y-1 mt-2">
            {languageOptions.map((lang) => (
              <label
                key={lang.value}
                className="flex items-center gap-2 py-1.5 px-2 rounded cursor-pointer hover:bg-void-800 transition-colors group"
              >
                <input
                  type="checkbox"
                  checked={filters.languages?.includes(lang.value) || false}
                  onChange={(e) =>
                    handleMultiSelect('languages', lang.value, e.target.checked)
                  }
                  className="w-3.5 h-3.5 rounded-sm bg-void-900 border-void-600 text-matrix-500 focus:ring-matrix-500/50 focus:ring-offset-void-900"
                />
                <span className="text-sm text-gray-400 group-hover:text-white transition-colors">
                  {lang.label}
                </span>
                <FacetCount count={languageCounts[lang.value]} />
              </label>
            ))}
          </div>
        )}
      </div>

      {/* MITRE Tactic filter */}
      <div className="mb-3">
        <SectionHeader title="MITRE Tactics" section="tactics" count={filters.mitre_tactics?.length} />
        {expandedSections.has('tactics') && (
          <div className="mt-2">
            <div className="space-y-1">
              {visibleTactics.map((tactic) => (
                <label
                  key={tactic.value}
                  className="flex items-center gap-2 py-1.5 px-2 rounded cursor-pointer hover:bg-void-800 transition-colors group"
                >
                  <input
                    type="checkbox"
                    checked={filters.mitre_tactics?.includes(tactic.value) || false}
                    onChange={(e) =>
                      handleMultiSelect('mitre_tactics', tactic.value, e.target.checked)
                    }
                    className="w-3.5 h-3.5 rounded-sm bg-void-900 border-void-600 text-matrix-500 focus:ring-matrix-500/50 focus:ring-offset-void-900"
                  />
                  <span className="text-sm text-gray-400 group-hover:text-white transition-colors truncate" title={tactic.value}>
                    {tactic.label}
                  </span>
                  <FacetCount count={tacticCounts[tactic.value]} />
                </label>
              ))}
            </div>
            {tacticOptions.length > 5 && (
              <button
                onClick={() => setShowAllTactics(!showAllTactics)}
                className="mt-2 text-xs font-mono text-matrix-500 hover:text-matrix-400 transition-colors"
              >
                {showAllTactics ? '- SHOW LESS' : `+ ${tacticOptions.length - 5} MORE`}
              </button>
            )}
          </div>
        )}
      </div>

      {/* MITRE Technique filter — autocomplete from MitreContext */}
      <div className="mb-3">
        <SectionHeader title="MITRE Technique" section="techniques" count={filters.mitre_techniques?.length} />
        {expandedSections.has('techniques') && (
          <div className="mt-2">
            <TagInputFilter
              values={filters.mitre_techniques || []}
              onChange={(values) =>
                onFiltersChange({ ...filters, mitre_techniques: values, offset: 0 })
              }
              placeholder="Search technique ID or name…"
              suggestions={techniqueSuggestions}
              normalize={(raw) => raw.trim().toUpperCase()}
              accent="purple"
            />
          </div>
        )}
      </div>

      {/* Telemetry — canonical taxonomy facets (Platform / Data Source /
          Event Type). Options + counts come from the live query-scoped
          facets; no hardcoded lists, and counts narrow as other
          filters apply. */}
      <div className="mb-3">
        <SectionHeader
          title="Telemetry"
          section="telemetry"
          count={
            (filters.platforms?.length || 0) +
            (filters.data_sources_normalized?.length || 0) +
            (filters.event_categories?.length || 0)
          }
        />
        {expandedSections.has('telemetry') && (
          <div className="mt-2">
            <TelemetryFilter
              filters={filters}
              onFiltersChange={onFiltersChange}
              options={{
                platforms: facets?.platforms || [],
                data_sources: facets?.data_sources || [],
                event_types: facets?.event_types || [],
              }}
            />
          </div>
        )}
      </div>


      {/* Observables — what the rule logic actually keys on, from the
          per-source extractors (observables v2). Facet-backed like
          Telemetry so every option shows what a click yields; the same
          dimensions are queryable from the bar (process: / action: /
          table: / eventid:) and round-trip through the sheet. */}
      <div className="mb-3">
        <SectionHeader
          title="Observables"
          section="observables"
          count={
            (filters.process_names?.length || 0) +
            (filters.api_actions?.length || 0) +
            (filters.source_tables?.length || 0) +
            (filters.event_ids?.length || 0)
          }
        />
        {expandedSections.has('observables') && (
          <div className="mt-2 space-y-4">
            <Facet
              title="Process"
              filterKey="process_names"
              accent="red"
              options={facets?.process_names || []}
              selected={filters.process_names || []}
              onChange={(values) => onFiltersChange({ ...filters, process_names: values, offset: 0 })}
            />
            <Facet
              title="API Action"
              filterKey="api_actions"
              accent="cyan"
              options={facets?.api_actions || []}
              selected={filters.api_actions || []}
              onChange={(values) => onFiltersChange({ ...filters, api_actions: values, offset: 0 })}
            />
            <Facet
              title="Source Table"
              filterKey="source_tables"
              accent="emerald"
              options={facets?.source_tables || []}
              selected={filters.source_tables || []}
              onChange={(values) => onFiltersChange({ ...filters, source_tables: values, offset: 0 })}
            />
            <Facet
              title="Event ID"
              filterKey="event_ids"
              accent="amber"
              options={facets?.event_ids || []}
              selected={filters.event_ids || []}
              onChange={(values) => onFiltersChange({ ...filters, event_ids: values, offset: 0 })}
              labels={eventIdLabels}
            />
          </div>
        )}
      </div>
    </div>
  );
}
