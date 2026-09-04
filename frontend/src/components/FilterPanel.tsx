/** Catalog filter sidebar. Every section renders live "what would
 * this click yield" counts from the query-scoped facets. Section
 * bodies and vocabularies live in components/filterpanel/. */

import { useState, useMemo } from 'react';
import { useFacets } from '../hooks/useDetections';
import { useEventIds } from '../hooks/useEventIds';
import { useMitre } from '../contexts/MitreContext';
import { ALL_SOURCES, sourceColors, sourceLabels } from '../constants/sources';
import { TelemetryFilter } from './TelemetryFilter';
import { TagInputFilter } from './TagInputFilter';
import type { SearchFilters } from '../types';
import { clipMd } from '../constants/style';
import { countActiveFilters } from '../utils/filterUtils';
import { SectionHeader } from './filterpanel/SectionHeader';
import { CheckboxOption } from './filterpanel/CheckboxOption';
import { StatusSection } from './filterpanel/StatusSection';
import { HygieneSection } from './filterpanel/HygieneSection';
import { TacticsSection } from './filterpanel/TacticsSection';
import { ObservablesSection } from './filterpanel/ObservablesSection';
import { SEVERITY_OPTIONS, LANGUAGE_LABELS, MODALITY_OPTIONS, countMap } from './filterpanel/options';

interface FilterPanelProps {
  filters: SearchFilters;
  onFiltersChange: (filters: SearchFilters) => void;
}

export function FilterPanel({ filters, onFiltersChange }: FilterPanelProps) {
  const { tactics, techniques } = useMitre();

  // Facet counts scoped to the active query.
  const { data: facets } = useFacets(filters);
  const { labels: eventIdLabels } = useEventIds();
  const sourceCounts = useMemo(() => countMap(facets?.sources), [facets]);
  const severityCounts = useMemo(() => countMap(facets?.severities), [facets]);
  const statusCounts = useMemo(() => countMap(facets?.statuses), [facets]);
  const buildingBlockCount = facets?.building_block?.find((o) => o.value === 'true')?.count;
  const qualityBandCounts = useMemo(() => countMap(facets?.quality_band), [facets]);
  const languageCounts = useMemo(() => countMap(facets?.languages), [facets]);
  const modalityCounts = useMemo(() => countMap(facets?.rule_modalities), [facets]);
  const tacticCounts = useMemo(() => countMap(facets?.mitre_tactics), [facets]);

  // Sources come from the live facet (scoped to the active query) so
  // new upstream repos appear automatically without a code change.
  // Preserves the intentional ALL_SOURCES ordering so long-standing
  // sources stay in their familiar position; values unknown to
  // ALL_SOURCES (right after ingest of a new source that predates the
  // FE deploy) append at the bottom. Sources with zero matches stay
  // listed (their own selection is excluded from the count, and the
  // query may change) but render dimmed.
  const sourceOptions = useMemo(() => {
    const facetValues = (facets?.sources || []).map((f) => f.value);
    const ordered: string[] = (ALL_SOURCES as readonly string[]).filter((s) => facetValues.includes(s));
    for (const s of facetValues) if (!ordered.includes(s)) ordered.push(s);
    return ordered;
  }, [facets]);

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

  // Tactics from context, sorted by ID for a stable order.
  const tacticOptions = useMemo(
    () =>
      Object.values(tactics)
        .map((tactic) => ({ value: tactic.id, label: tactic.name }))
        .sort((a, b) => a.value.localeCompare(b.value)),
    [tactics],
  );

  // MITRE technique suggestions for the autocomplete filter -- built
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

  const [expandedSections, setExpandedSections] = useState<Set<string>>(
    new Set(['source', 'status', 'severity', 'telemetry'])
  );
  const toggleSection = (section: string) => {
    const next = new Set(expandedSections);
    if (next.has(section)) next.delete(section);
    else next.add(section);
    setExpandedSections(next);
  };

  const toggle = (field: keyof SearchFilters, value: string, checked: boolean) => {
    const current = (filters[field] as string[]) || [];
    const updated = checked ? [...current, value] : current.filter((v) => v !== value);
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
  const ctx = { filters, onFiltersChange, toggle };

  const section = (id: string, title: string, count: number | undefined, body: React.ReactNode) => (
    <div className="mb-3">
      <SectionHeader title={title} count={count} expanded={expandedSections.has(id)} onToggle={() => toggleSection(id)} />
      {expandedSections.has(id) && body}
    </div>
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

      {section('source', 'Source', filters.sources?.length, (
        <div className="space-y-1 mt-2">
          {sourceOptions.map((value) => (
            <CheckboxOption
              key={value}
              checked={filters.sources?.includes(value) || false}
              onChange={(checked) => toggle('sources', value, checked)}
              label={sourceLabels[value] || value}
              color={sourceColors[value] || '#6b7280'}
              count={sourceCounts[value]}
            />
          ))}
        </div>
      ))}

      {section('severity', 'Severity', filters.severities?.length, (
        <div className="space-y-1 mt-2">
          {SEVERITY_OPTIONS.map((severity) => (
            <CheckboxOption
              key={severity.value}
              checked={filters.severities?.includes(severity.value) || false}
              onChange={(checked) => toggle('severities', severity.value, checked)}
              label={severity.label}
              color={severity.color}
              labelClass="capitalize"
              count={severityCounts[severity.value]}
            />
          ))}
        </div>
      ))}

      {section(
        'status',
        'Status',
        (filters.statuses?.length || 0) + (filters.building_block !== undefined ? 1 : 0),
        <StatusSection {...ctx} statusCounts={statusCounts} buildingBlockCount={buildingBlockCount} />,
      )}

      {section(
        'hygiene',
        'Completeness',
        filters.min_quality !== undefined ? 1 : 0,
        <HygieneSection filters={filters} onFiltersChange={onFiltersChange} bandCounts={qualityBandCounts} />,
      )}

      {section('modality', 'Modality', filters.rule_modalities?.length, (
        <div className="space-y-1 mt-2">
          {MODALITY_OPTIONS.filter((m) => modalityCounts[m.value] || filters.rule_modalities?.includes(m.value)).map((m) => (
            <CheckboxOption
              key={m.value}
              checked={filters.rule_modalities?.includes(m.value) || false}
              onChange={(checked) => toggle('rule_modalities', m.value, checked)}
              label={m.label}
              count={modalityCounts[m.value]}
              title={m.hint}
            />
          ))}
        </div>
      ))}

      {section('language', 'Language', filters.languages?.length, (
        <div className="space-y-1 mt-2">
          {languageOptions.map((lang) => (
            <CheckboxOption
              key={lang.value}
              checked={filters.languages?.includes(lang.value) || false}
              onChange={(checked) => toggle('languages', lang.value, checked)}
              label={lang.label}
              count={languageCounts[lang.value]}
            />
          ))}
        </div>
      ))}

      {section(
        'tactics',
        'MITRE Tactics',
        filters.mitre_tactics?.length,
        <TacticsSection filters={filters} toggle={toggle} options={tacticOptions} counts={tacticCounts} />,
      )}

      {section('techniques', 'MITRE Technique', filters.mitre_techniques?.length, (
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
      ))}

      {/* Telemetry -- canonical taxonomy facets (Domain / Platform / Data
          Source / Event Type / Product). Options + counts come from the live query-scoped
          facets; no hardcoded lists, and counts narrow as other
          filters apply. */}
      {section(
        'telemetry',
        'Telemetry',
        (filters.platforms?.length || 0) +
          (filters.domains?.length || 0) +
          (filters.products?.length || 0) +
          (filters.data_sources_normalized?.length || 0) +
          (filters.event_categories?.length || 0),
        (
          <div className="mt-2">
            <TelemetryFilter
              filters={filters}
              onFiltersChange={onFiltersChange}
              options={{
                domains: facets?.domains || [],
                platforms: facets?.platforms || [],
                data_sources: facets?.data_sources || [],
                event_types: facets?.event_types || [],
                event_type_groups: facets?.event_type_groups || [],
                products: facets?.products || [],
              }}
            />
          </div>
        ),
      )}

      {section(
        'observables',
        'Observables',
        (filters.process_names?.length || 0) +
          (filters.api_actions?.length || 0) +
          (filters.source_tables?.length || 0) +
          (filters.event_ids?.length || 0),
        <ObservablesSection filters={filters} onFiltersChange={onFiltersChange} facets={facets} eventIdLabels={eventIdLabels} />,
      )}
    </div>
  );
}
