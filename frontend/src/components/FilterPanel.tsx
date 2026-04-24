import { useState, useMemo } from 'react';
import { useFilterOptions } from '../hooks/useDetections';
import { useMitre } from '../contexts/MitreContext';
import { TelemetryFilter } from './TelemetryFilter';
import { TagInputFilter } from './TagInputFilter';
import type { SearchFilters } from '../types';

interface FilterPanelProps {
  filters: SearchFilters;
  onFiltersChange: (filters: SearchFilters) => void;
}

// Source color mapping
const sourceColors: Record<string, string> = {
  sigma: '#a855f7',
  elastic: '#3b82f6',
  splunk: '#f97316',
  sublime: '#ec4899',
  elastic_protections: '#06b6d4',
  lolrmm: '#22c55e',
  elastic_hunting: '#8b5cf6',
  sentinel: '#0078d4',
};

export function FilterPanel({ filters, onFiltersChange }: FilterPanelProps) {
  const { tactics, techniques } = useMitre();

  // Convert tactics from context into sorted options array
  const tacticOptions = useMemo(() => {
    const options = Object.values(tactics).map((tactic) => ({
      value: tactic.id,
      label: tactic.name,
    }));
    // Sort by tactic ID to maintain consistent order
    return options.sort((a, b) => a.value.localeCompare(b.value));
  }, [tactics]);

  // MITRE technique suggestions for the autocomplete filter.
  const techniqueSuggestions = useMemo(
    () =>
      Object.values(techniques)
        .filter((t) => !t.deprecated)
        .map((t) => ({ value: t.id, label: t.name }))
        .sort((a, b) => a.value.localeCompare(b.value)),
    [techniques],
  );
  const { data: filterOptions } = useFilterOptions();
  const [showAllTactics, setShowAllTactics] = useState(false);
  const [expandedSections, setExpandedSections] = useState<Set<string>>(
    new Set(['source', 'severity', 'status', 'telemetry'])
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

  const hasActiveFilters =
    (filters.sources?.length || 0) > 0 ||
    (filters.statuses?.length || 0) > 0 ||
    (filters.severities?.length || 0) > 0 ||
    (filters.languages?.length || 0) > 0 ||
    (filters.mitre_tactics?.length || 0) > 0 ||
    (filters.mitre_techniques?.length || 0) > 0 ||
    (filters.log_sources?.length || 0) > 0 ||
    (filters.platforms?.length || 0) > 0 ||
    (filters.event_categories?.length || 0) > 0 ||
    (filters.event_ids?.length || 0) > 0 ||
    (filters.process_names?.length || 0) > 0 ||
    (filters.query_complexity?.length || 0) > 0 ||
    (filters.api_actions?.length || 0) > 0;

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
      style={{
        clipPath: 'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))',
      }}
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
            {[
              { value: 'sigma', label: 'Sigma' },
              { value: 'elastic', label: 'Elastic' },
              { value: 'splunk', label: 'Splunk' },
              { value: 'sublime', label: 'Sublime' },
              { value: 'elastic_protections', label: 'Elastic Protect' },
              { value: 'lolrmm', label: 'LOLRMM' },
              { value: 'elastic_hunting', label: 'Elastic Hunting' },
              { value: 'sentinel', label: 'Microsoft Sentinel' },
            ].map((source) => (
              <label
                key={source.value}
                className="flex items-center gap-2 py-1.5 px-2 rounded cursor-pointer hover:bg-void-800 transition-colors group"
              >
                <input
                  type="checkbox"
                  checked={filters.sources?.includes(source.value) || false}
                  onChange={(e) =>
                    handleMultiSelect('sources', source.value, e.target.checked)
                  }
                  className="w-3.5 h-3.5 rounded-sm bg-void-900 border-void-600 text-matrix-500 focus:ring-matrix-500/50 focus:ring-offset-void-900"
                />
                <span
                  className="w-2 h-2 rounded-full"
                  style={{ backgroundColor: sourceColors[source.value] }}
                />
                <span className="text-sm text-gray-400 group-hover:text-white transition-colors">
                  {source.label}
                </span>
              </label>
            ))}
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
              </label>
            ))}
          </div>
        )}
      </div>

      {/* Status filter */}
      <div className="mb-3">
        <SectionHeader title="Status" section="status" count={filters.statuses?.length} />
        {expandedSections.has('status') && (
          <div className="space-y-1 mt-2">
            {[
              { value: 'stable', label: 'Stable', color: '#00ff41' },
              { value: 'experimental', label: 'Experimental', color: '#fbbf24' },
              { value: 'deprecated', label: 'Deprecated', color: '#ff0040' },
              { value: 'unknown', label: 'Unknown', color: '#6b7280' },
            ].map((status) => (
              <label
                key={status.value}
                className="flex items-center gap-2 py-1.5 px-2 rounded cursor-pointer hover:bg-void-800 transition-colors group"
              >
                <input
                  type="checkbox"
                  checked={filters.statuses?.includes(status.value) || false}
                  onChange={(e) =>
                    handleMultiSelect('statuses', status.value, e.target.checked)
                  }
                  className="w-3.5 h-3.5 rounded-sm bg-void-900 border-void-600 text-matrix-500 focus:ring-matrix-500/50 focus:ring-offset-void-900"
                />
                <span
                  className="w-2 h-2 rounded-full"
                  style={{ backgroundColor: status.color }}
                />
                <span className="text-sm text-gray-400 group-hover:text-white transition-colors capitalize">
                  {status.label}
                </span>
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
            {[
              { value: 'sigma', label: 'Sigma' },
              { value: 'spl', label: 'SPL (Splunk)' },
              { value: 'eql', label: 'EQL (Elastic)' },
              { value: 'esql', label: 'ES|QL (Elastic)' },
              { value: 'kql', label: 'KQL (Kibana)' },
              { value: 'lucene', label: 'Lucene' },
              { value: 'mql', label: 'MQL (Sublime)' },
              { value: 'ml', label: 'ML' },
              { value: 'threat_match', label: 'Threat Match' },
            ].map((lang) => (
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
          Event Type). Options + counts come from the live corpus via
          /api/detections/filters; no hardcoded lists. Replaces ~170
          lines of stale Platform subcategories + hardcoded Event
          Category list. */}
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
                platforms: filterOptions?.platforms || [],
                data_sources: filterOptions?.data_sources || [],
                event_types: filterOptions?.event_types || [],
              }}
            />
          </div>
        )}
      </div>

      {/* Log Sources filter */}
      <div className="mb-3">
        <SectionHeader title="Log Sources" section="logsources" count={filters.log_sources?.length} />
        {expandedSections.has('logsources') && (
          <div className="mt-2">
            <TagInputFilter
              values={filters.log_sources || []}
              onChange={(values) =>
                onFiltersChange({ ...filters, log_sources: values, offset: 0 })
              }
              placeholder="e.g., windows"
              normalize={(raw) => raw.trim().toLowerCase()}
              accent="orange"
            />
          </div>
        )}
      </div>

      {/* Event IDs filter */}
      <div className="mb-3">
        <SectionHeader title="Event IDs" section="eventids" count={filters.event_ids?.length} />
        {expandedSections.has('eventids') && (
          <div className="mt-2">
            <TagInputFilter
              values={filters.event_ids || []}
              onChange={(values) =>
                onFiltersChange({ ...filters, event_ids: values, offset: 0 })
              }
              placeholder="e.g., 4688"
              accent="orange"
            />
          </div>
        )}
      </div>

      {/* Process Names filter */}
      <div className="mb-3">
        <SectionHeader title="Process Names" section="processnames" count={filters.process_names?.length} />
        {expandedSections.has('processnames') && (
          <div className="mt-2">
            <TagInputFilter
              values={filters.process_names || []}
              onChange={(values) =>
                onFiltersChange({ ...filters, process_names: values, offset: 0 })
              }
              placeholder="e.g., powershell.exe"
              normalize={(raw) => raw.trim().toLowerCase()}
              accent="matrix"
            />
          </div>
        )}
      </div>

      {/* Query Complexity filter */}
      <div className="mb-3">
        <SectionHeader title="Query Complexity" section="complexity" count={filters.query_complexity?.length} />
        {expandedSections.has('complexity') && (
          <div className="space-y-1 mt-2">
            {[
              { value: 'simple', label: 'Simple', color: '#00ff41' },
              { value: 'moderate', label: 'Moderate', color: '#fbbf24' },
              { value: 'complex', label: 'Complex', color: '#ff0040' },
            ].map((complexity) => (
              <label
                key={complexity.value}
                className="flex items-center gap-2 py-1.5 px-2 rounded cursor-pointer hover:bg-void-800 transition-colors group"
              >
                <input
                  type="checkbox"
                  checked={filters.query_complexity?.includes(complexity.value) || false}
                  onChange={(e) =>
                    handleMultiSelect('query_complexity', complexity.value, e.target.checked)
                  }
                  className="w-3.5 h-3.5 rounded-sm bg-void-900 border-void-600 text-matrix-500 focus:ring-matrix-500/50 focus:ring-offset-void-900"
                />
                <span
                  className="w-2 h-2 rounded-full"
                  style={{ backgroundColor: complexity.color }}
                />
                <span className="text-sm text-gray-400 group-hover:text-white transition-colors capitalize">
                  {complexity.label}
                </span>
              </label>
            ))}
          </div>
        )}
      </div>

      {/* API Actions filter */}
      <div className="mb-3">
        <SectionHeader title="API Actions" section="apiactions" count={filters.api_actions?.length} />
        {expandedSections.has('apiactions') && (
          <div className="mt-2">
            <TagInputFilter
              values={filters.api_actions || []}
              onChange={(values) =>
                onFiltersChange({ ...filters, api_actions: values, offset: 0 })
              }
              placeholder="e.g., CreateUser"
              accent="cyan"
            />
          </div>
        )}
      </div>
    </div>
  );
}
