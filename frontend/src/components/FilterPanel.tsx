import { useState, useMemo } from 'react';
import { useFilterOptions } from '../hooks/useDetections';
import { useMitre } from '../contexts/MitreContext';
import type { SearchFilters } from '../types';

interface FilterPanelProps {
  filters: SearchFilters;
  onFiltersChange: (filters: SearchFilters) => void;
}

export function FilterPanel({ filters, onFiltersChange }: FilterPanelProps) {
  const { tactics } = useMitre();

  // Convert tactics from context into sorted options array
  const tacticOptions = useMemo(() => {
    const options = Object.values(tactics).map((tactic) => ({
      value: tactic.id,
      label: tactic.name,
    }));
    // Sort by tactic ID to maintain consistent order
    return options.sort((a, b) => a.value.localeCompare(b.value));
  }, [tactics]);
  const { data: _options } = useFilterOptions();
  const [showAllTactics, setShowAllTactics] = useState(false);

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
    (filters.log_sources?.length || 0) > 0;

  const visibleTactics = showAllTactics ? tacticOptions : tacticOptions.slice(0, 5);

  return (
    <div className="bg-cyber-850 rounded-lg border border-cyber-700 p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="font-semibold text-white">Filters</h3>
        {hasActiveFilters && (
          <button
            onClick={clearFilters}
            className="text-sm text-cyan-400 hover:text-cyan-300"
          >
            Clear all
          </button>
        )}
      </div>

      {/* Source filter */}
      <div className="mb-4">
        <label className="block text-sm font-medium text-gray-400 mb-2">
          Source
        </label>
        <div className="space-y-1">
          {[
            { value: 'sigma', label: 'Sigma' },
            { value: 'elastic', label: 'Elastic' },
            { value: 'splunk', label: 'Splunk' },
            { value: 'sublime', label: 'Sublime' },
            { value: 'elastic_protections', label: 'Elastic Protect' },
            { value: 'lolrmm', label: 'LOLRMM' },
          ].map((source) => (
            <label key={source.value} className="flex items-center text-gray-300 hover:text-white cursor-pointer">
              <input
                type="checkbox"
                checked={filters.sources?.includes(source.value) || false}
                onChange={(e) =>
                  handleMultiSelect('sources', source.value, e.target.checked)
                }
                className="rounded bg-cyber-900 border-cyber-600 text-cyan-500 focus:ring-cyan-500 mr-2"
              />
              <span className="text-sm">{source.label}</span>
            </label>
          ))}
        </div>
      </div>

      {/* Severity filter */}
      <div className="mb-4">
        <label className="block text-sm font-medium text-gray-400 mb-2">
          Severity
        </label>
        <div className="space-y-1">
          {['critical', 'high', 'medium', 'low', 'unknown'].map((severity) => (
            <label key={severity} className="flex items-center text-gray-300 hover:text-white cursor-pointer">
              <input
                type="checkbox"
                checked={filters.severities?.includes(severity) || false}
                onChange={(e) =>
                  handleMultiSelect('severities', severity, e.target.checked)
                }
                className="rounded bg-cyber-900 border-cyber-600 text-cyan-500 focus:ring-cyan-500 mr-2"
              />
              <span className="text-sm capitalize">{severity}</span>
            </label>
          ))}
        </div>
      </div>

      {/* Status filter */}
      <div className="mb-4">
        <label className="block text-sm font-medium text-gray-400 mb-2">
          Status
        </label>
        <div className="space-y-1">
          {['stable', 'experimental', 'deprecated', 'unknown'].map((status) => (
            <label key={status} className="flex items-center text-gray-300 hover:text-white cursor-pointer">
              <input
                type="checkbox"
                checked={filters.statuses?.includes(status) || false}
                onChange={(e) =>
                  handleMultiSelect('statuses', status, e.target.checked)
                }
                className="rounded bg-cyber-900 border-cyber-600 text-cyan-500 focus:ring-cyan-500 mr-2"
              />
              <span className="text-sm capitalize">{status}</span>
            </label>
          ))}
        </div>
      </div>

      {/* Language filter */}
      <div className="mb-4">
        <label className="block text-sm font-medium text-gray-400 mb-2">
          Language
        </label>
        <div className="space-y-1">
          {[
            { value: 'sigma', label: 'Sigma' },
            { value: 'spl', label: 'SPL (Splunk)' },
            { value: 'eql', label: 'EQL (Elastic)' },
            { value: 'esql', label: 'ES|QL (Elastic)' },
            { value: 'kql', label: 'KQL (Kibana)' },
            { value: 'lucene', label: 'Lucene' },
            { value: 'mql', label: 'MQL (Sublime)' },
            { value: 'ml', label: 'ML (Machine Learning)' },
            { value: 'threat_match', label: 'Threat Match' },
          ].map((lang) => (
            <label key={lang.value} className="flex items-center text-gray-300 hover:text-white cursor-pointer">
              <input
                type="checkbox"
                checked={filters.languages?.includes(lang.value) || false}
                onChange={(e) =>
                  handleMultiSelect('languages', lang.value, e.target.checked)
                }
                className="rounded bg-cyber-900 border-cyber-600 text-cyan-500 focus:ring-cyan-500 mr-2"
              />
              <span className="text-sm">{lang.label}</span>
            </label>
          ))}
        </div>
      </div>

      {/* MITRE Tactic filter */}
      <div className="mb-4">
        <label className="block text-sm font-medium text-gray-400 mb-2">
          MITRE Tactics
        </label>
        <div className="space-y-1">
          {visibleTactics.map((tactic) => (
            <label key={tactic.value} className="flex items-center text-gray-300 hover:text-white cursor-pointer">
              <input
                type="checkbox"
                checked={filters.mitre_tactics?.includes(tactic.value) || false}
                onChange={(e) =>
                  handleMultiSelect('mitre_tactics', tactic.value, e.target.checked)
                }
                className="rounded bg-cyber-900 border-cyber-600 text-cyan-500 focus:ring-cyan-500 mr-2"
              />
              <span className="text-sm" title={tactic.value}>
                {tactic.label}
              </span>
            </label>
          ))}
        </div>
        {tacticOptions.length > 5 && (
          <button
            onClick={() => setShowAllTactics(!showAllTactics)}
            className="text-sm text-cyan-400 hover:text-cyan-300 mt-1"
          >
            {showAllTactics ? 'Show less' : `Show ${tacticOptions.length - 5} more`}
          </button>
        )}
      </div>

      {/* MITRE Technique filter */}
      <div className="mb-4">
        <label className="block text-sm font-medium text-gray-400 mb-1">
          MITRE Technique
        </label>
        <input
          type="text"
          placeholder="e.g., T1059 (Enter to add)"
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              const value = (e.target as HTMLInputElement).value.trim().toUpperCase();
              if (value && !filters.mitre_techniques?.includes(value)) {
                onFiltersChange({
                  ...filters,
                  mitre_techniques: [...(filters.mitre_techniques || []), value],
                  offset: 0,
                });
                (e.target as HTMLInputElement).value = '';
              }
            }
          }}
          className="w-full px-3 py-2 bg-cyber-900 border border-cyber-700 rounded-md text-sm text-white placeholder-gray-500 focus:ring-cyan-500 focus:border-cyan-500"
        />
        {filters.mitre_techniques?.length ? (
          <div className="flex flex-wrap gap-1 mt-2">
            {filters.mitre_techniques.map((tech) => (
              <span
                key={tech}
                className="inline-flex items-center px-2 py-1 bg-cyan-500/20 text-cyan-400 text-xs rounded border border-cyan-500/30"
              >
                {tech}
                <button
                  onClick={() =>
                    onFiltersChange({
                      ...filters,
                      mitre_techniques: filters.mitre_techniques?.filter(
                        (t) => t !== tech
                      ),
                      offset: 0,
                    })
                  }
                  className="ml-1 hover:text-cyan-200"
                >
                  x
                </button>
              </span>
            ))}
          </div>
        ) : null}
      </div>

      {/* Log Sources filter */}
      <div className="mb-4">
        <label className="block text-sm font-medium text-gray-400 mb-1">
          Log Sources
        </label>
        <input
          type="text"
          placeholder="e.g., windows (Enter to add)"
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              const value = (e.target as HTMLInputElement).value.trim().toLowerCase();
              if (value && !filters.log_sources?.includes(value)) {
                onFiltersChange({
                  ...filters,
                  log_sources: [...(filters.log_sources || []), value],
                  offset: 0,
                });
                (e.target as HTMLInputElement).value = '';
              }
            }
          }}
          className="w-full px-3 py-2 bg-cyber-900 border border-cyber-700 rounded-md text-sm text-white placeholder-gray-500 focus:ring-cyan-500 focus:border-cyan-500"
        />
        {filters.log_sources?.length ? (
          <div className="flex flex-wrap gap-1 mt-2">
            {filters.log_sources.map((src) => (
              <span
                key={src}
                className="inline-flex items-center px-2 py-1 bg-green-500/20 text-green-400 text-xs rounded border border-green-500/30"
              >
                {src}
                <button
                  onClick={() =>
                    onFiltersChange({
                      ...filters,
                      log_sources: filters.log_sources?.filter(
                        (s) => s !== src
                      ),
                      offset: 0,
                    })
                  }
                  className="ml-1 hover:text-green-200"
                >
                  x
                </button>
              </span>
            ))}
          </div>
        ) : null}
      </div>
    </div>
  );
}
