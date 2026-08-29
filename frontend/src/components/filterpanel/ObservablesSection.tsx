/** Observables -- what the rule logic actually keys on, from the
 * per-source extractors (observables v2). Facet-backed like Telemetry
 * so every option shows what a click yields; the same dimensions are
 * queryable from the bar (process: / action: / table: / eventid:) and
 * round-trip through the sheet. */

import { Facet } from '../TelemetryFilter';
import type { DetectionFacets } from '../../services/api';
import type { FilterCtx } from './options';

export function ObservablesSection({
  filters, onFiltersChange, facets, eventIdLabels,
}: Omit<FilterCtx, 'toggle'> & { facets: DetectionFacets | undefined; eventIdLabels: Record<string, string> }) {
  return (
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
  );
}
