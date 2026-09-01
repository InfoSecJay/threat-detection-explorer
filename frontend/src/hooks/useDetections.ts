import { useQuery, useMutation } from '@tanstack/react-query';
import { detectionsApi, exportApi } from '../services/api';
import type { SearchFilters, ExportRequest } from '../types';

export function useDetections(filters: SearchFilters = {}) {
  return useQuery({
    queryKey: ['detections', filters],
    queryFn: () => detectionsApi.list(filters),
  });
}

export function useDetection(id: string) {
  return useQuery({
    queryKey: ['detection', id],
    queryFn: () => detectionsApi.get(id),
    enabled: !!id,
  });
}

export function useStatistics() {
  return useQuery({
    queryKey: ['statistics'],
    queryFn: detectionsApi.getStatistics,
    // Counts move only on the nightly sync; 15 min matches the CDN
    // s-maxage so a session never refetches more often than the edge
    // cache could answer differently (teardown R16 / #114).
    staleTime: 15 * 60 * 1000,
  });
}

export function useFilterOptions() {
  return useQuery({
    queryKey: ['filterOptions'],
    queryFn: detectionsApi.getFilterOptions,
    // Filter vocabulary changes only after a sync -- never refetch
    // during a session (teardown R16 / #114).
    staleTime: Infinity,
    gcTime: 24 * 60 * 60 * 1000,
  });
}

/** Facet counts scoped to the active query — powers the filter
 * sidebar so every option shows how many rules a click yields.
 * Pagination/sort changes don't affect counts, so they're stripped
 * from the query key to avoid refetching on page flips. */
export function useFacets(filters: SearchFilters = {}) {
  const { offset, limit, sort_by, sort_order, ...facetFilters } = filters;
  return useQuery({
    queryKey: ['facets', facetFilters],
    queryFn: () => detectionsApi.getFacets(facetFilters),
    placeholderData: (prev) => prev,
    // Facet counts only move on the nightly sync (teardown R16 / #114).
    staleTime: 15 * 60 * 1000,
  });
}

export function useExport() {
  return useMutation({
    mutationFn: async (request: ExportRequest) => {
      const blob = await exportApi.export(request);

      // Create download link
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = request.format === 'navigator' ? 'detection-explorer-layer.json' : request.format === 'observables' ? 'detection_observables.csv' : `detections_export.${request.format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    },
  });
}
