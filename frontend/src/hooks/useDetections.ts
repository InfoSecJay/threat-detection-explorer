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
  });
}

export function useFilterOptions() {
  return useQuery({
    queryKey: ['filterOptions'],
    queryFn: detectionsApi.getFilterOptions,
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
      a.download = `detections_export.${request.format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    },
  });
}
