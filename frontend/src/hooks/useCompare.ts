import { useQuery } from '@tanstack/react-query';
import { compareApi } from '../services/api';

export function useCompare(params: {
  technique?: string;
  keyword?: string;
  platform?: string;
  sources?: string[];
}) {
  return useQuery({
    queryKey: ['compare', params],
    queryFn: () => compareApi.compare(params),
    enabled: !!(params.technique || params.keyword || params.platform),
  });
}

export function useCoverageGap(baseSource: string, compareSource: string) {
  return useQuery({
    queryKey: ['coverageGap', baseSource, compareSource],
    queryFn: () => compareApi.coverageGap(baseSource, compareSource),
    enabled: !!(baseSource && compareSource),
  });
}

export function useCoverageMatrix(params?: {
  tactic?: string;
  include_subtechniques?: boolean;
}) {
  return useQuery({
    queryKey: ['coverageMatrix', params],
    queryFn: () => compareApi.coverageMatrix(params),
    staleTime: 1000 * 60 * 5, // Cache for 5 minutes
  });
}
