import { useQuery } from '@tanstack/react-query';
import { compareApi } from '../services/api';

export function useCoverageMatrix(params?: {
  tactic?: string;
  include_subtechniques?: boolean;
  domain?: string;
}) {
  return useQuery({
    queryKey: ['coverageMatrix', params],
    queryFn: () => compareApi.coverageMatrix(params),
    staleTime: 1000 * 60 * 5, // Cache for 5 minutes
  });
}

/** Observable-level diff of 2-6 rules (#11); off until two ids are given. */
export function useCompareDiff(ids: string[]) {
  return useQuery({
    queryKey: ['compareDiff', ids],
    queryFn: () => compareApi.diff(ids),
    enabled: ids.length >= 2,
    staleTime: 1000 * 60 * 10,
  });
}
