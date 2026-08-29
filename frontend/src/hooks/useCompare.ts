import { useQuery } from '@tanstack/react-query';
import { compareApi } from '../services/api';

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
