import { useQuery } from '@tanstack/react-query';
import { queryApi } from '../services/api';

export function useQueryFields() {
  return useQuery({
    queryKey: ['query-fields'],
    queryFn: queryApi.getFields,
    // Field registry changes only on deploy — cache aggressively.
    staleTime: 1000 * 60 * 60,
  });
}
