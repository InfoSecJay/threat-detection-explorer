import { useQuery } from '@tanstack/react-query';
import { queryApi } from '../services/api';

export function useQueryFields() {
  return useQuery({
    queryKey: ['query-fields'],
    queryFn: queryApi.getFields,
    // Field registry changes only on deploy -- never refetch during a
    // session (teardown R16 / #114).
    staleTime: Infinity,
    gcTime: 24 * 60 * 60 * 1000,
  });
}
