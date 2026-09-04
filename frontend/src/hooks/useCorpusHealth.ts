/**
 * Corpus-health report (#124): shared by the report page and the home
 * stats strip, so both read one edge-cached response and tests can mock
 * the hook like every other data hook.
 */
import { useQuery } from '@tanstack/react-query';
import { methodologyApi } from '../services/api';

export function useCorpusHealth() {
  return useQuery({
    queryKey: ['methodology', 'corpus-health'],
    queryFn: methodologyApi.corpusHealth,
    staleTime: 15 * 60 * 1000,
  });
}
