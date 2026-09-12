import { useQuery, keepPreviousData } from '@tanstack/react-query';
import { actorsApi, type ActorMatchMode, type ActorsQueryParams, type CoverageScopeParams } from '../services/api';

export function useActors() {
  return useQuery({
    queryKey: ['actors'],
    queryFn: actorsApi.list,
    // Full MITRE catalog moves rarely; corpus overlay refreshes with
    // ingestion. 10 min cache is generous but keeps navigation snappy.
    staleTime: 1000 * 60 * 10,
  });
}

export function useActorsQuery(params: ActorsQueryParams) {
  return useQuery({
    queryKey: ['actors-query', params],
    queryFn: () => actorsApi.query(params),
    staleTime: 1000 * 60 * 5,
    // Keep the previous page rendered while the next loads — avoids
    // table flicker on every filter/sort change.
    placeholderData: keepPreviousData,
  });
}

export function useActor(
  actorId: string | undefined,
  matchMode: ActorMatchMode = 'exact',
  scope?: CoverageScopeParams,
) {
  // The scope is part of the key (#143): the same actor scored
  // against a different stack is a different answer.
  const scopeKey = scope ? { sources: scope.sources ?? null, coverage: scope.coverage ?? 'strict' } : null;
  return useQuery({
    queryKey: ['actor', actorId, matchMode, scopeKey],
    queryFn: () => actorsApi.get(actorId as string, matchMode, scope),
    enabled: !!actorId,
    staleTime: 1000 * 60 * 5,
  });
}
