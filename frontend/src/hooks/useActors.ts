import { useQuery } from '@tanstack/react-query';
import { actorsApi, type ActorMatchMode } from '../services/api';

export function useActors() {
  return useQuery({
    queryKey: ['actors'],
    queryFn: actorsApi.list,
    // Full MITRE catalog moves rarely; corpus overlay refreshes with
    // ingestion. 10 min cache is generous but keeps navigation snappy.
    staleTime: 1000 * 60 * 10,
  });
}

export function useActor(
  actorId: string | undefined,
  matchMode: ActorMatchMode = 'exact',
) {
  return useQuery({
    queryKey: ['actor', actorId, matchMode],
    queryFn: () => actorsApi.get(actorId as string, matchMode),
    enabled: !!actorId,
    staleTime: 1000 * 60 * 5,
  });
}
