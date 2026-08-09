import { useQuery } from '@tanstack/react-query';
import { actorsApi } from '../services/api';

export function useActors() {
  return useQuery({
    queryKey: ['actors'],
    queryFn: actorsApi.list,
    staleTime: 1000 * 60 * 10,
  });
}

export function useActor(actorId: string | undefined) {
  return useQuery({
    queryKey: ['actor', actorId],
    queryFn: () => actorsApi.get(actorId as string),
    enabled: !!actorId,
    staleTime: 1000 * 60 * 5,
  });
}
