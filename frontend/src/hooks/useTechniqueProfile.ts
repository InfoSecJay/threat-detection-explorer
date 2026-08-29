import { useQuery } from '@tanstack/react-query';
import { techniqueProfileApi } from '../services/api';

export function useTechniqueProfile(techniqueId: string | undefined) {
  return useQuery({
    queryKey: ['technique-profile', techniqueId],
    queryFn: () => techniqueProfileApi.get(techniqueId!),
    enabled: !!techniqueId,
    staleTime: 1000 * 60 * 10,
    retry: false,
  });
}
