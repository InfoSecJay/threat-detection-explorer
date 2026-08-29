import { useQuery } from '@tanstack/react-query';
import { repositoriesApi } from '../services/api';

export function useRepositories() {
  return useQuery({
    queryKey: ['repositories'],
    queryFn: repositoriesApi.list,
    // Read-only surfaces (Intel health strip, Integrations) share this
    // key; the shortest interval wins in React Query, and nothing on
    // the site mutates sync state any more, so 30s is plenty.
    refetchInterval: 30000,
  });
}

export function useRepository(name: string) {
  return useQuery({
    queryKey: ['repository', name],
    queryFn: () => repositoriesApi.get(name),
    enabled: !!name,
  });
}

