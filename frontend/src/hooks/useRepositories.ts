import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
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

export function useSyncRepository() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: repositoriesApi.sync,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['repositories'] });
    },
  });
}

export function useSyncAllRepositories() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: repositoriesApi.syncAll,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['repositories'] });
    },
  });
}

export function useIngestRepository() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: repositoriesApi.ingest,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['repositories'] });
      queryClient.invalidateQueries({ queryKey: ['detections'] });
      queryClient.invalidateQueries({ queryKey: ['statistics'] });
    },
  });
}

export function useIngestAllRepositories() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: repositoriesApi.ingestAll,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['repositories'] });
      queryClient.invalidateQueries({ queryKey: ['detections'] });
      queryClient.invalidateQueries({ queryKey: ['statistics'] });
    },
  });
}
