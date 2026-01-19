import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { repositoriesApi } from '../services/api';

export function useRepositories() {
  return useQuery({
    queryKey: ['repositories'],
    queryFn: repositoriesApi.list,
    refetchInterval: 5000, // Poll every 5 seconds to update sync status
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
