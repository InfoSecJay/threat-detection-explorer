import { useQuery } from '@tanstack/react-query';
import { releasesApi } from '../services/api';

export function useReleaseSources() {
  return useQuery({
    queryKey: ['release-sources'],
    queryFn: releasesApi.listSources,
    staleTime: 1000 * 60 * 60, // Cache for 1 hour
  });
}

export function useReleases(source: string, perPage: number = 5) {
  return useQuery({
    queryKey: ['releases', source, perPage],
    queryFn: () => releasesApi.getReleases(source, perPage),
    enabled: !!source,
    staleTime: 1000 * 60 * 5, // Cache for 5 minutes
  });
}
