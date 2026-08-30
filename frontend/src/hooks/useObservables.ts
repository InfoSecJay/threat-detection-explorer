import { useQuery } from '@tanstack/react-query';
import { observablesApi } from '../services/api';

export function useObservableTypes() {
  return useQuery({ queryKey: ['observable-types'], queryFn: observablesApi.types, staleTime: 1000 * 60 * 30 });
}

export function useObservableTop(kind: string, limit = 100, source?: string, q?: string) {
  return useQuery({
    queryKey: ['observable-top', kind, limit, source ?? null, q ?? ''],
    queryFn: () => observablesApi.top(kind, limit, source, q),
    staleTime: 1000 * 60 * 30,
    enabled: !!kind,
    placeholderData: (prev) => prev,
  });
}

export function useObservableProfile(kind: string | undefined, value: string | undefined) {
  return useQuery({
    queryKey: ['observable-profile', kind, value],
    queryFn: () => observablesApi.profile(kind!, value!),
    staleTime: 1000 * 60 * 10,
    enabled: !!kind && !!value,
    retry: false,
  });
}
