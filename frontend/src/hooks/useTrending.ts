import { useQuery } from '@tanstack/react-query';
import { trendingApi, digestApi, ActivityFilters } from '../services/api';

export function useTrendingTechniques(
  days: number = 90,
  limit: number = 15,
  filters: ActivityFilters = {},
) {
  return useQuery({
    queryKey: ['trending-techniques', days, limit, filters],
    queryFn: () => trendingApi.getTechniques(days, limit, filters),
    staleTime: 1000 * 60 * 5, // Cache for 5 minutes
  });
}

export function useTrendingPlatforms(
  days: number = 90,
  limit: number = 15,
  filters: Omit<ActivityFilters, 'platforms'> = {},
) {
  return useQuery({
    queryKey: ['trending-platforms', days, limit, filters],
    queryFn: () => trendingApi.getPlatforms(days, limit, filters),
    staleTime: 1000 * 60 * 5,
  });
}

export function useNewlyCovered(
  days: number = 30,
  limit: number = 12,
  sources: string[] = [],
) {
  return useQuery({
    queryKey: ['newly-covered', days, limit, sources],
    queryFn: () => trendingApi.getNewlyCovered(days, limit, sources),
    staleTime: 1000 * 60 * 5,
  });
}

export function useTrendingSummary(days: number = 90) {
  return useQuery({
    queryKey: ['trending-summary', days],
    queryFn: () => trendingApi.getSummary(days),
    staleTime: 1000 * 60 * 5,
  });
}

export function useRecentRules(
  limit: number = 20,
  filters: ActivityFilters = {},
  days?: number,
) {
  return useQuery({
    queryKey: ['recent-rules', limit, filters, days ?? null],
    queryFn: () => trendingApi.getRecentRules(limit, filters, days),
    staleTime: 1000 * 60 * 5,
  });
}

export function useTrendingUseCases(
  days: number = 90,
  limit: number = 15,
  filters: ActivityFilters = {},
) {
  return useQuery({
    queryKey: ['trending-use-cases', days, limit, filters],
    queryFn: () => trendingApi.getUseCases(days, limit, filters),
    staleTime: 1000 * 60 * 5,
  });
}

export function useWeeklyActivity(weeks: number = 12) {
  return useQuery({
    queryKey: ['weekly-activity', weeks],
    queryFn: () => trendingApi.getWeeklyActivity(weeks),
    staleTime: 1000 * 60 * 10,
  });
}

/** Emerging data sources: canonical data_sources by new-rule volume (#17). */
export function useTrendingDataSources(
  days: number = 90,
  limit: number = 15,
  filters: Omit<ActivityFilters, 'platforms'> = {},
) {
  return useQuery({
    queryKey: ['trending-data-sources', days, limit, filters],
    queryFn: () => trendingApi.getDataSources(days, limit, filters),
    staleTime: 1000 * 60 * 5,
  });
}

/** Technique momentum: top gainers / losers between coverage snapshots (#19). */
export function useTechniqueDeltas(days: number = 7, limit: number = 6) {
  return useQuery({
    queryKey: ['technique-deltas', days, limit],
    queryFn: () => trendingApi.getTechniqueDeltas(days, limit),
    staleTime: 1000 * 60 * 10,
  });
}

/** Net per-source rule-count change over `days` (#19). */
export function useSourceDeltas(days: number = 7) {
  return useQuery({
    queryKey: ['source-deltas', days],
    queryFn: () => trendingApi.getSourceDeltas(days),
    staleTime: 1000 * 60 * 10,
  });
}



/** Weekly digest document (JSON twin of the RSS feeds). */
export function useDigest(days: number = 7, limit: number = 15, week?: string) {
  return useQuery({
    queryKey: week ? ['digest-week', week, limit] : ['digest', days, limit],
    queryFn: () => (week ? digestApi.getWeek(week, limit) : digestApi.get(days, limit)),
    staleTime: week ? 1000 * 60 * 60 : 1000 * 60 * 10,
  });
}
