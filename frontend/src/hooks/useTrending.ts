import { useQuery } from '@tanstack/react-query';
import { trendingApi, ActivityFilters } from '../services/api';

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

export function useTrendingSummary(days: number = 90) {
  return useQuery({
    queryKey: ['trending-summary', days],
    queryFn: () => trendingApi.getSummary(days),
    staleTime: 1000 * 60 * 5,
  });
}

export function useRecentRules(limit: number = 20, filters: ActivityFilters = {}) {
  return useQuery({
    queryKey: ['recent-rules', limit, filters],
    queryFn: () => trendingApi.getRecentRules(limit, filters),
    staleTime: 1000 * 60 * 5,
  });
}
