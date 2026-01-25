import { useQuery } from '@tanstack/react-query';
import { trendingApi } from '../services/api';

export function useTrendingTechniques(days: number = 90, limit: number = 15) {
  return useQuery({
    queryKey: ['trending-techniques', days, limit],
    queryFn: () => trendingApi.getTechniques(days, limit),
    staleTime: 1000 * 60 * 5, // Cache for 5 minutes
  });
}

export function useTrendingPlatforms(days: number = 90, limit: number = 15) {
  return useQuery({
    queryKey: ['trending-platforms', days, limit],
    queryFn: () => trendingApi.getPlatforms(days, limit),
    staleTime: 1000 * 60 * 5, // Cache for 5 minutes
  });
}

export function useTrendingSummary(days: number = 90) {
  return useQuery({
    queryKey: ['trending-summary', days],
    queryFn: () => trendingApi.getSummary(days),
    staleTime: 1000 * 60 * 5, // Cache for 5 minutes
  });
}
