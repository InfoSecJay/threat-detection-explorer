import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { queryApi } from '../services/api';

/**
 * Windows event-ID dictionary from /query/event-ids (issue #16). Static
 * per deploy, so it is cached for the session. `labels` is the flat
 * {id: label} map most call sites want ("4688" -> "Process created");
 * it is an empty object until the fetch resolves, so callers can
 * render raw IDs immediately and upgrade to labels when available.
 */
export function useEventIds() {
  const query = useQuery({
    queryKey: ['event-ids'],
    queryFn: queryApi.getEventIds,
    staleTime: Infinity,
  });
  const labels = useMemo(() => {
    const out: Record<string, string> = {};
    const entries = query.data?.event_ids || {};
    for (const [id, entry] of Object.entries(entries)) out[id] = entry.label;
    return out;
  }, [query.data]);
  return { ...query, labels, entries: query.data?.event_ids || {} };
}
