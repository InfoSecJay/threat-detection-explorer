import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { queryApi, type EventIdEntry } from '../services/api';

/**
 * Windows event-ID dictionary from /query/event-ids (issue #16). Static
 * per deploy, so it is cached for the session.
 *
 * The API keys entries by channel-namespaced id ("security:4688",
 * #110). `entries` and `labels` are indexed by BOTH that key and the
 * bare number, so call sites holding either form -- namespaced values
 * from the current corpus, bare ones from old links or pre-namespacing
 * rows -- resolve without caring. A bare number resolves to the
 * dictionary's one entry for it (ids are unique across providers).
 * `labels` is an empty object until the fetch resolves, so callers can
 * render raw IDs immediately and upgrade to labels when available.
 */
export function useEventIds() {
  const query = useQuery({
    queryKey: ['event-ids'],
    queryFn: queryApi.getEventIds,
    staleTime: Infinity,
  });
  const { entries, labels } = useMemo(() => {
    const entries: Record<string, EventIdEntry> = {};
    const labels: Record<string, string> = {};
    for (const [key, entry] of Object.entries(query.data?.event_ids || {})) {
      entries[key] = entry;
      labels[key] = entry.label;
      if (entry.event_id && !(entry.event_id in entries)) {
        entries[entry.event_id] = entry;
        labels[entry.event_id] = entry.label;
      }
    }
    return { entries, labels };
  }, [query.data]);
  return { ...query, labels, entries };
}
