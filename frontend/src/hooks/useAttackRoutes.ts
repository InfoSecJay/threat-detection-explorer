/**
 * Resolve attack.mitre.org entity URLs to our internal routes — but
 * only when the object actually exists in our catalog, so we never
 * link users onto a 404. Anything unrecognized stays an external link
 * to its real URL.
 *
 * Existence checks are cheap: the full group/software catalog is the
 * (react-query-cached) /actors payload the list page already loads,
 * and techniques come from the app-wide MitreContext. While either is
 * still loading the resolver returns null and links degrade to
 * external anchors.
 */

import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { actorsApi } from '../services/api';
import { useMitre } from '../contexts/MitreContext';

const ATTACK_ENTITY_RE =
  /^https?:\/\/attack\.mitre\.org\/(?:wiki\/)?(groups|software|techniques)\/([GST]\d{4})(?:\/(\d{3}))?\/?$/i;

export function useAttackRouteResolver(): (url: string) => string | null {
  const { data: actors } = useQuery({ queryKey: ['actors-catalog'], queryFn: actorsApi.catalog, staleTime: 1000 * 60 * 30 });
  const { techniques } = useMitre();

  return useMemo(() => {
    const catalogIds = new Set<string>();
    if (actors) {
      for (const g of actors.groups) catalogIds.add(g.id);
      for (const s of actors.software) catalogIds.add(s.id);
    }
    return (url: string): string | null => {
      const m = url.match(ATTACK_ENTITY_RE);
      if (!m) return null;
      const kind = m[1].toLowerCase();
      const id = m[2].toUpperCase();
      const sub = m[3];
      if (kind === 'techniques') {
        const tid = sub ? `${id}.${sub}` : id;
        return techniques[tid] ? `/mitre/${tid}` : null;
      }
      return catalogIds.has(id) ? `/actors/${id}` : null;
    };
  }, [actors, techniques]);
}
