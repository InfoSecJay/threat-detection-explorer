/**
 * Threat Actor / Software detail — MITRE-parity metadata + our
 * coverage. Layout mirrors what attack.mitre.org renders per group
 * or software (description, aliases, references, techniques,
 * cross-references) with our rule-coverage overlaid on top.
 *
 * The value-add over the MITRE site is the match-mode toggle. Modes
 * are DISJOINT tiers of attribution strength (issue #34): DEDICATED
 * (wire value `exact`) = rules built for the actor (ID tag, analytic
 * story named after it, or its name in the title); COVERAGE = rules
 * tagging any technique it uses; REFERENCED (wire value `mention`) =
 * rules that only cite it in prose/tags/references. All three counts
 * are always displayed, and each dedicated/referenced rule carries
 * match-reason chips saying why it counted.
 */

import { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useActor } from '../hooks/useActors';
import { MitreText, MitreReferences, resolveCitations } from '../components/MitreText';
import { useAttackRouteResolver } from '../hooks/useAttackRoutes';
import { clipMd } from '../constants/style';
import type { ActorMatchMode } from '../services/api';
import { SectionHead } from './actors/detail/SectionHead';
import { ActorHero } from './actors/detail/ActorHero';
import { CoverageBySource } from './actors/detail/CoverageBySource';
import { TechniquesGrid } from './actors/detail/TechniquesGrid';
import { AssociatedEntities } from './actors/detail/AssociatedEntities';
import { ActorRules } from './actors/detail/ActorRules';

export function ActorDetail() {
  const { id } = useParams<{ id: string }>();
  const [matchMode, setMatchMode] = useState<ActorMatchMode>('exact');
  const { data: actor, isLoading, error } = useActor(id, matchMode);
  const resolveRoute = useAttackRouteResolver();

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="h-32 bg-void-800 animate-pulse" style={clipMd} />
        <div className="h-64 bg-void-800 animate-pulse" style={clipMd} />
      </div>
    );
  }
  if (error || !actor) {
    return (
      <div className="text-center py-16">
        <div className="text-xs font-mono text-breach-400 mb-2">FAILED_TO_LOAD_ACTOR</div>
        <Link to="/actors" className="text-xs font-mono text-matrix-500 hover:text-matrix-400">
          &larr; back to Threat Actors
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Breadcrumb */}
      <div className="text-xs font-mono text-gray-500">
        <Link to="/actors" className="hover:text-matrix-500 transition-colors">
          &larr; Threat Actors
        </Link>
      </div>

      <ActorHero actor={actor} matchMode={matchMode} />
      <CoverageBySource actor={actor} />

      {/* Description + numbered references */}
      {actor.description && (
        <section>
          <SectionHead title="About" subtitle="from mitre att&ck" />
          <MitreText
            text={actor.description}
            references={actor.references}
            resolveRoute={resolveRoute}
          />
        </section>
      )}

      <TechniquesGrid actor={actor} />
      <AssociatedEntities actor={actor} />
      <ActorRules actor={actor} matchMode={matchMode} setMatchMode={setMatchMode} />

      {/* References — numbered to match the citation markers in the
          About text, uncited refs appended unnumbered */}
      {(actor.references.length > 0 ||
        resolveCitations(actor.description || '').length > 0) && (
        <section>
          <SectionHead title="References" subtitle="external sources cited by mitre" />
          <MitreReferences
            citations={resolveCitations(actor.description || '', actor.references)}
            references={actor.references}
          />
        </section>
      )}
    </div>
  );
}
