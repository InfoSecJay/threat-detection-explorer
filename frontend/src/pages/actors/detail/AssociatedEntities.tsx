/** Cross-references: software a group uses, or groups that use a
 * piece of software -- whichever applies to this entity. */

import { Link } from 'react-router-dom';
import { clipSm } from '../../../constants/style';
import { SectionHead } from './SectionHead';
import type { ActorDetail as ActorDetailData } from '../../../services/api';

export function AssociatedEntities({ actor }: { actor: ActorDetailData }) {
  const isGroup = actor.kind === 'group';
  return (
    <>
  {isGroup && actor.associated_software && actor.associated_software.length > 0 && (
    <section>
      <div className="flex items-center justify-between flex-wrap gap-2">
        <SectionHead title="Associated software" subtitle="malware + tools this actor is known to use" />
        <Link
          to={`/actors?tab=software&used_by_actor=${actor.id}`}
          className="text-[10px] font-mono text-matrix-500 hover:text-matrix-400 uppercase tracking-wider border border-matrix-500/30 hover:border-matrix-500/60 px-2 py-1 transition-colors mb-3"
        >
          [ filter software tab ]
        </Link>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-2">
        {actor.associated_software.map((s) => (
          <Link
            key={s.id}
            to={`/actors/${s.id}`}
            className={`block border px-3 py-2 transition-colors ${
              s.has_rules
                ? 'bg-void-850 border-void-700 hover:border-cyan-500/50'
                : 'bg-void-900/60 border-void-800 hover:border-void-600'
            }`}
            style={clipSm}
          >
            <div className="flex items-center gap-1.5 mb-1">
              <span className={`text-[9px] font-mono uppercase tracking-wider ${s.type === 'malware' ? 'text-orange-400' : 'text-cyan-400'}`}>
                {s.type}
              </span>
              <span className="text-[10px] font-mono text-gray-600 ml-auto tabular-nums">{s.id}</span>
            </div>
            <div className={`text-xs font-mono truncate ${s.has_rules ? 'text-white' : 'text-gray-500'}`}>{s.name}</div>
            <div className={`text-[10px] font-mono mt-1 ${s.has_rules ? 'text-gray-400' : 'text-gray-700'}`}>
              {s.has_rules ? `${s.rule_count} rules` : 'no rules'}
            </div>
          </Link>
        ))}
      </div>
    </section>
  )}

  {!isGroup && actor.associated_groups && actor.associated_groups.length > 0 && (
    <section>
      <SectionHead title="Used by" subtitle="threat groups known to use this software" />
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-2">
        {actor.associated_groups.map((g) => (
          <Link
            key={g.id}
            to={`/actors/${g.id}`}
            className={`block border px-3 py-2 transition-colors ${
              g.has_rules
                ? 'bg-void-850 border-void-700 hover:border-breach-500/50'
                : 'bg-void-900/60 border-void-800 hover:border-void-600'
            }`}
            style={clipSm}
            title={g.aliases.length ? `aka ${g.aliases.join(', ')}` : g.name}
          >
            <div className="flex items-center gap-1.5 mb-1">
              <span className="text-[9px] font-mono uppercase tracking-wider text-breach-400">ACTOR</span>
              <span className="text-[10px] font-mono text-gray-600 ml-auto tabular-nums">{g.id}</span>
            </div>
            <div className={`text-xs font-mono truncate ${g.has_rules ? 'text-white' : 'text-gray-500'}`}>{g.name}</div>
            <div className={`text-[10px] font-mono mt-1 ${g.has_rules ? 'text-gray-400' : 'text-gray-700'}`}>
              {g.has_rules ? `${g.rule_count} rules` : 'no rules'}
            </div>
          </Link>
        ))}
      </div>
    </section>
  )}
    </>
  );
}
