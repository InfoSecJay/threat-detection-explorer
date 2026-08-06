/**
 * Threat Spotlight — top ATT&CK Groups + Software active in-window.
 *
 * Backed by /trending/threat-actors which returns display-name-resolved
 * entries from `mitre_groups` + `mitre_software` normalized during
 * ingestion (Sigma + LOLRMM tags today). Clicking a chip deep-links
 * to the catalog filtered by the raw ATT&CK ID.
 *
 * This is the "who are we chasing right now?" signal — placed above the
 * Upstream Releases block so DEs see it before the vendor-specific
 * feed. Unknown IDs show their raw form (G1234) as the label, which is
 * still useful and never hallucinates a name.
 */

import { Link } from 'react-router-dom';
import { useThreatActors } from '../../hooks/useTrending';
import { sourceTheme as sourceConfig, clipSm } from '../../constants/style';
import type { ThreatActorGroup, ThreatActorSoftware } from '../../services/api';
import { SkeletonRow, EmptyLabel } from './Section';

function SourceDots({ sources }: { sources: string[] }) {
  return (
    <div className="flex gap-0.5 items-center">
      {sources.slice(0, 4).map((src) => {
        const cfg = sourceConfig[src];
        return (
          <span
            key={src}
            className={`w-1.5 h-1.5 rounded-full ${cfg?.dot || 'bg-gray-500'}`}
            title={cfg?.name || src}
          />
        );
      })}
    </div>
  );
}

function GroupChip({ g }: { g: ThreatActorGroup }) {
  const isKnown = g.name !== g.id;
  return (
    <Link
      to={`/detections?mitre_groups=${g.id}`}
      className="group block bg-void-850 border border-void-700 hover:border-breach-500/50 p-2.5 transition-colors"
      style={clipSm}
      title={g.aliases.length ? `${g.name} · aka ${g.aliases.join(', ')}` : g.name}
    >
      <div className="flex items-start justify-between gap-2 mb-1.5">
        <span className="text-[9px] font-mono uppercase tracking-wider px-1.5 py-0.5 border bg-breach-500/10 text-breach-400 border-breach-500/30">
          ACTOR
        </span>
        <span className="text-base font-display font-bold text-white tabular-nums leading-none">
          {g.count}
        </span>
      </div>
      <div className={`text-sm font-mono leading-tight line-clamp-2 mb-2 min-h-[2.5rem] ${isKnown ? 'text-gray-200 group-hover:text-white' : 'text-gray-500 italic'}`}>
        {g.name}
      </div>
      <div className="flex items-center justify-between gap-2">
        <span className="text-[9px] font-mono text-gray-600">{g.id}</span>
        <SourceDots sources={g.sources} />
      </div>
    </Link>
  );
}

function SoftwareChip({ s }: { s: ThreatActorSoftware }) {
  const isKnown = s.name !== s.id;
  const kindLabel = s.type === 'tool' ? 'TOOL' : s.type === 'malware' ? 'MALWARE' : 'SOFTWARE';
  const kindBadge =
    s.type === 'malware'
      ? 'bg-orange-500/10 text-orange-400 border-orange-500/30'
      : 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30';

  return (
    <Link
      to={`/detections?mitre_software=${s.id}`}
      className="group block bg-void-850 border border-void-700 hover:border-cyan-500/50 p-2.5 transition-colors"
      style={clipSm}
      title={s.name}
    >
      <div className="flex items-start justify-between gap-2 mb-1.5">
        <span className={`text-[9px] font-mono uppercase tracking-wider px-1.5 py-0.5 border ${kindBadge}`}>
          {kindLabel}
        </span>
        <span className="text-base font-display font-bold text-white tabular-nums leading-none">
          {s.count}
        </span>
      </div>
      <div className={`text-sm font-mono leading-tight line-clamp-2 mb-2 min-h-[2.5rem] ${isKnown ? 'text-gray-200 group-hover:text-white' : 'text-gray-500 italic'}`}>
        {s.name}
      </div>
      <div className="flex items-center justify-between gap-2">
        <span className="text-[9px] font-mono text-gray-600">{s.id}</span>
        <SourceDots sources={s.sources} />
      </div>
    </Link>
  );
}

export function ThreatSpotlightSection({ days }: { days?: number }) {
  const { data, isLoading, error } = useThreatActors(10, days);

  if (isLoading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-2">
        {[...Array(5)].map((_, i) => <SkeletonRow key={i} height="h-24" />)}
      </div>
    );
  }
  if (error || !data) return <EmptyLabel label="NO_THREAT_ACTOR_DATA" />;
  if (data.groups.length === 0 && data.software.length === 0) {
    return <EmptyLabel label="NO_THREAT_ACTOR_DATA · run ingest to backfill from vendor attack.g / attack.s tags" />;
  }

  const scopeLabel = data.scope === 'window' ? `last ${data.period_days}d` : 'full catalog';

  return (
    <div className="space-y-4">
      {data.groups.length > 0 && (
        <div>
          <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider mb-2">
            actors · {data.groups.length} threat groups with active rule coverage · {scopeLabel}
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-2">
            {data.groups.map((g) => <GroupChip key={g.id} g={g} />)}
          </div>
        </div>
      )}
      {data.software.length > 0 && (
        <div>
          <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider mb-2">
            software · malware families + offensive tools · {scopeLabel}
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-2">
            {data.software.map((s) => <SoftwareChip key={s.id} s={s} />)}
          </div>
        </div>
      )}
    </div>
  );
}
