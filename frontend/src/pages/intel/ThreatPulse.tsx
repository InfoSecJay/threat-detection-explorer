/**
 * Threat Pulse — named campaigns/malware (from vendor story tags) and
 * newly-mentioned CVEs across the full corpus or a time window.
 */

import { Link } from 'react-router-dom';
import { useThreatPulse } from '../../hooks/useTrending';
import { sourceTheme as sourceConfig, clipSm } from '../../constants/style';
import type { NamedThreat, CveMention } from '../../services/api';
import { SkeletonRow, EmptyLabel } from './Section';

function ThreatCard({ threat }: { threat: NamedThreat }) {
  const kindBadge = threat.kind === 'malware'
    ? 'bg-orange-500/10 text-orange-400 border-orange-500/30'
    : 'bg-breach-500/10 text-breach-400 border-breach-500/30';
  const kindLabel = threat.kind === 'malware' ? 'MALWARE' : 'CAMPAIGN';

  // Link to one example rule's detail page so users can drill in.
  // We don't yet have a cross-vendor "all rules for threat X" filter.
  const example = threat.examples[0];

  return (
    <Link
      to={example ? `/detections/${example.id}` : '/detections'}
      className="group block bg-void-850 border border-void-700 hover:border-breach-500/40 p-3 transition-colors"
      style={clipSm}
    >
      <div className="flex items-start justify-between gap-2 mb-1.5">
        <span className={`text-[9px] font-mono uppercase tracking-wider px-1.5 py-0.5 border ${kindBadge}`}>
          {kindLabel}
        </span>
        <span className="text-base font-display font-bold text-white tabular-nums">
          {threat.count}
        </span>
      </div>
      <div className="text-sm text-gray-200 font-mono leading-tight line-clamp-2 mb-2 min-h-[2.5rem] group-hover:text-white">
        {threat.name}
      </div>
      <div className="flex items-center gap-1">
        {threat.sources.map((src) => {
          const cfg = sourceConfig[src];
          return (
            <span
              key={src}
              className={`w-1.5 h-1.5 rounded-full ${cfg?.dot || 'bg-gray-500'}`}
              title={cfg?.name || src}
            />
          );
        })}
        <span className="text-[10px] font-mono text-gray-500 ml-1">
          {threat.sources.length} {threat.sources.length === 1 ? 'source' : 'sources'}
        </span>
      </div>
    </Link>
  );
}

function CveCard({ cve }: { cve: CveMention }) {
  const year = parseInt(cve.cve.slice(4, 8));
  const isRecent = year >= new Date().getFullYear() - 1;

  return (
    <a
      href={`https://nvd.nist.gov/vuln/detail/${cve.cve}`}
      target="_blank"
      rel="noopener noreferrer"
      className={`group block bg-void-850 border p-3 transition-colors ${
        isRecent ? 'border-breach-500/30 hover:border-breach-500/60' : 'border-void-700 hover:border-gray-500'
      }`}
      style={clipSm}
    >
      <div className="flex items-start justify-between gap-2 mb-1.5">
        <span className={`text-[9px] font-mono uppercase tracking-wider px-1.5 py-0.5 border ${
          isRecent
            ? 'text-breach-400 border-breach-500/40 bg-breach-500/10'
            : 'text-gray-500 border-gray-600/40 bg-void-800'
        }`}>
          CVE
        </span>
        <span className="text-base font-display font-bold text-white tabular-nums">{cve.count}</span>
      </div>
      <div className="text-sm text-gray-200 font-mono font-bold leading-tight mb-2 group-hover:text-matrix-400">
        {cve.cve}
      </div>
      <div className="flex items-center gap-1">
        {cve.sources.map((src) => {
          const cfg = sourceConfig[src];
          return (
            <span
              key={src}
              className={`w-1.5 h-1.5 rounded-full ${cfg?.dot || 'bg-gray-500'}`}
              title={cfg?.name || src}
            />
          );
        })}
        <span className="text-[10px] font-mono text-gray-500 ml-1">nvd ↗</span>
      </div>
    </a>
  );
}

export function ThreatPulseSection({ days }: { days?: number }) {
  const { data, isLoading, error } = useThreatPulse(12, days);

  if (isLoading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-2">
        {[...Array(6)].map((_, i) => <SkeletonRow key={i} height="h-24" />)}
      </div>
    );
  }
  if (error || !data) return <EmptyLabel label="NO_THREAT_DATA" />;

  const threats = data.named_threats.slice(0, 12);
  const cves = data.cves.slice(0, 6);
  const scopeLabel = data.scope === 'window'
    ? `last ${data.period_days}d`
    : 'full catalog';

  return (
    <div className="space-y-3">
      {threats.length > 0 && (
        <div>
          <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider mb-2">
            named threats · {threats.length} specific campaigns &amp; malware families · {scopeLabel}
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-2">
            {threats.map((t) => <ThreatCard key={t.name} threat={t} />)}
          </div>
        </div>
      )}

      {cves.length > 0 && (
        <div>
          <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider mb-2">
            cve watch · vulnerabilities most covered by vendor rules
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2">
            {cves.map((c) => <CveCard key={c.cve} cve={c} />)}
          </div>
        </div>
      )}
    </div>
  );
}
