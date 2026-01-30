import { Link } from 'react-router-dom';

interface ChangeLogEntry {
  version: string;
  date: string;
  changes: {
    type: 'added' | 'improved' | 'fixed' | 'removed';
    description: string;
  }[];
}

const changeLog: ChangeLogEntry[] = [
  {
    version: '1.4.0',
    date: '2026-01-30',
    changes: [
      { type: 'added', description: 'Microsoft Sentinel Analytics Rules integration - KQL detection rules from Azure Sentinel' },
      { type: 'added', description: 'Sentinel connector-based platform detection (AWS, Azure, GCP, Windows, Linux)' },
      { type: 'improved', description: 'Detection Intel Feed now supports 8 security repositories' },
    ],
  },
  {
    version: '1.3.0',
    date: '2026-01-30',
    changes: [
      { type: 'added', description: 'Elastic Hunting Queries integration - 138 ES|QL threat hunting queries' },
      { type: 'added', description: 'MITRE ATT&CK technique validation with deprecated technique mapping' },
      { type: 'added', description: 'Sub-technique rollup in MITRE Coverage Matrix' },
      { type: 'added', description: 'Rule Created date column in Detections table' },
      { type: 'improved', description: 'Coverage Matrix now shows parent technique counts including sub-techniques' },
      { type: 'fixed', description: 'Invalid MITRE techniques (e.g., T1208) now mapped to current equivalents' },
    ],
  },
  {
    version: '1.2.0',
    date: '2026-01-25',
    changes: [
      { type: 'added', description: 'Resources dropdown menu with About, Change Log, and Integrations pages' },
      { type: 'added', description: 'Integrations status page showing source feed sync status' },
      { type: 'added', description: 'Change Log page to track website updates' },
      { type: 'improved', description: 'Moved About and Legal sections to dedicated About page' },
      { type: 'improved', description: 'Navigation restructured with dropdown menus' },
    ],
  },
  {
    version: '1.1.0',
    date: '2026-01-25',
    changes: [
      { type: 'added', description: 'Cyberpunk/matrix-style UI redesign with custom color palette' },
      { type: 'added', description: 'Custom graphics components (CircuitBoard, HexShield, ThreatRadar)' },
      { type: 'added', description: 'Side-by-side rule comparison with split panel view' },
      { type: 'added', description: 'Comparison charts with vendor distribution, severity, and platform analytics' },
      { type: 'added', description: 'MITRE technique name lookups in coverage gap analysis' },
      { type: 'added', description: 'Log source taxonomy standardization (platform, event_category, data_source)' },
      { type: 'improved', description: 'Filter panel with new platform and event category filters' },
      { type: 'improved', description: 'Detection cards with enhanced metadata display' },
    ],
  },
  {
    version: '1.0.0',
    date: '2026-01-24',
    changes: [
      { type: 'added', description: 'Initial release of Threat Detection Explorer' },
      { type: 'added', description: 'Detection rule aggregation from multiple security repositories' },
      { type: 'added', description: 'Full-text search and MITRE ATT&CK filtering' },
      { type: 'added', description: 'Cross-vendor comparison functionality' },
      { type: 'added', description: 'Coverage gap analysis between sources' },
      { type: 'added', description: 'Direct links to original source files' },
      { type: 'added', description: 'MITRE ATT&CK technique and tactic mapping' },
    ],
  },
];

const typeConfig = {
  added: { label: 'ADDED', color: 'text-pulse-400', bg: 'bg-pulse-500/10', border: 'border-pulse-500/30' },
  improved: { label: 'IMPROVED', color: 'text-matrix-400', bg: 'bg-matrix-500/10', border: 'border-matrix-500/30' },
  fixed: { label: 'FIXED', color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/30' },
  removed: { label: 'REMOVED', color: 'text-threat-400', bg: 'bg-threat-500/10', border: 'border-threat-500/30' },
};

export function ChangeLog() {
  return (
    <div className="space-y-8 max-w-4xl mx-auto">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">
          Change Log
        </h1>
        <p className="text-sm text-gray-500 mt-1 font-mono">
          VERSION_HISTORY // SYSTEM_UPDATES
        </p>
      </div>

      {/* Timeline */}
      <div className="relative">
        {/* Vertical line */}
        <div className="absolute left-4 top-0 bottom-0 w-px bg-void-700" />

        {/* Entries */}
        <div className="space-y-8">
          {changeLog.map((entry, index) => (
            <div key={entry.version} className="relative pl-12">
              {/* Timeline dot */}
              <div className={`absolute left-2.5 top-1 w-3 h-3 rounded-full ${index === 0 ? 'bg-matrix-500' : 'bg-void-600'} ring-4 ring-void-950`} />

              {/* Version card */}
              <div
                className="bg-void-850 border border-void-700 p-6"
                style={{
                  clipPath: 'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))',
                }}
              >
                {/* Header */}
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <span className="text-lg font-display font-bold text-matrix-500">
                      v{entry.version}
                    </span>
                    {index === 0 && (
                      <span className="px-2 py-0.5 bg-matrix-500/20 text-matrix-400 text-xs font-mono uppercase">
                        Latest
                      </span>
                    )}
                  </div>
                  <span className="text-sm font-mono text-gray-500">
                    {entry.date}
                  </span>
                </div>

                {/* Changes list */}
                <div className="space-y-2">
                  {entry.changes.map((change, changeIndex) => {
                    const config = typeConfig[change.type];
                    return (
                      <div
                        key={changeIndex}
                        className="flex items-start gap-3"
                      >
                        <span className={`px-2 py-0.5 text-xs font-mono uppercase ${config.color} ${config.bg} border ${config.border} flex-shrink-0`}>
                          {config.label}
                        </span>
                        <span className="text-sm text-gray-400">
                          {change.description}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Back link */}
      <div className="pt-4">
        <Link
          to="/"
          className="text-sm font-mono text-gray-500 hover:text-matrix-500 transition-colors"
        >
          &larr; BACK_TO_HOME
        </Link>
      </div>
    </div>
  );
}
