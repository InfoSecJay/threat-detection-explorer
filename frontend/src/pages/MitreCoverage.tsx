import { CoverageMatrix } from '../components/CoverageMatrix';

export function MitreCoverage() {
  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">
          MITRE ATT&CK Coverage
        </h1>
        <p className="text-sm text-gray-500 mt-1 font-mono">
          TECHNIQUE_COVERAGE // CROSS_VENDOR_ANALYSIS // GAP_IDENTIFICATION
        </p>
      </div>

      {/* Coverage Matrix */}
      <div
        className="bg-void-850 border border-void-700 p-6"
        style={{
          clipPath: 'polygon(0 0, calc(100% - 16px) 0, 100% 16px, 100% 100%, 16px 100%, 0 calc(100% - 16px))',
        }}
      >
        <CoverageMatrix />
      </div>
    </div>
  );
}
