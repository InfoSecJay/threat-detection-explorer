/**
 * CoverageConstellation -- the hero's right-hand ornament: ATT&CK
 * Enterprise drawn as a field of cells, one per base technique, tactic
 * columns in kill-chain order left to right. Covered techniques glow
 * matrix (brighter = more rules), gaps stay dark, and a scan band
 * sweeps the kill chain. Decorative but true: it reads the same
 * coverage-matrix query the stats strip already caches, so it costs
 * no extra request.
 *
 * Deliberately non-interactive -- one link to /mitre, no per-cell
 * tooltips. Home is a table of contents, not a dashboard.
 */

import { Link } from 'react-router-dom';
import { useCoverageMatrix } from '../../hooks/useCompare';

const X_PITCH = 15; // column spacing in viewBox units
const Y_PITCH = 9;
const CELL_W = 8;
const CELL_H = 5;

/** Three brightness tiers so density reads at a glance without a legend. */
function cellStyle(ruleCount: number): { fill: string; opacity: number } {
  if (ruleCount === 0) return { fill: '#30363d', opacity: 0.5 };
  if (ruleCount < 5) return { fill: '#00ffcc', opacity: 0.3 };
  if (ruleCount < 20) return { fill: '#00ffcc', opacity: 0.55 };
  return { fill: '#00ffcc', opacity: 0.9 };
}

export function CoverageConstellation() {
  const { data } = useCoverageMatrix({ include_subtechniques: false });
  if (!data || data.tactics.length === 0) return null;

  const width = data.tactics.length * X_PITCH - (X_PITCH - CELL_W);
  const maxRows = Math.max(...data.tactics.map((t) => t.techniques.length));
  if (maxRows === 0) return null;
  const height = maxRows * Y_PITCH - (Y_PITCH - CELL_H);
  const { techniques_with_any_coverage: covered, total_techniques: total } = data.summary;

  return (
    <Link
      to="/mitre"
      data-testid="hero-constellation"
      aria-label={`ATT&CK Enterprise coverage: ${covered} of ${total} techniques covered. Open the coverage browser.`}
      className="group block w-[230px]"
    >
      <svg viewBox={`0 0 ${width} ${height}`} className="w-full" aria-hidden="true">
        <defs>
          <linearGradient id="constellation-scan" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="#00ffcc" stopOpacity="0" />
            <stop offset="60%" stopColor="#00ffcc" stopOpacity="0.18" />
            <stop offset="100%" stopColor="#00ffcc" stopOpacity="0" />
          </linearGradient>
        </defs>
        {data.tactics.map((tactic, col) =>
          tactic.techniques.map((tech, row) => {
            const { fill, opacity } = cellStyle(tech.total_detections);
            return (
              <rect
                key={tech.id}
                data-cell={tech.total_detections > 0 ? 'covered' : 'gap'}
                x={col * X_PITCH}
                y={row * Y_PITCH}
                width={CELL_W}
                height={CELL_H}
                rx={1}
                fill={fill}
                opacity={opacity}
              />
            );
          }),
        )}
        <rect
          className="constellation-sweep"
          x={-40}
          y={0}
          width={40}
          height={height}
          fill="url(#constellation-scan)"
        />
      </svg>
      <div className="mt-3 flex items-center gap-2 text-[9px] font-mono uppercase tracking-[0.2em] text-gray-600">
        <span>Recon</span>
        <span className="flex-1 h-px bg-gradient-to-r from-void-700 via-matrix-500/30 to-void-700" />
        <span>Impact</span>
      </div>
      <div className="mt-2 text-[10px] font-mono uppercase tracking-wider text-gray-500 group-hover:text-matrix-400 transition-colors">
        ATT&amp;CK Enterprise coverage
        <span className="block text-gray-700">// dim cells = gaps</span>
      </div>
    </Link>
  );
}
