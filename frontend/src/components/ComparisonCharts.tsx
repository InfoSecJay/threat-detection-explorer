import { useMemo } from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import type { CompareResponse } from '../types';
import { sourceColors, sourceLabels, sourceLabelsShort, severityColors } from '../constants/sources';

interface ComparisonChartsProps {
  data: CompareResponse;
}

const platformColors: Record<string, string> = {
  windows: '#3b82f6',
  linux: '#f97316',
  macos: '#8b5cf6',
  aws: '#ff9900',
  azure: '#0078d4',
  gcp: '#4285f4',
  cloud: '#06b6d4',
  network: '#22c55e',
  email: '#ec4899',
  unknown: '#6b7280',
  '': '#6b7280',
};

// MITRE ATT&CK tactics in kill-chain order (by tactic ID)
const MITRE_TACTICS = [
  'TA0043', 'TA0042', 'TA0001', 'TA0002', 'TA0003', 'TA0004',
  'TA0005', 'TA0006', 'TA0007', 'TA0008', 'TA0009', 'TA0011',
  'TA0010', 'TA0040',
] as const;

const tacticLabels: Record<string, string> = {
  'TA0043': 'Recon',
  'TA0042': 'Res Dev',
  'TA0001': 'Init Access',
  'TA0002': 'Execution',
  'TA0003': 'Persistence',
  'TA0004': 'Priv Esc',
  'TA0005': 'Def Evasion',
  'TA0006': 'Cred Access',
  'TA0007': 'Discovery',
  'TA0008': 'Lat Move',
  'TA0009': 'Collection',
  'TA0011': 'C2',
  'TA0010': 'Exfil',
  'TA0040': 'Impact',
};

export function ComparisonCharts({ data }: ComparisonChartsProps) {
  // Prepare data for coverage chart (horizontal bar)
  const coverageData = Object.entries(data.total_by_source)
    .filter(([_, count]) => count > 0)
    .map(([source, count]) => ({
      source: sourceLabels[source] || source,
      count,
      fill: sourceColors[source] || '#6b7280',
    }))
    .sort((a, b) => b.count - a.count);

  // Prepare data for severity distribution (stacked bar per source)
  const severityData = Object.entries(data.results)
    .filter(([_, detections]) => detections.length > 0)
    .map(([source, detections]) => {
      const counts: Record<string, number> = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        unknown: 0,
      };
      detections.forEach((d) => {
        counts[d.severity] = (counts[d.severity] || 0) + 1;
      });
      return {
        source: sourceLabels[source] || source,
        ...counts,
      };
    });

  // Prepare data for platform distribution (pie chart)
  const platformCounts: Record<string, number> = {};
  Object.values(data.results)
    .flat()
    .forEach((detection) => {
      // Count every canonical platform on each rule (a multi-OS rule
      // counts towards each platform it covers).
      const platforms = detection.platforms?.length
        ? detection.platforms
        : ['unknown'];
      platforms.forEach((platform) => {
        platformCounts[platform] = (platformCounts[platform] || 0) + 1;
      });
    });

  const platformData = Object.entries(platformCounts)
    .map(([platform, count]) => ({
      name: platform || 'unknown',
      value: count,
      color: platformColors[platform] || '#6b7280',
    }))
    .filter((d) => d.value > 0)
    .sort((a, b) => b.value - a.value);

  const barChartHeight = Math.max(180, coverageData.length * 36);

  // Custom tooltip styling
  const tooltipStyle = {
    backgroundColor: '#0d1117',
    border: '1px solid #21262d',
    borderRadius: '0px',
    color: '#e5e7eb',
  };

  // ── MITRE Tactic Heatmap Data ──────────────────────────────────────
  const { heatmapGrid, maxCount } = useMemo(() => {
    // Build a map: source → tactic → count
    const tacticMap: Record<string, Record<string, number>> = {};
    const sourcesWithData: string[] = [];

    for (const [source, detections] of Object.entries(data.results)) {
      if (detections.length === 0) continue;
      sourcesWithData.push(source);
      tacticMap[source] = {};
      for (const d of detections) {
        for (const tactic of d.mitre_tactics) {
          tacticMap[source][tactic] = (tacticMap[source][tactic] || 0) + 1;
        }
      }
    }

    // Find the global max for color scaling
    let globalMax = 0;
    for (const source of sourcesWithData) {
      for (const tactic of MITRE_TACTICS) {
        const count = tacticMap[source]?.[tactic] || 0;
        if (count > globalMax) globalMax = count;
      }
    }

    // Build grid rows
    const grid = sourcesWithData.map((source) => ({
      source,
      label: sourceLabelsShort[source] || source.toUpperCase(),
      cells: MITRE_TACTICS.map((tactic) => ({
        tactic,
        count: tacticMap[source]?.[tactic] || 0,
      })),
    }));

    return { heatmapGrid: grid, maxCount: globalMax };
  }, [data.results]);

  // Interpolate color intensity for heatmap cell
  const getCellColor = (count: number, source: string): string => {
    if (count === 0) return 'transparent';
    const baseColor = sourceColors[source] || '#6b7280';
    // Scale opacity from 0.2 to 1.0 based on count relative to max
    const intensity = maxCount > 0 ? 0.2 + (count / maxCount) * 0.8 : 0.5;
    return `${baseColor}${Math.round(intensity * 255).toString(16).padStart(2, '0')}`;
  };

  return (
    <div className="space-y-4">
      <h3 className="text-sm font-display font-bold text-gray-400 tracking-wider uppercase">
        Comparison Analytics
      </h3>

      {/* ── Top Row: 3 charts ──────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Coverage by Source */}
        <div
          className="bg-void-850 border border-void-700 p-4"
          style={{
            clipPath:
              'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))',
          }}
        >
          <h4 className="text-xs font-mono text-gray-500 mb-3 uppercase">
            Rules by Vendor
          </h4>
          <ResponsiveContainer width="100%" height={barChartHeight}>
            <BarChart data={coverageData} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
              <XAxis type="number" stroke="#6b7280" tick={{ fontSize: 11 }} />
              <YAxis
                type="category"
                dataKey="source"
                stroke="#6b7280"
                width={110}
                tick={{ fontSize: 11 }}
              />
              <Tooltip contentStyle={tooltipStyle} />
              <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                {coverageData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Severity Distribution */}
        <div
          className="bg-void-850 border border-void-700 p-4"
          style={{
            clipPath:
              'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))',
          }}
        >
          <h4 className="text-xs font-mono text-gray-500 mb-3 uppercase">
            Severity Distribution
          </h4>
          <ResponsiveContainer width="100%" height={barChartHeight}>
            <BarChart data={severityData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
              <XAxis dataKey="source" stroke="#6b7280" tick={{ fontSize: 10 }} />
              <YAxis stroke="#6b7280" tick={{ fontSize: 11 }} />
              <Tooltip contentStyle={tooltipStyle} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              <Bar
                dataKey="critical"
                stackId="severity"
                fill={severityColors.critical}
                name="Critical"
              />
              <Bar
                dataKey="high"
                stackId="severity"
                fill={severityColors.high}
                name="High"
              />
              <Bar
                dataKey="medium"
                stackId="severity"
                fill={severityColors.medium}
                name="Medium"
              />
              <Bar
                dataKey="low"
                stackId="severity"
                fill={severityColors.low}
                name="Low"
              />
              <Bar
                dataKey="unknown"
                stackId="severity"
                fill={severityColors.unknown}
                name="Unknown"
              />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Platform Distribution (compact pie) */}
        {platformData.length > 0 && (
          <div
            className="bg-void-850 border border-void-700 p-4"
            style={{
              clipPath:
                'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))',
            }}
          >
            <h4 className="text-xs font-mono text-gray-500 mb-3 uppercase">
              Platform Distribution
            </h4>
            <ResponsiveContainer width="100%" height={barChartHeight}>
              <PieChart>
                <Pie
                  data={platformData}
                  cx="50%"
                  cy="50%"
                  innerRadius={40}
                  outerRadius={65}
                  paddingAngle={2}
                  dataKey="value"
                  label={({ name, percent }) =>
                    `${name} ${((percent ?? 0) * 100).toFixed(0)}%`
                  }
                  labelLine={{ stroke: '#6b7280' }}
                >
                  {platformData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={tooltipStyle} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* ── MITRE Tactic Heatmap ───────────────────────────────────────── */}
      {heatmapGrid.length > 0 && (
        <div
          className="bg-void-850 border border-void-700 p-4"
          style={{
            clipPath:
              'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))',
          }}
        >
          <h4 className="text-xs font-mono text-gray-500 mb-3 uppercase">
            MITRE ATT&CK Tactic Coverage
          </h4>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead>
                <tr>
                  <th className="text-left text-[10px] font-mono text-gray-500 p-1.5 w-24 min-w-[96px]">
                    SOURCE
                  </th>
                  {MITRE_TACTICS.map((tactic) => (
                    <th
                      key={tactic}
                      className="text-center text-[9px] font-mono text-gray-500 p-1 min-w-[60px]"
                    >
                      {tacticLabels[tactic]}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {heatmapGrid.map((row) => (
                  <tr key={row.source}>
                    <td className="text-[10px] font-mono font-semibold p-1.5" style={{ color: sourceColors[row.source] }}>
                      {row.label}
                    </td>
                    {row.cells.map((cell) => (
                      <td key={cell.tactic} className="p-1">
                        <div
                          className="flex items-center justify-center h-7 text-[10px] font-mono border border-void-700/50 transition-colors"
                          style={{
                            backgroundColor: getCellColor(cell.count, row.source),
                            color: cell.count > 0 ? '#e5e7eb' : '#374151',
                          }}
                          title={`${sourceLabels[row.source] || row.source} — ${tacticLabels[cell.tactic]}: ${cell.count} rules`}
                        >
                          {cell.count > 0 ? cell.count : '—'}
                        </div>
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
