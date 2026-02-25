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
import { sourceColors, sourceLabels, severityColors } from '../constants/sources';

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
      const platform = detection.platform || 'unknown';
      platformCounts[platform] = (platformCounts[platform] || 0) + 1;
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

  return (
    <div className="space-y-4">
      <h3 className="text-sm font-display font-bold text-gray-400 tracking-wider uppercase">
        Comparison Analytics
      </h3>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
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

        {/* Platform Distribution */}
        {platformData.length > 0 && (
          <div
            className="bg-void-850 border border-void-700 p-4 lg:col-span-2"
            style={{
              clipPath:
                'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))',
            }}
          >
            <h4 className="text-xs font-mono text-gray-500 mb-3 uppercase">
              Platform Distribution
            </h4>
            <div className="flex items-center justify-center">
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie
                    data={platformData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={90}
                    paddingAngle={2}
                    dataKey="value"
                    label={({ name, percent }) =>
                      `${name} (${((percent ?? 0) * 100).toFixed(0)}%)`
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
          </div>
        )}
      </div>
    </div>
  );
}
