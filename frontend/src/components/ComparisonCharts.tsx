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

interface ComparisonChartsProps {
  data: CompareResponse;
}

const sourceLabels: Record<string, string> = {
  sigma: 'Sigma',
  elastic: 'Elastic',
  splunk: 'Splunk',
  sublime: 'Sublime',
  elastic_protections: 'Elastic Protect',
  lolrmm: 'LOLRMM',
};

const sourceColors: Record<string, string> = {
  sigma: '#a855f7',
  elastic: '#3b82f6',
  splunk: '#f97316',
  sublime: '#ec4899',
  elastic_protections: '#06b6d4',
  lolrmm: '#22c55e',
};

const severityColors: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  unknown: '#6b7280',
};

const platformColors: Record<string, string> = {
  windows: '#3b82f6',
  linux: '#f97316',
  macos: '#8b5cf6',
  cloud: '#06b6d4',
  network: '#22c55e',
  email: '#ec4899',
  '': '#6b7280',
};

export function ComparisonCharts({ data }: ComparisonChartsProps) {
  // Prepare data for coverage chart (horizontal bar)
  const coverageData = Object.entries(data.total_by_source)
    .map(([source, count]) => ({
      source: sourceLabels[source] || source,
      count,
      fill: sourceColors[source] || '#6b7280',
    }))
    .sort((a, b) => b.count - a.count);

  // Prepare data for severity distribution (stacked bar per source)
  const severityData = Object.entries(data.results).map(([source, detections]) => {
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

  // Custom tooltip styling
  const tooltipStyle = {
    backgroundColor: '#1a1f2e',
    border: '1px solid #374151',
    borderRadius: '8px',
    color: '#e5e7eb',
  };

  return (
    <div className="space-y-6">
      <h3 className="text-lg font-semibold text-white">Comparison Analytics</h3>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Coverage by Source */}
        <div className="bg-cyber-850 rounded-lg border border-cyber-700 p-4">
          <h4 className="text-sm font-medium text-gray-400 mb-4">
            Rules by Vendor
          </h4>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={coverageData} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis type="number" stroke="#9ca3af" />
              <YAxis
                type="category"
                dataKey="source"
                stroke="#9ca3af"
                width={100}
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
        <div className="bg-cyber-850 rounded-lg border border-cyber-700 p-4">
          <h4 className="text-sm font-medium text-gray-400 mb-4">
            Severity Distribution
          </h4>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={severityData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="source" stroke="#9ca3af" />
              <YAxis stroke="#9ca3af" />
              <Tooltip contentStyle={tooltipStyle} />
              <Legend />
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
          <div className="bg-cyber-850 rounded-lg border border-cyber-700 p-4 lg:col-span-2">
            <h4 className="text-sm font-medium text-gray-400 mb-4">
              Platform Distribution
            </h4>
            <div className="flex items-center justify-center">
              <ResponsiveContainer width="100%" height={250}>
                <PieChart>
                  <Pie
                    data={platformData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={100}
                    paddingAngle={2}
                    dataKey="value"
                    label={({ name, percent }) =>
                      `${name} (${((percent ?? 0) * 100).toFixed(0)}%)`
                    }
                    labelLine={{ stroke: '#9ca3af' }}
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
