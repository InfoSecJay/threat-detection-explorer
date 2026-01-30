import { Link } from 'react-router-dom';
import { useStatistics } from '../hooks/useDetections';
import { ThreatRadar } from '../components/graphics/ThreatRadar';
import { HexShield } from '../components/graphics/HexShield';
import { DataSourceIcon } from '../components/graphics/DataSourceIcon';

// External link icon
function ExternalLinkIcon({ size = 16 }: { size?: number }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
      <polyline points="15 3 21 3 21 9" />
      <line x1="10" y1="14" x2="21" y2="3" />
    </svg>
  );
}

// Data sources configuration
const dataSources = [
  {
    id: 'sigma' as const,
    name: 'SigmaHQ',
    description: 'Community-driven detection rules covering comprehensive MITRE ATT&CK techniques.',
    repoUrl: 'https://github.com/SigmaHQ/sigma',
    color: '#a855f7',
  },
  {
    id: 'elastic' as const,
    name: 'Elastic Detection Rules',
    description: 'Detection rules for Elastic Security using KQL and EQL query formats.',
    repoUrl: 'https://github.com/elastic/detection-rules',
    color: '#3b82f6',
  },
  {
    id: 'splunk' as const,
    name: 'Splunk Security Content',
    description: 'Analytics stories and detection searches for Splunk Enterprise Security.',
    repoUrl: 'https://github.com/splunk/security_content',
    color: '#f97316',
  },
  {
    id: 'sublime' as const,
    name: 'Sublime Security',
    description: 'Email security detection rules using Message Query Language (MQL).',
    repoUrl: 'https://github.com/sublime-security/sublime-rules',
    color: '#ec4899',
  },
  {
    id: 'elastic_protections' as const,
    name: 'Elastic Protections',
    description: 'Endpoint behavior rules for Elastic Endpoint Security using EQL.',
    repoUrl: 'https://github.com/elastic/protections-artifacts',
    color: '#06b6d4',
  },
  {
    id: 'lolrmm' as const,
    name: 'LOLRMM',
    description: 'Detection rules for RMM tools commonly abused by threat actors.',
    repoUrl: 'https://github.com/magicsword-io/LOLRMM',
    color: '#22c55e',
  },
  {
    id: 'elastic_hunting' as const,
    name: 'Elastic Hunting',
    description: 'Proactive threat hunting queries using ES|QL for Elastic Security.',
    repoUrl: 'https://github.com/elastic/detection-rules/tree/main/hunting',
    color: '#8b5cf6',
  },
];

// Feature cards configuration
const features = [
  {
    title: 'AGGREGATE',
    subtitle: 'Multi-Source Intelligence',
    description: 'Detection rules from 7 security repositories unified into a single searchable command interface.',
    variant: 'aggregate' as const,
  },
  {
    title: 'NORMALIZE',
    subtitle: 'Unified Schema',
    description: 'Different rule formats (Sigma, SPL, EQL, KQL) normalized to a common schema for analysis.',
    variant: 'normalize' as const,
  },
  {
    title: 'MAP',
    subtitle: 'MITRE ATT&CK Coverage',
    description: 'Rules mapped to MITRE ATT&CK techniques and tactics for comprehensive coverage analysis.',
    variant: 'map' as const,
  },
  {
    title: 'LINK',
    subtitle: 'Source Attribution',
    description: 'Direct links to original source files for accessing authoritative detection content.',
    variant: 'link' as const,
  },
];

// Statistics card component
function StatCard({
  value,
  label,
  color,
  delay = 0
}: {
  value: number;
  label: string;
  color: string;
  delay?: number;
}) {
  return (
    <div
      className="relative group"
      style={{ animationDelay: `${delay}ms` }}
    >
      {/* Card background with glow effect */}
      <div
        className="relative bg-void-850 border border-void-700 p-4 transition-all duration-300 group-hover:border-opacity-50 overflow-hidden"
        style={{
          clipPath: 'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))',
          borderColor: `${color}30`,
        }}
      >
        {/* Hover glow */}
        <div
          className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300"
          style={{
            background: `radial-gradient(ellipse at center, ${color}10 0%, transparent 70%)`,
          }}
        />

        {/* Top corner accent */}
        <div
          className="absolute top-0 right-0 w-3 h-3"
          style={{ backgroundColor: color }}
        />

        {/* Content */}
        <div className="relative">
          <p
            className="text-3xl lg:text-4xl font-display font-bold tracking-wider"
            style={{ color }}
          >
            {value.toLocaleString()}
          </p>
          <p className="text-xs font-mono text-gray-500 mt-1 uppercase tracking-wider">
            {label}
          </p>
        </div>
      </div>
    </div>
  );
}

// Feature card component
function FeatureCard({
  title,
  subtitle,
  description,
  variant,
  index
}: {
  title: string;
  subtitle: string;
  description: string;
  variant: 'aggregate' | 'normalize' | 'map' | 'link';
  index: number;
}) {
  return (
    <div
      className="group relative bg-void-850 border border-void-700 p-6 transition-all duration-500 hover:border-matrix-500/30 card-lift"
      style={{
        clipPath: 'polygon(0 0, calc(100% - 16px) 0, 100% 16px, 100% 100%, 16px 100%, 0 calc(100% - 16px))',
        animationDelay: `${index * 100}ms`,
      }}
    >
      {/* Corner decoration */}
      <div className="absolute top-0 right-0 w-4 h-4 bg-matrix-500/20 group-hover:bg-matrix-500/40 transition-colors" />
      <div className="absolute bottom-0 left-0 w-4 h-4 bg-matrix-500/20 group-hover:bg-matrix-500/40 transition-colors" />

      {/* Icon */}
      <div className="w-16 h-16 mb-4 group-hover:scale-110 transition-transform duration-300">
        <HexShield variant={variant} className="w-full h-full" />
      </div>

      {/* Content */}
      <h3 className="text-lg font-display font-bold text-matrix-500 tracking-wider mb-1">
        {title}
      </h3>
      <p className="text-xs font-mono text-gray-500 mb-3 uppercase tracking-wide">
        {subtitle}
      </p>
      <p className="text-sm text-gray-400 leading-relaxed">
        {description}
      </p>

      {/* Bottom border accent on hover */}
      <div className="absolute bottom-0 left-4 right-4 h-px bg-gradient-to-r from-transparent via-matrix-500/50 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
    </div>
  );
}

// Data source card component
function DataSourceCard({
  source,
  index
}: {
  source: typeof dataSources[0];
  index: number;
}) {
  return (
    <a
      href={source.repoUrl}
      target="_blank"
      rel="noopener noreferrer"
      className="group relative bg-void-850 border border-void-700 p-5 transition-all duration-300 hover:border-opacity-50 card-lift"
      style={{
        borderColor: `${source.color}30`,
        animationDelay: `${index * 50}ms`,
      }}
    >
      {/* Background glow on hover */}
      <div
        className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300"
        style={{
          background: `radial-gradient(ellipse at top left, ${source.color}08 0%, transparent 50%)`,
        }}
      />

      {/* Content */}
      <div className="relative flex items-start gap-4">
        <div className="flex-shrink-0">
          <DataSourceIcon source={source.id} size={48} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-2">
            <h3
              className="font-display font-semibold tracking-wide text-sm group-hover:brightness-125 transition-all truncate"
              style={{ color: source.color }}
            >
              {source.name}
            </h3>
            <span className="text-gray-600 group-hover:text-matrix-500 transition-colors flex-shrink-0">
              <ExternalLinkIcon size={14} />
            </span>
          </div>
          <p className="text-xs text-gray-500 mt-2 line-clamp-2">
            {source.description}
          </p>
        </div>
      </div>

      {/* Left accent bar */}
      <div
        className="absolute left-0 top-4 bottom-4 w-0.5 opacity-50 group-hover:opacity-100 transition-opacity"
        style={{ backgroundColor: source.color }}
      />
    </a>
  );
}

export function Home() {
  const { data: stats, isLoading } = useStatistics();

  return (
    <div className="space-y-16">
      {/* Hero Section */}
      <section className="relative overflow-hidden">
        {/* Background effects */}
        <div className="absolute inset-0 bg-hero-radial pointer-events-none" />
        <div className="absolute inset-0 bg-grid-pattern bg-grid opacity-30 pointer-events-none" />

        {/* Content */}
        <div className="relative grid lg:grid-cols-2 gap-8 lg:gap-12 items-center py-12 lg:py-20">
          {/* Left - Text content */}
          <div className="text-center lg:text-left">
            {/* Badge */}
            <div className="inline-flex items-center gap-2 px-3 py-1.5 bg-void-800 border border-void-600 rounded mb-6">
              <span className="w-2 h-2 bg-pulse-500 rounded-full animate-pulse" />
              <span className="text-xs font-mono text-gray-400">
                <span className="text-pulse-400">OPERATIONAL</span> // 7 INTEL FEEDS ACTIVE
              </span>
            </div>

            {/* Title */}
            <h1 className="text-4xl md:text-5xl lg:text-6xl font-display font-bold tracking-wider mb-6">
              <span className="text-white">THREAT</span>
              <br />
              <span className="text-matrix-500 text-glow-sm">DETECTION</span>
              <br />
              <span className="text-white">EXPLORER</span>
            </h1>

            {/* Description */}
            <p className="text-lg text-gray-400 max-w-xl mx-auto lg:mx-0 mb-8 font-sans">
              Unified command interface for browsing, searching, and comparing detection rules
              across multiple open-source security repositories.
            </p>

            {/* CTA Buttons */}
            <div className="flex flex-col sm:flex-row gap-4 justify-center lg:justify-start">
              <Link
                to="/detections"
                className="btn-primary inline-flex items-center justify-center gap-2"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
                Browse Detections
              </Link>
              <Link
                to="/compare"
                className="btn-secondary inline-flex items-center justify-center gap-2"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
                Compare Coverage
              </Link>
            </div>
          </div>

          {/* Right - Radar graphic */}
          <div className="relative flex justify-center lg:justify-end">
            <div className="w-80 h-80 lg:w-96 lg:h-96 relative">
              <ThreatRadar className="w-full h-full opacity-80" />

              {/* Decorative labels around radar */}
              <div className="absolute -top-2 left-1/2 -translate-x-1/2 text-xs font-mono text-matrix-500/60">
                THREAT_INTEL
              </div>
              <div className="absolute -bottom-2 left-1/2 -translate-x-1/2 text-xs font-mono text-matrix-500/60">
                COVERAGE_MAP
              </div>
            </div>
          </div>
        </div>

        {/* Bottom decoration line */}
        <div className="absolute bottom-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-matrix-500/30 to-transparent" />
      </section>

      {/* Statistics Section */}
      {!isLoading && stats && (
        <section>
          <div className="flex items-center gap-4 mb-8">
            <h2 className="text-xl font-display font-bold text-white tracking-wider uppercase">
              Detection Intel Feed
            </h2>
            <div className="flex-1 h-px bg-gradient-to-r from-void-700 to-transparent" />
          </div>

          {/* Two-tier layout: Hero total + Source grid */}
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
            {/* Hero Total - spans 1 column on large screens, full width on mobile */}
            <div className="lg:col-span-1">
              <div
                className="relative group h-full"
              >
                <div
                  className="relative bg-void-850 border border-matrix-500/30 p-6 h-full transition-all duration-300 group-hover:border-matrix-500/50 overflow-hidden"
                  style={{
                    clipPath: 'polygon(0 0, calc(100% - 16px) 0, 100% 16px, 100% 100%, 16px 100%, 0 calc(100% - 16px))',
                  }}
                >
                  {/* Background glow */}
                  <div
                    className="absolute inset-0 opacity-20"
                    style={{
                      background: 'radial-gradient(ellipse at center, #00ffcc20 0%, transparent 70%)',
                    }}
                  />
                  {/* Corner accent */}
                  <div className="absolute top-0 right-0 w-4 h-4 bg-matrix-500" />

                  <div className="relative">
                    <p className="text-xs font-mono text-gray-500 mb-2 uppercase tracking-wider">
                      Aggregate Total
                    </p>
                    <p className="text-4xl lg:text-5xl font-display font-bold tracking-wider text-matrix-500">
                      {stats.total.toLocaleString()}
                    </p>
                    <p className="text-sm font-mono text-gray-400 mt-2">
                      Detection Rules
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* Source Cards Grid - 3 columns on large, 2 on medium, responsive fill */}
            <div className="lg:col-span-3 grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-3">
              <StatCard
                value={stats.by_source.sigma || 0}
                label="Sigma"
                color="#a855f7"
                delay={50}
              />
              <StatCard
                value={stats.by_source.elastic || 0}
                label="Elastic"
                color="#3b82f6"
                delay={100}
              />
              <StatCard
                value={stats.by_source.splunk || 0}
                label="Splunk"
                color="#f97316"
                delay={150}
              />
              <StatCard
                value={stats.by_source.sublime || 0}
                label="Sublime"
                color="#ec4899"
                delay={200}
              />
              <StatCard
                value={stats.by_source.elastic_protections || 0}
                label="Elastic Protect"
                color="#06b6d4"
                delay={250}
              />
              <StatCard
                value={stats.by_source.lolrmm || 0}
                label="LOLRMM"
                color="#22c55e"
                delay={300}
              />
              <StatCard
                value={stats.by_source.elastic_hunting || 0}
                label="Elastic Hunt"
                color="#8b5cf6"
                delay={350}
              />
            </div>
          </div>
        </section>
      )}

      {/* Features Section */}
      <section>
        <div className="flex items-center gap-4 mb-8">
          <h2 className="text-xl font-display font-bold text-white tracking-wider uppercase">
            System Capabilities
          </h2>
          <div className="flex-1 h-px bg-gradient-to-r from-void-700 to-transparent" />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {features.map((feature, index) => (
            <FeatureCard key={feature.title} {...feature} index={index} />
          ))}
        </div>
      </section>

      {/* Data Sources Section */}
      <section>
        <div className="flex items-center gap-4 mb-8">
          <h2 className="text-xl font-display font-bold text-white tracking-wider uppercase">
            Intelligence Sources
          </h2>
          <div className="flex-1 h-px bg-gradient-to-r from-void-700 to-transparent" />
          <span className="text-xs font-mono text-gray-500">
            {dataSources.length} ACTIVE_FEEDS
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {dataSources.map((source, index) => (
            <DataSourceCard key={source.id} source={source} index={index} />
          ))}
        </div>
      </section>

    </div>
  );
}
