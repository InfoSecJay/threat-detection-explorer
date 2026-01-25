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
];

// Feature cards configuration
const features = [
  {
    title: 'AGGREGATE',
    subtitle: 'Multi-Source Intelligence',
    description: 'Detection rules from 6 security repositories unified into a single searchable command interface.',
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
                <span className="text-pulse-400">OPERATIONAL</span> // 6 INTEL FEEDS ACTIVE
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
            <span className="text-xs font-mono text-gray-500">
              TOTAL_RULES: <span className="text-matrix-500">{stats.total.toLocaleString()}</span>
            </span>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
            <StatCard
              value={stats.total}
              label="Total Rules"
              color="#00ffcc"
              delay={0}
            />
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

      {/* About Section */}
      <section className="relative">
        <div
          className="bg-void-850 border border-void-700 p-8 lg:p-10"
          style={{
            clipPath: 'polygon(0 0, calc(100% - 24px) 0, 100% 24px, 100% 100%, 24px 100%, 0 calc(100% - 24px))',
          }}
        >
          {/* Corner decorations */}
          <div className="absolute top-0 right-0 w-6 h-6 bg-matrix-500/20" />
          <div className="absolute bottom-0 left-0 w-6 h-6 bg-matrix-500/20" />

          <div className="flex items-center gap-4 mb-6">
            <h2 className="text-xl font-display font-bold text-white tracking-wider uppercase">
              About the Engineer
            </h2>
            <div className="flex-1 h-px bg-gradient-to-r from-void-700 to-transparent" />
          </div>

          <div className="flex flex-col md:flex-row items-start gap-8">
            {/* Avatar */}
            <div className="flex-shrink-0">
              <div className="relative w-24 h-24">
                <svg viewBox="0 0 100 100" className="w-full h-full">
                  <defs>
                    <linearGradient id="avatarGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                      <stop offset="0%" stopColor="#00ffcc" />
                      <stop offset="100%" stopColor="#00ff41" />
                    </linearGradient>
                  </defs>
                  <polygon
                    points="50,5 90,27 90,73 50,95 10,73 10,27"
                    fill="url(#avatarGrad)"
                    fillOpacity="0.1"
                    stroke="url(#avatarGrad)"
                    strokeWidth="2"
                  />
                  <text
                    x="50"
                    y="58"
                    textAnchor="middle"
                    fill="url(#avatarGrad)"
                    fontSize="28"
                    fontFamily="Orbitron"
                    fontWeight="bold"
                  >
                    JT
                  </text>
                </svg>
              </div>
            </div>

            {/* Bio */}
            <div className="flex-1">
              <h3 className="text-lg font-display font-semibold text-matrix-500 tracking-wide mb-4">
                JAY TYMCHUK
              </h3>
              <p className="text-gray-400 leading-relaxed mb-4 text-sm">
                Senior cybersecurity professional and lead detection engineer specializing in
                large-scale SOC operations, detection-as-code, and advanced threat detection across
                EDR, SIEM, NGFW, and cloud environments. Extensive experience building and
                deploying automated threat detection content across various security platforms.
              </p>
              <p className="text-gray-400 leading-relaxed mb-6 text-sm">
                Expertise spans development of threat detection strategies, automation engineering,
                and operationalizing threat intelligence. Passionate about creating tools that
                help security teams work more efficiently.
              </p>

              {/* Social links */}
              <div className="flex items-center gap-4">
                <a
                  href="https://www.linkedin.com/in/jay-tymchuk/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 text-sm text-gray-400 hover:text-matrix-500 transition-colors"
                >
                  <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
                  </svg>
                  <span className="font-mono text-xs">LINKEDIN</span>
                </a>
                <a
                  href="https://github.com/InfoSecJay"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 text-sm text-gray-400 hover:text-matrix-500 transition-colors"
                >
                  <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                    <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
                  </svg>
                  <span className="font-mono text-xs">GITHUB</span>
                </a>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Disclaimer Section */}
      <section>
        <div
          className="bg-threat-500/5 border border-threat-500/30 p-6 lg:p-8"
          style={{
            clipPath: 'polygon(0 0, calc(100% - 16px) 0, 100% 16px, 100% 100%, 16px 100%, 0 calc(100% - 16px))',
          }}
        >
          <div className="flex items-center gap-3 mb-4">
            <svg className="w-5 h-5 text-threat-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <h2 className="text-lg font-display font-bold text-threat-400 tracking-wider uppercase">
              Legal Notice
            </h2>
          </div>

          <div className="space-y-3 text-sm text-threat-300/80">
            <p>
              <span className="font-semibold text-threat-400">EDUCATIONAL & RESEARCH TOOL.</span>{' '}
              Detection rules displayed are aggregated from third-party open-source repositories
              and remain the intellectual property of their respective owners.
            </p>
            <p>
              All rules link to original source files. This tool does not claim ownership of any
              detection content and is not affiliated with or endorsed by source projects.
            </p>
            <p>
              <span className="font-semibold text-threat-400">LICENSE COMPLIANCE:</span>{' '}
              Review and comply with individual licenses of each source repository before use.
              Some licenses have restrictions on commercial use and managed services.
            </p>
            <p>
              <span className="font-semibold text-threat-400">NO WARRANTY:</span>{' '}
              Provided "as is" without warranty. Rules may be outdated or unsuitable for your
              environment. Always validate before production deployment.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}
