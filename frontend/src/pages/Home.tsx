import { Link } from 'react-router-dom';
import { useStatistics } from '../hooks/useDetections';

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

const dataSources = [
  {
    id: 'sigma',
    name: 'SigmaHQ',
    description: 'Community-driven Sigma rules covering a wide range of MITRE ATT&CK techniques.',
    repoUrl: 'https://github.com/SigmaHQ/sigma',
    color: 'from-purple-500 to-purple-600',
    textColor: 'text-purple-400',
  },
  {
    id: 'elastic',
    name: 'Elastic Detection Rules',
    description: 'Detection rules for Elastic Security using KQL and EQL query formats.',
    repoUrl: 'https://github.com/elastic/detection-rules',
    color: 'from-blue-500 to-blue-600',
    textColor: 'text-blue-400',
  },
  {
    id: 'splunk',
    name: 'Splunk Security Content',
    description: 'Analytics stories and detection searches for Splunk Enterprise Security.',
    repoUrl: 'https://github.com/splunk/security_content',
    color: 'from-orange-500 to-orange-600',
    textColor: 'text-orange-400',
  },
  {
    id: 'sublime',
    name: 'Sublime Security',
    description: 'Email security detection rules using Message Query Language (MQL).',
    repoUrl: 'https://github.com/sublime-security/sublime-rules',
    color: 'from-pink-500 to-pink-600',
    textColor: 'text-pink-400',
  },
  {
    id: 'elastic_protections',
    name: 'Elastic Protections',
    description: 'Endpoint behavior rules for Elastic Endpoint Security using EQL.',
    repoUrl: 'https://github.com/elastic/protections-artifacts',
    color: 'from-cyan-500 to-cyan-600',
    textColor: 'text-cyan-400',
  },
  {
    id: 'lolrmm',
    name: 'LOLRMM',
    description: 'Detection rules for RMM tools commonly abused by threat actors.',
    repoUrl: 'https://github.com/magicsword-io/LOLRMM',
    color: 'from-green-500 to-green-600',
    textColor: 'text-green-400',
  },
];

const features = [
  {
    title: 'Aggregates',
    description: 'Detection rules from multiple security repositories into a single searchable interface.',
    icon: (
      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
      </svg>
    ),
  },
  {
    title: 'Normalizes',
    description: 'Different rule formats (Sigma, SPL, EQL, KQL) to a common schema for easier comparison.',
    icon: (
      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" />
      </svg>
    ),
  },
  {
    title: 'Maps',
    description: 'Rules to MITRE ATT&CK techniques and tactics for coverage analysis.',
    icon: (
      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7" />
      </svg>
    ),
  },
  {
    title: 'Links',
    description: 'Back to original source files so you can access the authoritative version.',
    icon: (
      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
      </svg>
    ),
  },
];

export function Home() {
  const { data: stats, isLoading } = useStatistics();

  return (
    <div className="space-y-16">
      {/* Hero Section */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 bg-hero-gradient pointer-events-none" />
        <div className="relative text-center py-16 px-4">
          <h1 className="text-4xl md:text-5xl font-bold text-white mb-4">
            Threat Detection{' '}
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">
              Explorer
            </span>
          </h1>
          <p className="text-lg md:text-xl text-gray-400 max-w-2xl mx-auto mb-8">
            Browse, search, and compare detection rules from multiple open-source
            security repositories in one unified interface.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link
              to="/detections"
              className="px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-500 text-white font-semibold rounded-lg hover:from-cyan-400 hover:to-blue-400 transition-all shadow-glow-cyan"
            >
              Browse Detections
            </Link>
            <Link
              to="/compare"
              className="px-6 py-3 bg-cyber-800 text-cyan-400 font-semibold rounded-lg border border-cyan-500/30 hover:bg-cyber-700 hover:border-cyan-500/50 transition-all"
            >
              Compare Coverage
            </Link>
          </div>
        </div>
      </section>

      {/* Statistics Section */}
      {!isLoading && stats && (
        <section>
          <h2 className="text-2xl font-bold text-white text-center mb-8">
            Detection Rules by Source
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
            <div className="bg-cyber-850 rounded-lg border border-cyber-700 p-4 text-center hover:border-cyan-500/30 transition-colors">
              <p className="text-3xl font-bold text-cyan-400">{stats.total.toLocaleString()}</p>
              <p className="text-sm text-gray-400 mt-1">Total</p>
            </div>
            <div className="bg-cyber-850 rounded-lg border border-cyber-700 p-4 text-center hover:border-purple-500/30 transition-colors">
              <p className="text-3xl font-bold text-purple-400">{(stats.by_source.sigma || 0).toLocaleString()}</p>
              <p className="text-sm text-gray-400 mt-1">Sigma</p>
            </div>
            <div className="bg-cyber-850 rounded-lg border border-cyber-700 p-4 text-center hover:border-blue-500/30 transition-colors">
              <p className="text-3xl font-bold text-blue-400">{(stats.by_source.elastic || 0).toLocaleString()}</p>
              <p className="text-sm text-gray-400 mt-1">Elastic</p>
            </div>
            <div className="bg-cyber-850 rounded-lg border border-cyber-700 p-4 text-center hover:border-orange-500/30 transition-colors">
              <p className="text-3xl font-bold text-orange-400">{(stats.by_source.splunk || 0).toLocaleString()}</p>
              <p className="text-sm text-gray-400 mt-1">Splunk</p>
            </div>
            <div className="bg-cyber-850 rounded-lg border border-cyber-700 p-4 text-center hover:border-pink-500/30 transition-colors">
              <p className="text-3xl font-bold text-pink-400">{(stats.by_source.sublime || 0).toLocaleString()}</p>
              <p className="text-sm text-gray-400 mt-1">Sublime</p>
            </div>
            <div className="bg-cyber-850 rounded-lg border border-cyber-700 p-4 text-center hover:border-cyan-500/30 transition-colors">
              <p className="text-3xl font-bold text-cyan-400">{(stats.by_source.elastic_protections || 0).toLocaleString()}</p>
              <p className="text-sm text-gray-400 mt-1">Elastic Protect</p>
            </div>
            <div className="bg-cyber-850 rounded-lg border border-cyber-700 p-4 text-center hover:border-green-500/30 transition-colors">
              <p className="text-3xl font-bold text-green-400">{(stats.by_source.lolrmm || 0).toLocaleString()}</p>
              <p className="text-sm text-gray-400 mt-1">LOLRMM</p>
            </div>
          </div>
        </section>
      )}

      {/* What We Provide Section */}
      <section>
        <h2 className="text-2xl font-bold text-white text-center mb-8">What This Tool Does</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {features.map((feature) => (
            <div
              key={feature.title}
              className="bg-cyber-850 rounded-lg border border-cyber-700 p-6 hover:border-cyan-500/30 hover:shadow-glow-cyan transition-all"
            >
              <div className="w-12 h-12 bg-cyan-500/10 rounded-lg flex items-center justify-center text-cyan-400 mb-4">
                {feature.icon}
              </div>
              <h3 className="text-lg font-semibold text-white mb-2">{feature.title}</h3>
              <p className="text-gray-400 text-sm">{feature.description}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Data Sources Section */}
      <section>
        <h2 className="text-2xl font-bold text-white text-center mb-8">Data Sources</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {dataSources.map((source) => (
            <a
              key={source.id}
              href={source.repoUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="group bg-cyber-850 rounded-lg border border-cyber-700 p-5 hover:border-cyan-500/30 transition-all"
            >
              <div className="flex items-start justify-between">
                <div>
                  <h3 className={`font-semibold ${source.textColor} group-hover:brightness-125 transition-all`}>
                    {source.name}
                  </h3>
                  <p className="text-sm text-gray-400 mt-2">{source.description}</p>
                </div>
                <span className="text-gray-500 group-hover:text-cyan-400 transition-colors">
                  <ExternalLinkIcon size={18} />
                </span>
              </div>
            </a>
          ))}
        </div>
      </section>

      {/* About the Author Section */}
      <section className="bg-cyber-850 rounded-xl border border-cyber-700 p-8">
        <h2 className="text-2xl font-bold text-white mb-6">About the Author</h2>
        <div className="flex flex-col md:flex-row items-start gap-6">
          <div className="flex-shrink-0 w-24 h-24 bg-gradient-to-br from-cyan-500 to-blue-500 rounded-full flex items-center justify-center text-white text-3xl font-bold">
            JT
          </div>
          <div className="flex-1">
            <h3 className="text-xl font-semibold text-white mb-3">Jay Tymchuk</h3>
            <p className="text-gray-400 leading-relaxed mb-4">
              I am a senior cybersecurity professional and lead detection engineer specializing in
              large-scale SOC operations, detection-as-code, and advanced threat detection across
              EDR, SIEM, NGFW, and cloud environments. I have extensive experience building and
              deploying automated threat detection content across various security platforms,
              including custom SIEM solutions and AI-enhanced detection strategies.
            </p>
            <p className="text-gray-400 leading-relaxed mb-4">
              My expertise spans development of threat detection strategies, automation engineering,
              and operationalizing threat intelligence. I am passionate about creating tools that
              help security teams work more efficiently and effectively.
            </p>
            <div className="flex items-center gap-4">
              <a
                href="https://www.linkedin.com/in/jay-tymchuk/"
                target="_blank"
                rel="noopener noreferrer"
                className="text-gray-400 hover:text-cyan-400 transition-colors"
                aria-label="LinkedIn"
              >
                <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
                </svg>
              </a>
              <a
                href="https://github.com/InfoSecJay"
                target="_blank"
                rel="noopener noreferrer"
                className="text-gray-400 hover:text-cyan-400 transition-colors"
                aria-label="GitHub"
              >
                <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
                  <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
                </svg>
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* Disclaimer Section */}
      <section className="bg-amber-500/10 rounded-xl border border-amber-500/30 p-8">
        <h2 className="text-xl font-bold text-amber-400 mb-4">Disclaimer</h2>
        <div className="space-y-4 text-amber-200/80 text-sm">
          <p>
            <strong className="text-amber-300">This is an educational and research tool.</strong> The detection rules
            displayed on this site are aggregated from third-party open-source repositories and remain the
            intellectual property of their respective owners.
          </p>
          <p>
            All rules are displayed with links to their original source files. This tool does not claim
            ownership of any detection content and is not affiliated with or endorsed by any of the
            source projects.
          </p>
          <p>
            <strong className="text-amber-300">License Compliance:</strong> Users should review and comply with the
            individual licenses of each source repository before using any detection rules. Some licenses
            have specific restrictions on commercial use and managed services.
          </p>
          <p>
            <strong className="text-amber-300">No Warranty:</strong> This tool is provided "as is" without warranty
            of any kind. Detection rules may be outdated, incorrect, or unsuitable for your environment.
            Always test and validate rules before deploying them in production.
          </p>
        </div>
      </section>
    </div>
  );
}
