import { Link } from 'react-router-dom';

export function About() {
  return (
    <div className="space-y-12 max-w-4xl mx-auto">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">
          About
        </h1>
        <p className="text-sm text-gray-500 mt-1 font-mono">
          THREAT_DETECTION_EXPLORER // SYSTEM_INFO
        </p>
      </div>

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

      {/* Project Info Section */}
      <section>
        <div
          className="bg-void-850 border border-void-700 p-8"
          style={{
            clipPath: 'polygon(0 0, calc(100% - 16px) 0, 100% 16px, 100% 100%, 16px 100%, 0 calc(100% - 16px))',
          }}
        >
          <div className="flex items-center gap-4 mb-6">
            <h2 className="text-xl font-display font-bold text-white tracking-wider uppercase">
              About This Project
            </h2>
            <div className="flex-1 h-px bg-gradient-to-r from-void-700 to-transparent" />
          </div>

          <div className="space-y-4 text-sm text-gray-400">
            <p>
              <span className="text-matrix-500 font-semibold">Threat Detection Explorer</span> is an open-source tool
              designed to help security professionals browse, search, and compare detection rules across multiple
              community-driven security repositories.
            </p>
            <p>
              The tool aggregates detection content from sources including SigmaHQ, Elastic Detection Rules,
              Splunk Security Content, Sublime Security, Elastic Protections, and LOLRMM - providing a unified
              interface to explore thousands of detection rules mapped to the MITRE ATT&CK framework.
            </p>
            <p>
              Key capabilities include full-text search, MITRE ATT&CK technique filtering, cross-vendor comparison,
              and direct links to original source files for easy reference and implementation.
            </p>
          </div>

          <div className="mt-6 pt-6 border-t border-void-700">
            <a
              href="https://github.com/InfoSecJay/threat-detection-explorer"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 text-sm text-matrix-500 hover:text-matrix-400 transition-colors"
            >
              <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
              </svg>
              <span className="font-mono text-xs uppercase">View on GitHub</span>
            </a>
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
