export function About() {
  return (
    <div className="max-w-4xl mx-auto space-y-8">
      {/* Hero Section */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        <div className="h-2 bg-gradient-to-r from-blue-600 via-purple-600 to-amber-500" />
        <div className="p-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-4">About Threat Detection Explorer</h1>
          <p className="text-lg text-gray-600 leading-relaxed">
            Threat Detection Explorer is a tool for security professionals to browse, search, and compare
            detection rules from multiple open-source threat detection repositories. It normalizes rules
            from different formats into a common schema, making it easier to understand coverage gaps
            and find relevant detections across different platforms.
          </p>
        </div>
      </div>

      {/* What This Tool Does */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-8">
        <h2 className="text-xl font-bold text-gray-900 mb-4">What This Tool Does</h2>
        <ul className="space-y-3 text-gray-600">
          <li className="flex items-start gap-3">
            <span className="flex-shrink-0 w-6 h-6 bg-blue-100 text-blue-700 rounded-full flex items-center justify-center text-sm font-semibold">1</span>
            <span><strong>Aggregates</strong> detection rules from multiple security repositories into a single searchable interface</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="flex-shrink-0 w-6 h-6 bg-blue-100 text-blue-700 rounded-full flex items-center justify-center text-sm font-semibold">2</span>
            <span><strong>Normalizes</strong> different rule formats (Sigma, SPL, EQL, KQL, etc.) to a common schema for easier comparison</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="flex-shrink-0 w-6 h-6 bg-blue-100 text-blue-700 rounded-full flex items-center justify-center text-sm font-semibold">3</span>
            <span><strong>Maps</strong> rules to MITRE ATT&CK techniques and tactics for coverage analysis</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="flex-shrink-0 w-6 h-6 bg-blue-100 text-blue-700 rounded-full flex items-center justify-center text-sm font-semibold">4</span>
            <span><strong>Links</strong> back to original source files so you can access the authoritative version</span>
          </li>
        </ul>
      </div>

      {/* Data Sources */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-8">
        <h2 className="text-xl font-bold text-gray-900 mb-4">Data Sources</h2>
        <p className="text-gray-600 mb-4">
          This tool aggregates detection rules from the following open-source repositories:
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[
            { name: 'SigmaHQ', url: 'https://github.com/SigmaHQ/sigma', license: 'Detection Rule License (DRL) 1.1', color: 'bg-blue-600' },
            { name: 'Elastic Detection Rules', url: 'https://github.com/elastic/detection-rules', license: 'Elastic License 2.0', color: 'bg-amber-500' },
            { name: 'Splunk Security Content', url: 'https://github.com/splunk/security_content', license: 'Apache 2.0', color: 'bg-green-600' },
            { name: 'Sublime Security Rules', url: 'https://github.com/sublime-security/sublime-rules', license: 'See repository', color: 'bg-purple-600' },
            { name: 'Elastic Protections', url: 'https://github.com/elastic/protections-artifacts', license: 'Elastic License 2.0', color: 'bg-amber-600' },
            { name: 'LOLRMM', url: 'https://github.com/magicsword-io/LOLRMM', license: 'See repository', color: 'bg-rose-600' },
          ].map((source) => (
            <a
              key={source.name}
              href={source.url}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-3 p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors"
            >
              <div className={`w-3 h-3 rounded-full ${source.color}`} />
              <div>
                <p className="font-medium text-gray-900">{source.name}</p>
                <p className="text-sm text-gray-500">{source.license}</p>
              </div>
            </a>
          ))}
        </div>
      </div>

      {/* Disclaimer */}
      <div className="bg-amber-50 rounded-xl border border-amber-200 p-8">
        <h2 className="text-xl font-bold text-amber-900 mb-4">Disclaimer</h2>
        <div className="space-y-4 text-amber-800">
          <p>
            <strong>This is an educational and research tool.</strong> The detection rules displayed on this
            site are aggregated from third-party open-source repositories and remain the intellectual property
            of their respective owners.
          </p>
          <p>
            All rules are displayed with links to their original source files. This tool does not claim
            ownership of any detection content and is not affiliated with or endorsed by any of the
            source projects.
          </p>
          <p>
            <strong>License Compliance:</strong> Users of this tool should review and comply with the
            individual licenses of each source repository before using any detection rules in their
            own environments. Some licenses (such as the Elastic License 2.0) have specific restrictions
            on commercial use and managed services.
          </p>
          <p>
            <strong>No Warranty:</strong> This tool is provided "as is" without warranty of any kind.
            Detection rules may be outdated, incorrect, or unsuitable for your environment. Always
            test and validate rules before deploying them in production.
          </p>
        </div>
      </div>

      {/* About Me */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-8">
        <h2 className="text-xl font-bold text-gray-900 mb-4">About the Author</h2>
        <div className="flex items-start gap-6">
          {/* Placeholder for profile image */}
          <div className="flex-shrink-0 w-24 h-24 bg-gray-200 rounded-full flex items-center justify-center text-gray-400">
            <svg className="w-12 h-12" fill="currentColor" viewBox="0 0 24 24">
              <path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z" />
            </svg>
          </div>
          <div className="space-y-3">
            {/* TODO: Fill in your information */}
            <p className="text-gray-600">
              <strong className="text-gray-900">[Your Name]</strong>
            </p>
            <p className="text-gray-600">
              [A brief bio about yourself - your background in security, why you built this tool, etc.]
            </p>
            <div className="flex items-center gap-4">
              {/* Social links - uncomment and update as needed */}
              {/*
              <a href="https://github.com/yourusername" target="_blank" rel="noopener noreferrer" className="text-gray-500 hover:text-gray-700">
                <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
                  <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
                </svg>
              </a>
              <a href="https://linkedin.com/in/yourusername" target="_blank" rel="noopener noreferrer" className="text-gray-500 hover:text-gray-700">
                <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
                </svg>
              </a>
              <a href="https://twitter.com/yourusername" target="_blank" rel="noopener noreferrer" className="text-gray-500 hover:text-gray-700">
                <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M23.953 4.57a10 10 0 01-2.825.775 4.958 4.958 0 002.163-2.723c-.951.555-2.005.959-3.127 1.184a4.92 4.92 0 00-8.384 4.482C7.69 8.095 4.067 6.13 1.64 3.162a4.822 4.822 0 00-.666 2.475c0 1.71.87 3.213 2.188 4.096a4.904 4.904 0 01-2.228-.616v.06a4.923 4.923 0 003.946 4.827 4.996 4.996 0 01-2.212.085 4.936 4.936 0 004.604 3.417 9.867 9.867 0 01-6.102 2.105c-.39 0-.779-.023-1.17-.067a13.995 13.995 0 007.557 2.209c9.053 0 13.998-7.496 13.998-13.985 0-.21 0-.42-.015-.63A9.935 9.935 0 0024 4.59z"/>
                </svg>
              </a>
              */}
              <span className="text-gray-400 text-sm">[Add your social links]</span>
            </div>
          </div>
        </div>
      </div>

      {/* Contact / Feedback */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-8">
        <h2 className="text-xl font-bold text-gray-900 mb-4">Feedback & Contributions</h2>
        <p className="text-gray-600 mb-4">
          Found a bug? Have a suggestion? Want to contribute?
        </p>
        <p className="text-gray-600">
          {/* TODO: Update with your contact method */}
          [Add your preferred contact method - GitHub issues, email, etc.]
        </p>
      </div>
    </div>
  );
}
