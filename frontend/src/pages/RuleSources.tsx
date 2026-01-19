import { useState } from 'react';
import ReactMarkdown from 'react-markdown';
import { useReleases } from '../hooks/useReleases';

// Simple external link icon component
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

interface RuleSource {
  id: string;
  name: string;
  description: string;
  repoUrl: string;
  hasReleases: boolean;
  color: string;
  bgColor: string;
  borderColor: string;
}

// Format release notes to proper markdown
function formatReleaseBody(body: string): string {
  let formatted = body;

  // Convert section headers (lines that are standalone titles followed by items)
  // Common patterns: "New Rules", "Updated Rules", "Fixed Rules", "Removed / Deprecated Rules", etc.
  formatted = formatted.replace(
    /^(New Rules|Updated Rules|Fixed Rules|Removed \/ Deprecated Rules|Removed Rules|Deprecated Rules|Acknowledgement|Breaking Changes|Bug Fixes|Features|Enhancements|Other Changes|What's Changed|Full Changelog)$/gm,
    '\n## $1\n'
  );

  // Convert lines starting with prefixes like "new:", "update:", "fix:", "remove:" to bullet points
  formatted = formatted.replace(/^(new|update|fix|remove|deprecate|add|change):\s*/gim, '- **$1:** ');

  // Convert lines starting with "- " followed by text (already bullet points) - keep them
  // Convert lines starting with "* " to "- " for consistency
  formatted = formatted.replace(/^\* /gm, '- ');

  // Convert @mentions to bold
  formatted = formatted.replace(/@(\w+)/g, '**@$1**');

  // Add line breaks before sections that look like headers but weren't caught
  formatted = formatted.replace(/\n([A-Z][A-Za-z\s\/]+)\n(?=-|\*|new:|update:|fix:)/g, '\n\n## $1\n\n');

  // Clean up multiple newlines
  formatted = formatted.replace(/\n{3,}/g, '\n\n');

  return formatted.trim();
}

const ruleSources: RuleSource[] = [
  {
    id: 'sigma',
    name: 'SigmaHQ',
    description: 'The original and largest community-driven Sigma rules repository, covering a wide range of MITRE ATT&CK techniques with platform-agnostic detection rules.',
    repoUrl: 'https://github.com/SigmaHQ/sigma',
    hasReleases: true,
    color: 'text-purple-700',
    bgColor: 'bg-purple-50',
    borderColor: 'border-purple-200',
  },
  {
    id: 'elastic',
    name: 'Elastic Detection Rules',
    description: 'Detection rules designed for Elastic Security using KQL and EQL query formats, with built-in MITRE ATT&CK mapping.',
    repoUrl: 'https://github.com/elastic/detection-rules',
    hasReleases: true,
    color: 'text-blue-700',
    bgColor: 'bg-blue-50',
    borderColor: 'border-blue-200',
  },
  {
    id: 'splunk',
    name: 'Splunk Security Content',
    description: 'Analytics stories and detection searches for Splunk Enterprise Security, providing comprehensive threat coverage.',
    repoUrl: 'https://github.com/splunk/security_content',
    hasReleases: true,
    color: 'text-orange-700',
    bgColor: 'bg-orange-50',
    borderColor: 'border-orange-200',
  },
  {
    id: 'sublime',
    name: 'Sublime Security',
    description: 'Email security detection rules using Message Query Language (MQL) for identifying phishing, BEC, and other email-based threats.',
    repoUrl: 'https://github.com/sublime-security/sublime-rules',
    hasReleases: false,
    color: 'text-pink-700',
    bgColor: 'bg-pink-50',
    borderColor: 'border-pink-200',
  },
  {
    id: 'elastic_protections',
    name: 'Elastic Protection Artifacts',
    description: 'Endpoint behavior rules for Elastic Endpoint Security, using EQL for real-time behavioral detection and response.',
    repoUrl: 'https://github.com/elastic/protections-artifacts',
    hasReleases: false,
    color: 'text-cyan-700',
    bgColor: 'bg-cyan-50',
    borderColor: 'border-cyan-200',
  },
  {
    id: 'lolrmm',
    name: 'LOLRMM',
    description: 'Detection rules for Remote Monitoring and Management (RMM) tools commonly abused by threat actors for persistence and lateral movement.',
    repoUrl: 'https://github.com/magicsword-io/LOLRMM',
    hasReleases: false,
    color: 'text-green-700',
    bgColor: 'bg-green-50',
    borderColor: 'border-green-200',
  },
];

function ReleaseViewer({ source }: { source: RuleSource }) {
  const { data: releases, isLoading, error } = useReleases(source.id, 10);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-8">
        <div className="animate-spin h-6 w-6 border-2 border-gray-400 border-t-transparent rounded-full"></div>
        <span className="ml-2 text-gray-500">Loading releases...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-red-600 py-4">
        Failed to load releases. GitHub API may be rate limited.
      </div>
    );
  }

  if (!releases || releases.length === 0) {
    return (
      <div className="text-gray-500 py-4">No releases found.</div>
    );
  }

  return (
    <div className="space-y-4">
      {releases.map((release) => (
        <div
          key={release.id}
          className="border border-gray-200 rounded-lg p-4 bg-white"
        >
          <div className="flex items-start justify-between">
            <div>
              <h4 className="font-semibold text-gray-900">{release.name}</h4>
              <p className="text-sm text-gray-500">
                {release.tag_name} • Released{' '}
                {new Date(release.published_at).toLocaleDateString()}
                {release.author && ` by ${release.author}`}
              </p>
            </div>
            <a
              href={release.html_url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-600 hover:text-blue-800 flex items-center gap-1 text-sm"
            >
              View on GitHub <ExternalLinkIcon size={14} />
            </a>
          </div>
          {release.body && (
            <div className="mt-3 text-sm text-gray-700 prose prose-sm max-w-none bg-gray-50 p-4 rounded">
              <ReactMarkdown>{formatReleaseBody(release.body)}</ReactMarkdown>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

export function RuleSources() {
  const [selectedSource, setSelectedSource] = useState<string | null>(null);
  const selectedRuleSource = ruleSources.find((s) => s.id === selectedSource);
  const sourcesWithReleases = ruleSources.filter((s) => s.hasReleases);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Rule Sources</h1>
        <p className="text-gray-600 mt-1">
          Detection rule repositories integrated into Threat Detection Explorer
        </p>
      </div>

      {/* Rule Source Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {ruleSources.map((source) => (
          <div
            key={source.id}
            className={`rounded-lg border p-5 ${source.borderColor} ${source.bgColor}`}
          >
            <h2 className={`text-lg font-semibold ${source.color}`}>
              {source.name}
            </h2>
            <p className="text-gray-600 text-sm mt-2 leading-relaxed">
              {source.description}
            </p>
            <div className="mt-4">
              <a
                href={source.repoUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 text-sm font-medium text-gray-700 hover:text-gray-900"
              >
                <ExternalLinkIcon size={14} />
                View Repository
              </a>
            </div>
          </div>
        ))}
      </div>

      {/* Release Notes Section */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="border-b border-gray-200 p-4">
          <h2 className="text-lg font-semibold text-gray-900">Release Notes</h2>
          <p className="text-sm text-gray-600 mt-1">
            View the latest releases from vendors with published release notes
          </p>
        </div>

        {/* Tabs */}
        <div className="border-b border-gray-200">
          <div className="flex gap-1 p-2 overflow-x-auto">
            {sourcesWithReleases.map((source) => (
              <button
                key={source.id}
                onClick={() =>
                  setSelectedSource(selectedSource === source.id ? null : source.id)
                }
                className={`px-4 py-2 rounded-lg text-sm font-medium whitespace-nowrap transition-colors ${
                  selectedSource === source.id
                    ? `${source.bgColor} ${source.color} border ${source.borderColor}`
                    : 'text-gray-600 hover:bg-gray-100'
                }`}
              >
                {source.name}
              </button>
            ))}
          </div>
        </div>

        {/* Release Content */}
        <div className="p-4">
          {selectedSource && selectedRuleSource ? (
            <ReleaseViewer source={selectedRuleSource} />
          ) : (
            <div className="text-center py-8 text-gray-500">
              <p>Select a vendor above to view their release notes</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
