// Original SVG icons for each data source
export function DataSourceIcon({
  source,
  className = '',
  size = 48
}: {
  source: 'sigma' | 'elastic' | 'splunk' | 'sublime' | 'elastic_protections' | 'lolrmm' | 'elastic_hunting' | 'sentinel' | 'google_secops' | 'okta' | 'auth0' | 'panther' | 'pypanther';
  className?: string;
  size?: number;
}) {
  const colors: Record<string, string> = {
    sigma: '#a855f7',
    elastic: '#3b82f6',
    splunk: '#f97316',
    sublime: '#ec4899',
    elastic_protections: '#06b6d4',
    lolrmm: '#22c55e',
    elastic_hunting: '#8b5cf6',
    sentinel: '#0078d4',
    google_secops: '#84cc16',
    okta: '#14b8a6',
    auth0: '#f59e0b',
    panther: '#d946ef',
    pypanther: '#c026d3',
  };

  const color = colors[source] || '#00ffcc';

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      className={className}
      xmlns="http://www.w3.org/2000/svg"
    >
      <defs>
        <filter id={`glow-${source}`}>
          <feGaussianBlur stdDeviation="1.5" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        <linearGradient id={`grad-${source}`} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor={color} stopOpacity="0.4" />
          <stop offset="100%" stopColor={color} stopOpacity="0.1" />
        </linearGradient>
      </defs>

      {/* Background circle */}
      <circle cx="24" cy="24" r="22" fill={`url(#grad-${source})`} />
      <circle cx="24" cy="24" r="22" fill="none" stroke={color} strokeWidth="1" strokeOpacity="0.5" />

      {/* Source-specific icon */}
      {source === 'sigma' && (
        // Sigma symbol (Greek letter)
        <g filter={`url(#glow-${source})`}>
          <path
            d="M14,14 L34,14 L24,24 L34,34 L14,34"
            fill="none"
            stroke={color}
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </g>
      )}

      {source === 'elastic' && (
        // Elastic search bars
        <g filter={`url(#glow-${source})`}>
          <rect x="13" y="14" width="22" height="4" rx="2" fill={color} />
          <rect x="13" y="22" width="16" height="4" rx="2" fill={color} fillOpacity="0.7" />
          <rect x="13" y="30" width="10" height="4" rx="2" fill={color} fillOpacity="0.5" />
        </g>
      )}

      {source === 'splunk' && (
        // Data stream / pipeline
        <g filter={`url(#glow-${source})`}>
          <path
            d="M12,24 Q18,16 24,24 Q30,32 36,24"
            fill="none"
            stroke={color}
            strokeWidth="3"
            strokeLinecap="round"
          />
          <circle cx="12" cy="24" r="3" fill={color} />
          <circle cx="36" cy="24" r="3" fill={color} />
        </g>
      )}

      {source === 'sublime' && (
        // Email/envelope icon
        <g filter={`url(#glow-${source})`}>
          <rect x="10" y="15" width="28" height="18" rx="2" fill="none" stroke={color} strokeWidth="2" />
          <path d="M10,15 L24,26 L38,15" fill="none" stroke={color} strokeWidth="2" strokeLinejoin="round" />
        </g>
      )}

      {source === 'elastic_protections' && (
        // Shield icon
        <g filter={`url(#glow-${source})`}>
          <path
            d="M24,8 L38,14 L38,26 Q38,38 24,42 Q10,38 10,26 L10,14 Z"
            fill="none"
            stroke={color}
            strokeWidth="2"
          />
          <path
            d="M18,24 L22,28 L30,20"
            fill="none"
            stroke={color}
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </g>
      )}

      {source === 'lolrmm' && (
        // RMM/Remote icon
        <g filter={`url(#glow-${source})`}>
          <rect x="14" y="12" width="20" height="16" rx="2" fill="none" stroke={color} strokeWidth="2" />
          <path d="M24,28 L24,34" stroke={color} strokeWidth="2" />
          <path d="M18,34 L30,34" stroke={color} strokeWidth="2" strokeLinecap="round" />
          <circle cx="24" cy="20" r="4" fill="none" stroke={color} strokeWidth="1.5" />
          <path d="M24,16 L24,18" stroke={color} strokeWidth="1.5" strokeLinecap="round" />
        </g>
      )}

      {source === 'elastic_hunting' && (
        // Hunting/Magnifier with crosshair icon
        <g filter={`url(#glow-${source})`}>
          <circle cx="20" cy="20" r="10" fill="none" stroke={color} strokeWidth="2" />
          <path d="M28,28 L36,36" stroke={color} strokeWidth="2.5" strokeLinecap="round" />
          <path d="M20,14 L20,26" stroke={color} strokeWidth="1.5" strokeLinecap="round" />
          <path d="M14,20 L26,20" stroke={color} strokeWidth="1.5" strokeLinecap="round" />
        </g>
      )}

      {source === 'sentinel' && (
        // Microsoft Sentinel - cloud with radar/eye icon
        <g filter={`url(#glow-${source})`}>
          {/* Cloud shape */}
          <path
            d="M14,28 Q10,28 10,24 Q10,20 14,20 Q14,14 20,14 Q24,14 26,16 Q28,14 32,14 Q38,14 38,20 Q38,28 32,28 Z"
            fill="none"
            stroke={color}
            strokeWidth="2"
          />
          {/* Inner eye/radar */}
          <circle cx="24" cy="22" r="4" fill="none" stroke={color} strokeWidth="1.5" />
          <circle cx="24" cy="22" r="1.5" fill={color} />
        </g>
      )}

      {source === 'google_secops' && (
        // Google SecOps - stylized "G" inside hex (Chronicle/SecOps)
        <g filter={`url(#glow-${source})`}>
          {/* Hex shield */}
          <path
            d="M24,8 L38,16 L38,32 L24,40 L10,32 L10,16 Z"
            fill="none"
            stroke={color}
            strokeWidth="2"
            strokeLinejoin="round"
          />
          {/* Stylized G */}
          <path
            d="M30,21 A6,6 0 1,0 30,27 L25,27 L25,24 L30,24"
            fill="none"
            stroke={color}
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </g>
      )}

      {source === 'okta' && (
        // Okta - identity/ID badge with concentric ring (auth focus)
        <g filter={`url(#glow-${source})`}>
          {/* Outer ID-card */}
          <rect
            x="10" y="14" width="28" height="20" rx="3"
            fill="none" stroke={color} strokeWidth="2"
          />
          {/* User silhouette circle */}
          <circle cx="19" cy="22" r="3" fill="none" stroke={color} strokeWidth="1.5" />
          <path
            d="M14,32 Q14,26 19,26 Q24,26 24,32"
            fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round"
          />
          {/* Auth lines */}
          <line x1="28" y1="22" x2="34" y2="22" stroke={color} strokeWidth="1.5" strokeLinecap="round" />
          <line x1="28" y1="26" x2="34" y2="26" stroke={color} strokeWidth="1.5" strokeLinecap="round" />
        </g>
      )}

      {source === 'auth0' && (
        // Auth0 - stylized lock with key cutout (authentication focus)
        <g filter={`url(#glow-${source})`}>
          {/* Lock body */}
          <rect
            x="13" y="22" width="22" height="16" rx="2"
            fill="none" stroke={color} strokeWidth="2"
          />
          {/* Lock shackle */}
          <path
            d="M18,22 L18,17 Q18,12 24,12 Q30,12 30,17 L30,22"
            fill="none" stroke={color} strokeWidth="2" strokeLinecap="round"
          />
          {/* Keyhole */}
          <circle cx="24" cy="29" r="2" fill={color} />
          <line x1="24" y1="29" x2="24" y2="34" stroke={color} strokeWidth="2" strokeLinecap="round" />
        </g>
      )}

      {source === 'pypanther' && (
        // PyPanther - the panther eyes over python brackets: same cat,
        // Pythonic framework
        <g filter={`url(#glow-${source})`}>
          <ellipse cx="19" cy="19" rx="2.5" ry="3.5" fill={color} />
          <ellipse cx="29" cy="19" rx="2.5" ry="3.5" fill={color} />
          <path
            d="M18,27 Q24,31 30,27"
            fill="none" stroke={color} strokeWidth="2" strokeLinecap="round"
          />
          {/* Python-style brackets */}
          <path
            d="M13,33 Q10,36 13,39"
            fill="none" stroke={color} strokeWidth="2" strokeLinecap="round"
          />
          <path
            d="M35,33 Q38,36 35,39"
            fill="none" stroke={color} strokeWidth="2" strokeLinecap="round"
          />
        </g>
      )}

      {source === 'panther' && (
        // Panther - stylized panther eyes / silhouette on dark background
        // (Python-based detections spanning 97 log sources)
        <g filter={`url(#glow-${source})`}>
          {/* Two eyes */}
          <ellipse cx="19" cy="21" rx="2.5" ry="3.5" fill={color} />
          <ellipse cx="29" cy="21" rx="2.5" ry="3.5" fill={color} />
          {/* Feline mouth arc */}
          <path
            d="M18,30 Q24,34 30,30"
            fill="none" stroke={color} strokeWidth="2" strokeLinecap="round"
          />
          {/* Pointed ears */}
          <path
            d="M14,17 L11,11 L17,14 Z"
            fill={color} fillOpacity="0.7"
          />
          <path
            d="M34,17 L37,11 L31,14 Z"
            fill={color} fillOpacity="0.7"
          />
        </g>
      )}
    </svg>
  );
}
