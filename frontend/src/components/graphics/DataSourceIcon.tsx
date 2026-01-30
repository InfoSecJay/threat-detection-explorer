// Original SVG icons for each data source
export function DataSourceIcon({
  source,
  className = '',
  size = 48
}: {
  source: 'sigma' | 'elastic' | 'splunk' | 'sublime' | 'elastic_protections' | 'lolrmm' | 'elastic_hunting';
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
    </svg>
  );
}
