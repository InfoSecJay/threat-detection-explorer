// Original SVG hexagonal shield graphic for feature cards
export function HexShield({
  className = '',
  variant = 'default'
}: {
  className?: string;
  variant?: 'default' | 'aggregate' | 'normalize' | 'map' | 'link';
}) {
  const colors = {
    default: { primary: '#00ffcc', secondary: '#00ff41' },
    aggregate: { primary: '#a855f7', secondary: '#00ffcc' },
    normalize: { primary: '#3b82f6', secondary: '#00ffcc' },
    map: { primary: '#f97316', secondary: '#00ffcc' },
    link: { primary: '#ec4899', secondary: '#00ffcc' },
  };

  const { primary, secondary } = colors[variant];

  return (
    <svg
      viewBox="0 0 100 100"
      className={className}
      xmlns="http://www.w3.org/2000/svg"
    >
      <defs>
        <linearGradient id={`shieldGrad-${variant}`} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor={primary} stopOpacity="0.3" />
          <stop offset="100%" stopColor={secondary} stopOpacity="0.1" />
        </linearGradient>

        <filter id={`shieldGlow-${variant}`}>
          <feGaussianBlur stdDeviation="2" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      {/* Outer hexagon */}
      <polygon
        points="50,5 90,27 90,73 50,95 10,73 10,27"
        fill={`url(#shieldGrad-${variant})`}
        stroke={primary}
        strokeWidth="2"
        strokeOpacity="0.5"
      />

      {/* Inner hexagon */}
      <polygon
        points="50,15 80,32 80,68 50,85 20,68 20,32"
        fill="none"
        stroke={primary}
        strokeWidth="1"
        strokeOpacity="0.3"
        strokeDasharray="4 2"
      />

      {/* Center icon area */}
      <circle
        cx="50"
        cy="50"
        r="20"
        fill={primary}
        fillOpacity="0.1"
        stroke={primary}
        strokeWidth="1"
        strokeOpacity="0.4"
      />

      {/* Variant-specific inner icon */}
      {variant === 'aggregate' && (
        <g stroke={primary} strokeWidth="2" fill="none" strokeLinecap="round">
          <path d="M40,55 L50,45 L60,55" />
          <path d="M35,60 L50,45 L65,60" />
          <circle cx="50" cy="45" r="3" fill={primary} />
        </g>
      )}

      {variant === 'normalize' && (
        <g stroke={primary} strokeWidth="2" fill="none" strokeLinecap="round">
          <path d="M38,45 H62" />
          <path d="M38,50 H62" />
          <path d="M38,55 H62" />
          <circle cx="50" cy="50" r="8" strokeDasharray="3 2" />
        </g>
      )}

      {variant === 'map' && (
        <g stroke={primary} strokeWidth="2" fill="none" strokeLinecap="round">
          <circle cx="42" cy="45" r="5" />
          <circle cx="58" cy="55" r="5" />
          <path d="M47,45 L53,55" />
          <path d="M42,50 L42,60" strokeDasharray="2 2" />
        </g>
      )}

      {variant === 'link' && (
        <g stroke={primary} strokeWidth="2" fill="none" strokeLinecap="round">
          <circle cx="42" cy="50" r="6" />
          <circle cx="58" cy="50" r="6" />
          <path d="M48,50 H52" />
          <path d="M36,50 H32" />
          <path d="M64,50 H68" />
        </g>
      )}

      {variant === 'default' && (
        <g stroke={primary} strokeWidth="2" fill="none" strokeLinecap="round">
          <path d="M50,40 L50,60" />
          <path d="M40,50 L60,50" />
        </g>
      )}

      {/* Decorative corner dots */}
      <circle cx="50" cy="8" r="2" fill={primary} fillOpacity="0.5" />
      <circle cx="86" cy="28" r="2" fill={primary} fillOpacity="0.5" />
      <circle cx="86" cy="72" r="2" fill={primary} fillOpacity="0.5" />
      <circle cx="50" cy="92" r="2" fill={primary} fillOpacity="0.5" />
      <circle cx="14" cy="72" r="2" fill={primary} fillOpacity="0.5" />
      <circle cx="14" cy="28" r="2" fill={primary} fillOpacity="0.5" />
    </svg>
  );
}
