// Original SVG radar graphic for the hero section
export function ThreatRadar({ className = '' }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 400 400"
      className={`${className}`}
      xmlns="http://www.w3.org/2000/svg"
    >
      <defs>
        {/* Gradients */}
        <radialGradient id="radarGlow" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#00ffcc" stopOpacity="0.3" />
          <stop offset="50%" stopColor="#00ffcc" stopOpacity="0.1" />
          <stop offset="100%" stopColor="#00ffcc" stopOpacity="0" />
        </radialGradient>

        <linearGradient id="sweepGradient" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#00ffcc" stopOpacity="0" />
          <stop offset="50%" stopColor="#00ffcc" stopOpacity="0.4" />
          <stop offset="100%" stopColor="#00ffcc" stopOpacity="0" />
        </linearGradient>

        {/* Filters */}
        <filter id="glow">
          <feGaussianBlur stdDeviation="2" result="coloredBlur"/>
          <feMerge>
            <feMergeNode in="coloredBlur"/>
            <feMergeNode in="SourceGraphic"/>
          </feMerge>
        </filter>
      </defs>

      {/* Background glow */}
      <circle cx="200" cy="200" r="180" fill="url(#radarGlow)" />

      {/* Concentric circles */}
      {[180, 140, 100, 60].map((r, i) => (
        <circle
          key={r}
          cx="200"
          cy="200"
          r={r}
          fill="none"
          stroke="#00ffcc"
          strokeWidth="1"
          strokeOpacity={0.2 - i * 0.03}
          strokeDasharray={i % 2 === 0 ? "none" : "4 4"}
        />
      ))}

      {/* Cross-hairs */}
      <line x1="200" y1="20" x2="200" y2="380" stroke="#00ffcc" strokeWidth="1" strokeOpacity="0.15" />
      <line x1="20" y1="200" x2="380" y2="200" stroke="#00ffcc" strokeWidth="1" strokeOpacity="0.15" />
      <line x1="60" y1="60" x2="340" y2="340" stroke="#00ffcc" strokeWidth="1" strokeOpacity="0.1" />
      <line x1="340" y1="60" x2="60" y2="340" stroke="#00ffcc" strokeWidth="1" strokeOpacity="0.1" />

      {/* Radar sweep animation */}
      <g className="animate-radar" style={{ transformOrigin: '200px 200px' }}>
        <path
          d="M200,200 L200,20 A180,180 0 0,1 350,200 Z"
          fill="url(#sweepGradient)"
          opacity="0.5"
        />
      </g>

      {/* Threat blips */}
      <g filter="url(#glow)">
        {/* Critical threat */}
        <circle cx="280" cy="120" r="6" fill="#ff0040" className="animate-pulse">
          <animate attributeName="opacity" values="1;0.5;1" dur="1.5s" repeatCount="indefinite" />
        </circle>

        {/* High threats */}
        <circle cx="150" cy="280" r="5" fill="#ff9500" className="animate-pulse">
          <animate attributeName="opacity" values="1;0.5;1" dur="2s" repeatCount="indefinite" />
        </circle>
        <circle cx="310" cy="250" r="5" fill="#ff9500">
          <animate attributeName="opacity" values="1;0.5;1" dur="1.8s" repeatCount="indefinite" />
        </circle>

        {/* Medium threats */}
        <circle cx="100" cy="150" r="4" fill="#fbbf24">
          <animate attributeName="opacity" values="1;0.3;1" dur="2.2s" repeatCount="indefinite" />
        </circle>
        <circle cx="240" cy="300" r="4" fill="#fbbf24">
          <animate attributeName="opacity" values="1;0.3;1" dur="2.5s" repeatCount="indefinite" />
        </circle>

        {/* Low threats (green = detected/resolved) */}
        <circle cx="180" cy="180" r="3" fill="#00ff41">
          <animate attributeName="opacity" values="0.8;0.4;0.8" dur="3s" repeatCount="indefinite" />
        </circle>
        <circle cx="260" cy="180" r="3" fill="#00ff41">
          <animate attributeName="opacity" values="0.8;0.4;0.8" dur="2.8s" repeatCount="indefinite" />
        </circle>
      </g>

      {/* Center marker */}
      <circle cx="200" cy="200" r="4" fill="#00ffcc" filter="url(#glow)" />
      <circle cx="200" cy="200" r="8" fill="none" stroke="#00ffcc" strokeWidth="2" strokeOpacity="0.5" />

      {/* Corner decorations */}
      <path d="M30,30 L30,60 M30,30 L60,30" stroke="#00ffcc" strokeWidth="2" strokeOpacity="0.4" fill="none" />
      <path d="M370,30 L370,60 M370,30 L340,30" stroke="#00ffcc" strokeWidth="2" strokeOpacity="0.4" fill="none" />
      <path d="M30,370 L30,340 M30,370 L60,370" stroke="#00ffcc" strokeWidth="2" strokeOpacity="0.4" fill="none" />
      <path d="M370,370 L370,340 M370,370 L340,370" stroke="#00ffcc" strokeWidth="2" strokeOpacity="0.4" fill="none" />

      {/* Coordinate labels */}
      <text x="200" y="15" fill="#00ffcc" fontSize="10" textAnchor="middle" fontFamily="monospace" opacity="0.5">N</text>
      <text x="200" y="395" fill="#00ffcc" fontSize="10" textAnchor="middle" fontFamily="monospace" opacity="0.5">S</text>
      <text x="10" y="205" fill="#00ffcc" fontSize="10" textAnchor="middle" fontFamily="monospace" opacity="0.5">W</text>
      <text x="390" y="205" fill="#00ffcc" fontSize="10" textAnchor="middle" fontFamily="monospace" opacity="0.5">E</text>
    </svg>
  );
}
