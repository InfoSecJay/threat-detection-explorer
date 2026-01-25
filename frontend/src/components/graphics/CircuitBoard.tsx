// Original SVG circuit board pattern for backgrounds
export function CircuitBoard({ className = '' }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 800 600"
      className={`${className}`}
      xmlns="http://www.w3.org/2000/svg"
      preserveAspectRatio="xMidYMid slice"
    >
      <defs>
        <linearGradient id="circuitGlow" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#00ffcc" stopOpacity="0.5" />
          <stop offset="100%" stopColor="#00ff41" stopOpacity="0.3" />
        </linearGradient>

        <filter id="circuitBlur">
          <feGaussianBlur stdDeviation="1" />
        </filter>
      </defs>

      {/* Main circuit traces */}
      <g stroke="#00ffcc" strokeWidth="1" fill="none" opacity="0.15">
        {/* Horizontal traces */}
        <path d="M0,100 H200 L220,120 H400 L420,100 H600 L620,120 H800" />
        <path d="M0,200 H100 L120,220 H300 L320,200 H500 L520,220 H800" />
        <path d="M0,300 H150 L170,320 H350 L370,300 H550 L570,320 H800" />
        <path d="M0,400 H250 L270,420 H450 L470,400 H650 L670,420 H800" />
        <path d="M0,500 H180 L200,520 H380 L400,500 H580 L600,520 H800" />

        {/* Vertical traces */}
        <path d="M100,0 V150 L120,170 V350 L100,370 V600" />
        <path d="M200,0 V100 L220,120 V280 L200,300 V600" />
        <path d="M350,0 V200 L370,220 V400 L350,420 V600" />
        <path d="M500,0 V150 L520,170 V330 L500,350 V600" />
        <path d="M650,0 V250 L670,270 V450 L650,470 V600" />

        {/* Diagonal connectors */}
        <path d="M100,100 L150,150 M250,200 L300,250 M400,300 L450,350" />
        <path d="M600,100 L550,150 M500,200 L450,250 M350,300 L300,350" />
      </g>

      {/* Junction nodes */}
      <g fill="#00ffcc" opacity="0.3">
        <circle cx="100" cy="100" r="4" />
        <circle cx="200" cy="100" r="3" />
        <circle cx="400" cy="100" r="4" />
        <circle cx="600" cy="100" r="3" />

        <circle cx="100" cy="200" r="3" />
        <circle cx="300" cy="200" r="4" />
        <circle cx="500" cy="200" r="3" />

        <circle cx="150" cy="300" r="4" />
        <circle cx="350" cy="300" r="3" />
        <circle cx="550" cy="300" r="4" />

        <circle cx="250" cy="400" r="3" />
        <circle cx="450" cy="400" r="4" />
        <circle cx="650" cy="400" r="3" />

        <circle cx="180" cy="500" r="4" />
        <circle cx="380" cy="500" r="3" />
        <circle cx="580" cy="500" r="4" />
      </g>

      {/* Active data flow indicators */}
      <g fill="#00ff41" filter="url(#circuitBlur)">
        <circle cx="200" cy="100" r="2" opacity="0.8">
          <animate attributeName="cx" values="200;400;600;400;200" dur="4s" repeatCount="indefinite" />
        </circle>
        <circle cx="100" cy="300" r="2" opacity="0.8">
          <animate attributeName="cx" values="100;350;550;350;100" dur="5s" repeatCount="indefinite" />
        </circle>
        <circle cx="300" cy="200" r="2" opacity="0.8">
          <animate attributeName="cy" values="200;400;500;400;200" dur="3.5s" repeatCount="indefinite" />
        </circle>
      </g>

      {/* Component boxes */}
      <g stroke="#00ffcc" strokeWidth="1" fill="none" opacity="0.2">
        <rect x="80" y="140" width="40" height="20" rx="2" />
        <rect x="280" y="240" width="40" height="20" rx="2" />
        <rect x="480" y="340" width="40" height="20" rx="2" />
        <rect x="180" y="440" width="40" height="20" rx="2" />
        <rect x="580" y="140" width="40" height="20" rx="2" />
      </g>
    </svg>
  );
}
