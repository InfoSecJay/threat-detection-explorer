/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        'display': ['Orbitron', 'sans-serif'],
        'mono': ['JetBrains Mono', 'monospace'],
        'sans': ['Rajdhani', 'sans-serif'],
      },
      colors: {
        // Command center dark backgrounds
        void: {
          950: '#010409',
          900: '#0a0c10',
          850: '#0d1117',
          800: '#161b22',
          700: '#21262d',
          600: '#30363d',
        },
        // Primary accent - electric cyan
        matrix: {
          500: '#00ffcc',
          400: '#33ffd6',
          300: '#66ffe0',
          200: '#99ffeb',
        },
        // Secondary accent - neon green (for active/success states)
        pulse: {
          500: '#00ff41',
          400: '#33ff6d',
          300: '#66ff93',
        },
        // Warning/threat amber
        threat: {
          500: '#ff9500',
          400: '#ffaa33',
          300: '#ffbf66',
        },
        // Critical red
        breach: {
          500: '#ff0040',
          400: '#ff3366',
          300: '#ff668c',
        },
        // Source-specific colors
        sigma: '#a855f7',
        elastic: '#3b82f6',
        splunk: '#f97316',
        sublime: '#ec4899',
        protections: '#06b6d4',
        lolrmm: '#22c55e',
      },
      backgroundImage: {
        // Gradient backgrounds
        'grid-pattern': 'linear-gradient(rgba(0, 255, 204, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 255, 204, 0.03) 1px, transparent 1px)',
        'radial-glow': 'radial-gradient(ellipse at center, rgba(0, 255, 204, 0.1) 0%, transparent 70%)',
        'scan-line': 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0, 255, 204, 0.03) 2px, rgba(0, 255, 204, 0.03) 4px)',
        'hero-radial': 'radial-gradient(ellipse 80% 50% at 50% -20%, rgba(0, 255, 204, 0.15) 0%, transparent 50%)',
        'card-shine': 'linear-gradient(135deg, rgba(0, 255, 204, 0.05) 0%, transparent 50%, rgba(0, 255, 204, 0.02) 100%)',
        'circuit': 'url("data:image/svg+xml,%3Csvg width=\'60\' height=\'60\' viewBox=\'0 0 60 60\' xmlns=\'http://www.w3.org/2000/svg\'%3E%3Cpath d=\'M30 0v10M30 50v10M0 30h10M50 30h10\' stroke=\'%2300ffcc\' stroke-opacity=\'0.05\' fill=\'none\'/%3E%3C/svg%3E")',
      },
      backgroundSize: {
        'grid': '40px 40px',
      },
      boxShadow: {
        'glow': '0 0 20px rgba(0, 255, 204, 0.2)',
        'glow-lg': '0 0 40px rgba(0, 255, 204, 0.3)',
        'glow-pulse': '0 0 30px rgba(0, 255, 65, 0.25)',
        'glow-threat': '0 0 20px rgba(255, 149, 0, 0.25)',
        'glow-breach': '0 0 20px rgba(255, 0, 64, 0.25)',
        'inner-glow': 'inset 0 0 20px rgba(0, 255, 204, 0.1)',
      },
      animation: {
        'pulse-slow': 'pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scan': 'scan 8s linear infinite',
        'glow-pulse': 'glow-pulse 2s ease-in-out infinite alternate',
        'float': 'float 6s ease-in-out infinite',
        'radar': 'radar 4s linear infinite',
        'blink': 'blink 1s step-end infinite',
        'typewriter': 'typewriter 2s steps(20) forwards',
        'border-flow': 'border-flow 3s linear infinite',
      },
      keyframes: {
        scan: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        'glow-pulse': {
          '0%': { boxShadow: '0 0 20px rgba(0, 255, 204, 0.2)' },
          '100%': { boxShadow: '0 0 40px rgba(0, 255, 204, 0.4)' },
        },
        float: {
          '0%, 100%': { transform: 'translateY(0)' },
          '50%': { transform: 'translateY(-10px)' },
        },
        radar: {
          '0%': { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' },
        },
        blink: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0' },
        },
        typewriter: {
          '0%': { width: '0' },
          '100%': { width: '100%' },
        },
        'border-flow': {
          '0%': { backgroundPosition: '0% 50%' },
          '100%': { backgroundPosition: '200% 50%' },
        },
      },
      dropShadow: {
        'glow': '0 0 10px rgba(0, 255, 204, 0.5)',
        'glow-lg': '0 0 20px rgba(0, 255, 204, 0.7)',
      },
    },
  },
  plugins: [],
}
