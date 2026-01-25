/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Primary dark backgrounds
        cyber: {
          950: '#030712',
          900: '#0f172a',
          850: '#111827',
          800: '#1e293b',
          700: '#334155',
          600: '#475569',
        },
      },
      backgroundImage: {
        'hero-gradient': 'linear-gradient(180deg, rgba(6,182,212,0.1) 0%, rgba(59,130,246,0.05) 50%, transparent 100%)',
        'card-gradient': 'linear-gradient(135deg, rgba(6,182,212,0.05) 0%, rgba(59,130,246,0.05) 100%)',
      },
      boxShadow: {
        'glow-cyan': '0 0 20px rgba(34, 211, 238, 0.15)',
        'glow-blue': '0 0 20px rgba(59, 130, 246, 0.15)',
      },
    },
  },
  plugins: [],
}
