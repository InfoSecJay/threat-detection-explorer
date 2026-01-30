import { useState, useRef, useEffect } from 'react';
import { Routes, Route, Link, useLocation } from 'react-router-dom';
import { Home } from './pages/Home';
import { DetectionList } from './pages/DetectionList';
import { DetectionDetail } from './pages/DetectionDetail';
import { Compare } from './pages/Compare';
import { SideBySide } from './pages/SideBySide';
import { MitreCoverage } from './pages/MitreCoverage';
import { IndustryIntel } from './pages/IndustryIntel';
import { About } from './pages/About';
import { ChangeLog } from './pages/ChangeLog';
import { Integrations } from './pages/Integrations';

// Status indicator component
function StatusIndicator() {
  return (
    <div className="flex items-center gap-2 text-xs font-mono">
      <span className="status-dot active bg-pulse-500" />
      <span className="text-pulse-400">SYSTEM ONLINE</span>
    </div>
  );
}

// Navigation link with tactical styling
function NavLink({ to, children }: { to: string; children: React.ReactNode }) {
  const location = useLocation();
  const isActive = to === '/'
    ? location.pathname === '/'
    : location.pathname === to || location.pathname.startsWith(to + '/');

  return (
    <Link
      to={to}
      className={`relative px-4 py-2 font-display text-sm uppercase tracking-wider transition-all duration-300 ${
        isActive
          ? 'text-matrix-500 bg-matrix-500/10 border border-matrix-500/30'
          : 'text-gray-400 hover:text-matrix-400 hover:bg-void-800 border border-transparent'
      }`}
      style={{
        clipPath: 'polygon(0 0, calc(100% - 8px) 0, 100% 8px, 100% 100%, 8px 100%, 0 calc(100% - 8px))',
      }}
    >
      {isActive && (
        <span className="absolute top-0 left-0 w-2 h-2 bg-matrix-500" />
      )}
      {children}
    </Link>
  );
}

// Dropdown menu component
function NavDropdown({ label, items }: { label: string; items: { to: string; label: string }[] }) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const location = useLocation();

  // Check if any child route is active
  const isActive = items.some(item =>
    location.pathname === item.to || location.pathname.startsWith(item.to + '/')
  );

  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Close dropdown on route change
  useEffect(() => {
    setIsOpen(false);
  }, [location.pathname]);

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={`relative px-4 py-2 font-display text-sm uppercase tracking-wider transition-all duration-300 flex items-center gap-1 ${
          isActive
            ? 'text-matrix-500 bg-matrix-500/10 border border-matrix-500/30'
            : 'text-gray-400 hover:text-matrix-400 hover:bg-void-800 border border-transparent'
        }`}
        style={{
          clipPath: 'polygon(0 0, calc(100% - 8px) 0, 100% 8px, 100% 100%, 8px 100%, 0 calc(100% - 8px))',
        }}
      >
        {isActive && (
          <span className="absolute top-0 left-0 w-2 h-2 bg-matrix-500" />
        )}
        {label}
        <svg
          className={`w-3 h-3 transition-transform ${isOpen ? 'rotate-180' : ''}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {isOpen && (
        <div
          className="absolute top-full left-0 mt-1 bg-void-900 border border-void-700 py-1 min-w-[180px] z-50"
          style={{
            clipPath: 'polygon(0 0, calc(100% - 8px) 0, 100% 8px, 100% 100%, 8px 100%, 0 calc(100% - 8px))',
          }}
        >
          {items.map((item) => {
            const itemActive = location.pathname === item.to || location.pathname.startsWith(item.to + '/');
            return (
              <Link
                key={item.to}
                to={item.to}
                className={`block px-4 py-2 text-sm font-display uppercase tracking-wider transition-colors ${
                  itemActive
                    ? 'text-matrix-500 bg-matrix-500/10'
                    : 'text-gray-400 hover:text-matrix-400 hover:bg-void-800'
                }`}
              >
                {item.label}
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}

// Logo component
function Logo() {
  return (
    <Link to="/" className="flex items-center gap-3 group">
      {/* Hexagon logo */}
      <div className="relative w-10 h-10">
        <svg viewBox="0 0 40 40" className="w-full h-full">
          <defs>
            <linearGradient id="logoGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#00ffcc" />
              <stop offset="100%" stopColor="#00ff41" />
            </linearGradient>
          </defs>
          <polygon
            points="20,2 36,11 36,29 20,38 4,29 4,11"
            fill="none"
            stroke="url(#logoGrad)"
            strokeWidth="2"
            className="group-hover:drop-shadow-glow transition-all"
          />
          <text
            x="20"
            y="24"
            textAnchor="middle"
            fill="url(#logoGrad)"
            fontSize="14"
            fontFamily="Orbitron"
            fontWeight="bold"
          >
            TD
          </text>
        </svg>
      </div>

      {/* Title */}
      <div className="hidden sm:block">
        <div className="font-display text-lg font-bold tracking-wider">
          <span className="text-matrix-500">THREAT</span>
          <span className="text-white ml-1">DETECTION</span>
        </div>
        <div className="text-[10px] font-mono text-gray-500 tracking-widest">
          EXPLORER // v1.4.0
        </div>
      </div>
    </Link>
  );
}

function App() {
  return (
    <div className="min-h-screen bg-void-950 flex flex-col">
      {/* Top status bar */}
      <div className="bg-void-900/80 border-b border-void-700 px-4 py-1">
        <div className="max-w-[1800px] mx-auto flex items-center justify-between">
          <div className="flex items-center gap-4 text-xs font-mono text-gray-500">
            <span className="hidden md:inline">
              <span className="text-gray-600">[</span>
              <span className="text-matrix-500">SYS</span>
              <span className="text-gray-600">]</span>
              {' '}DETECTION_AGGREGATOR
            </span>
          </div>
          <StatusIndicator />
          <div className="text-xs font-mono text-gray-500">
            <span className="hidden md:inline">UTC </span>
            <span className="text-gray-400">{new Date().toISOString().slice(0, 19).replace('T', ' ')}</span>
          </div>
        </div>
      </div>

      {/* Main navigation */}
      <nav className="bg-void-900/50 backdrop-blur-sm border-b border-void-700 sticky top-0 z-50">
        <div className="max-w-[1800px] mx-auto px-4 py-3">
          <div className="flex items-center justify-between">
            <Logo />

            {/* Navigation links */}
            <div className="flex items-center gap-1">
              <NavLink to="/">Home</NavLink>
              <NavLink to="/detections">Detections</NavLink>
              <NavDropdown
                label="Compare"
                items={[
                  { to: '/compare', label: 'Rule Comparison' },
                  { to: '/compare/mitre-coverage', label: 'MITRE Coverage' },
                ]}
              />
              <NavLink to="/intel">Intel</NavLink>
              <NavDropdown
                label="Resources"
                items={[
                  { to: '/about', label: 'About' },
                  { to: '/changelog', label: 'Change Log' },
                  { to: '/integrations', label: 'Integrations' },
                ]}
              />
            </div>

            {/* Quick stats badge */}
            <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 bg-void-800 border border-void-600 rounded">
              <span className="w-2 h-2 bg-matrix-500 rounded-full animate-pulse" />
              <span className="text-xs font-mono text-gray-400">
                <span className="text-matrix-400">8</span> SOURCES ACTIVE
              </span>
            </div>
          </div>
        </div>
      </nav>

      {/* Main content */}
      <main className="flex-1 max-w-[1800px] w-full mx-auto px-4 py-6">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/detections" element={<DetectionList />} />
          <Route path="/detections/:id" element={<DetectionDetail />} />
          <Route path="/compare" element={<Compare />} />
          <Route path="/compare/side-by-side" element={<SideBySide />} />
          <Route path="/compare/mitre-coverage" element={<MitreCoverage />} />
          <Route path="/intel" element={<IndustryIntel />} />
          <Route path="/about" element={<About />} />
          <Route path="/changelog" element={<ChangeLog />} />
          <Route path="/integrations" element={<Integrations />} />
        </Routes>
      </main>

      {/* Footer */}
      <footer className="bg-void-900/50 border-t border-void-700">
        <div className="max-w-[1800px] mx-auto px-4 py-6">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            {/* Left - Credits */}
            <div className="flex items-center gap-4">
              <span className="text-xs font-mono text-gray-500">
                <span className="text-gray-600">&lt;</span>
                ENGINEERED BY
                <span className="text-gray-600">&gt;</span>
              </span>
              <a
                href="https://www.linkedin.com/in/jay-tymchuk/"
                target="_blank"
                rel="noopener noreferrer"
                className="text-sm font-display text-matrix-500 hover:text-matrix-400 transition-colors link-underline"
              >
                JAY TYMCHUK
              </a>
            </div>

            {/* Center - Version */}
            <div className="text-xs font-mono text-gray-600">
              THREAT_DETECTION_EXPLORER // v1.4.0
            </div>

            {/* Right - Social links */}
            <div className="flex items-center gap-4">
              <a
                href="https://www.linkedin.com/in/jay-tymchuk/"
                target="_blank"
                rel="noopener noreferrer"
                className="text-gray-500 hover:text-matrix-500 transition-colors"
                aria-label="LinkedIn"
              >
                <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
                </svg>
              </a>
              <a
                href="https://github.com/InfoSecJay"
                target="_blank"
                rel="noopener noreferrer"
                className="text-gray-500 hover:text-matrix-500 transition-colors"
                aria-label="GitHub"
              >
                <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                  <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
                </svg>
              </a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
