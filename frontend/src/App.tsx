import { useState, useRef, useEffect, lazy, Suspense } from 'react';
import { Routes, Route, Link, Navigate, useLocation } from 'react-router-dom';
import { clipSm } from './constants/style';
import { ALL_SOURCES } from './constants/sources';
import { RouteErrorBoundary } from './components/RouteErrorBoundary';

// Route-level code splitting. Each page becomes its own chunk so the
// initial bundle only ships shared shell + the page the user lands on.
// Vite emits a separate JS file per lazy() target. Keep Home eager —
// it's the most common entry point and avoiding the loading flash on
// landing matters more than shaving a few KB off the first chunk.
import { Home } from './pages/Home';
const DetectionList   = lazy(() => import('./pages/DetectionList').then(m => ({ default: m.DetectionList })));
const DetectionDetail = lazy(() => import('./pages/DetectionDetail').then(m => ({ default: m.DetectionDetail })));
const MitreCoverage   = lazy(() => import('./pages/MitreCoverage').then(m => ({ default: m.MitreCoverage })));
const Actors          = lazy(() => import('./pages/Actors').then(m => ({ default: m.Actors })));
const ActorDetail     = lazy(() => import('./pages/ActorDetail').then(m => ({ default: m.ActorDetail })));
const QueryReference  = lazy(() => import('./pages/QueryReference').then(m => ({ default: m.QueryReference })));
const About           = lazy(() => import('./pages/About').then(m => ({ default: m.About })));
const Digest          = lazy(() => import('./pages/Digest').then(m => ({ default: m.Digest })));
const Observables     = lazy(() => import('./pages/Observables').then(m => ({ default: m.Observables })));
const ObservableDetail = lazy(() => import('./pages/ObservableDetail').then(m => ({ default: m.ObservableDetail })));
const CoverageHeatmap = lazy(() => import('./pages/actors/CoverageHeatmap').then(m => ({ default: m.CoverageHeatmap })));
const DataSourceHeatmap = lazy(() => import('./pages/mitre/DataSourceHeatmap').then(m => ({ default: m.DataSourceHeatmap })));
const NotFound = lazy(() => import('./pages/NotFound').then(m => ({ default: m.NotFound })));
const Methodology = lazy(() => import('./pages/Methodology').then(m => ({ default: m.Methodology })));
const Unclassified = lazy(() => import('./pages/Unclassified').then(m => ({ default: m.Unclassified })));
const CorpusHealth = lazy(() => import('./pages/CorpusHealth').then(m => ({ default: m.CorpusHealth })));
// The old Compare / SideBySide pages were removed (#48); the rebuild as
// an observable-level diff is tracked in #11. Their routes below still
// redirect so old links do not 404.
const IndustryIntel     = lazy(() => import('./pages/IndustryIntel').then(m => ({ default: m.IndustryIntel })));

// Hover intent on the nav fetches the route's chunk before the click
// (dynamic imports are memoised by the bundler, so this is idempotent).
const ROUTE_LOADERS: Record<string, () => Promise<unknown>> = {
  '/detections': () => import('./pages/DetectionList'),
  '/mitre': () => import('./pages/MitreCoverage'),
  '/actors': () => import('./pages/Actors'),
  '/observables': () => import('./pages/Observables'),
  '/intel': () => import('./pages/IndustryIntel'),
  '/digest': () => import('./pages/Digest'),
  '/query': () => import('./pages/QueryReference'),
  '/about': () => import('./pages/About'),
  '/methodology': () => import('./pages/Methodology'),
  '/methodology/unclassified': () => import('./pages/Unclassified'),
  '/methodology/corpus-health': () => import('./pages/CorpusHealth'),
};
// Swallow prefetch failures: a hover on a link right after a deploy can
// 404 the old chunk. The real navigation is covered by the route error
// boundary; an unhandled rejection here would just be console noise.
const prefetchRoute = (to: string) => { void ROUTE_LOADERS[to]?.().catch(() => {}); };

// Lightweight loading state shown while a lazy route's chunk fetches.
// Plain pulse — kept minimal so the layout doesn't shift.
function RouteFallback() {
  return (
    <div className="flex items-center justify-center py-20">
      <div className="text-xs font-mono text-gray-500 animate-pulse">LOADING_MODULE…</div>
    </div>
  );
}

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
      onMouseEnter={() => prefetchRoute(to)}
      onFocus={() => prefetchRoute(to)}
      className={`relative px-4 py-2 font-display text-sm uppercase tracking-wider transition-all duration-300 ${
        isActive
          ? 'text-matrix-500 bg-matrix-500/10 border border-matrix-500/30'
          : 'text-gray-400 hover:text-matrix-400 hover:bg-void-800 border border-transparent'
      }`}
      style={clipSm}
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
        style={clipSm}
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
          style={clipSm}
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
          <span className="text-matrix-500">DETECTION</span>
          <span className="text-white ml-1">EXPLORER</span>
        </div>
        <div className="text-[10px] font-mono text-gray-500 tracking-widest">
          OPEN DETECTION RULES // {__APP_VERSION__}
        </div>
      </div>
    </Link>
  );
}

// Mobile navigation drawer (teardown F04 / #78): below md the nav row
// is hidden and every destination lives here. Closes on route change.
const MOBILE_NAV: { to: string; label: string }[] = [
  { to: '/', label: 'Home' },
  { to: '/detections', label: 'Detections' },
  { to: '/mitre', label: 'MITRE' },
  { to: '/actors', label: 'Actors' },
  { to: '/observables', label: 'Observables' },
  { to: '/intel', label: 'Intel' },
  { to: '/digest', label: 'Digest' },
  { to: '/methodology', label: 'Methodology' },
  { to: '/query', label: 'Query Reference' },
  { to: '/about', label: 'About' },
];

function MobileMenu() {
  const [open, setOpen] = useState(false);
  const location = useLocation();

  useEffect(() => {
    setOpen(false);
  }, [location.pathname]);

  return (
    <div className="md:hidden">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-label={open ? 'Close navigation' : 'Open navigation'}
        data-testid="mobile-menu-button"
        className="p-2 text-gray-300 hover:text-matrix-400 border border-void-700 hover:border-void-600"
        style={clipSm}
      >
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
          {open ? (
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          ) : (
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
          )}
        </svg>
      </button>
      {open && (
        <div
          className="absolute left-0 right-0 top-full bg-void-900 border-b border-void-700 shadow-xl z-50"
          data-testid="mobile-menu"
        >
          <div className="px-4 py-2 grid grid-cols-2 gap-1">
            {MOBILE_NAV.map((item) => {
              const active = item.to === '/'
                ? location.pathname === '/'
                : location.pathname === item.to || location.pathname.startsWith(item.to + '/');
              return (
                <Link
                  key={item.to}
                  to={item.to}
                  className={`px-3 py-2.5 font-display text-sm uppercase tracking-wider ${
                    active ? 'text-matrix-500 bg-matrix-500/10' : 'text-gray-300 hover:text-matrix-400 hover:bg-void-800'
                  }`}
                >
                  {item.label}
                </Link>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

function App() {
  // Keying the error boundary on the path lets a navigation away from a
  // crashed page reset it instead of trapping the whole session.
  const location = useLocation();
  return (
    <div className="min-h-screen bg-void-950 flex flex-col">
      {/* Skip link (teardown R24): eight nav items precede the content. */}
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:z-[60] focus:top-2 focus:left-2 focus:bg-void-900 focus:text-matrix-400 focus:px-3 focus:py-2 focus:border focus:border-matrix-500 focus:text-sm focus:font-mono"
      >
        Skip to content
      </a>
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
          <UtcClock />
        </div>
      </div>

      {/* Main navigation */}
      <nav className="bg-void-900/50 backdrop-blur-sm border-b border-void-700 sticky top-0 z-50">
        <div className="max-w-[1800px] mx-auto px-4 py-3">
          <div className="flex items-center justify-between">
            <Logo />

            {/* Navigation links. Comparison temporarily hidden pending
                rework — see docs/roadmap.md. Below md the row collapses
                into the drawer (teardown F04: five of eight items were
                simply unreachable on phones). */}
            <div className="hidden md:flex items-center gap-1">
              <NavLink to="/">Home</NavLink>
              <NavLink to="/detections">Detections</NavLink>
              <NavLink to="/mitre">MITRE</NavLink>
              <NavLink to="/actors">Actors</NavLink>
              <NavLink to="/observables">Observables</NavLink>
              <NavLink to="/intel">Intel</NavLink>
              <NavLink to="/digest">Digest</NavLink>
              <NavDropdown
                label="Resources"
                items={[
                  { to: '/methodology', label: 'Methodology' },
                  { to: '/query', label: 'Query Reference' },
                  { to: '/about', label: 'About' },
                ]}
              />
            </div>

            {/* Quick stats badge */}
            <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 bg-void-800 border border-void-600 rounded">
              <span className="w-2 h-2 bg-matrix-500 rounded-full animate-pulse" />
              <span className="text-xs font-mono text-gray-400">
                <span className="text-matrix-400">{ALL_SOURCES.length}</span> SOURCES ACTIVE
              </span>
            </div>

            <MobileMenu />
          </div>
        </div>
      </nav>

      {/* Main content */}
      <main id="main" className="flex-1 max-w-[1800px] w-full mx-auto px-4 py-6">
        <RouteErrorBoundary key={location.pathname}>
        <Suspense fallback={<RouteFallback />}>
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/detections" element={<DetectionList />} />
            <Route path="/detections/:id" element={<DetectionDetail />} />
            <Route path="/mitre" element={<MitreCoverage />} />
            <Route path="/mitre/heatmap" element={<DataSourceHeatmap />} />
            <Route path="/mitre/:techniqueId" element={<MitreCoverage />} />
            <Route path="/actors" element={<Actors />} />
            <Route path="/actors/heatmap" element={<CoverageHeatmap />} />
            <Route path="/actors/:id" element={<ActorDetail />} />
            <Route path="/query" element={<QueryReference />} />
            {/* Old /compare/mitre-coverage bookmarks still redirect to /mitre. */}
            <Route path="/compare/mitre-coverage" element={<Navigate to="/mitre" replace />} />
            <Route path="/intel" element={<IndustryIntel />} />
            {/* Temporarily hidden pages — redirect to home so existing
                bookmarks don't 404. Restore routes when the pages are
                reworked (tracked in docs/roadmap.md). */}
            <Route path="/compare" element={<Navigate to="/" replace />} />
            <Route path="/compare/side-by-side" element={<Navigate to="/" replace />} />
            <Route path="/about" element={<About />} />
            <Route path="/methodology" element={<Methodology />} />
            <Route path="/methodology/unclassified" element={<Unclassified />} />
            <Route path="/methodology/corpus-health" element={<CorpusHealth />} />
            {/* /integrations folded into /intel (#90 / teardown S4.3) */}
            <Route path="/integrations" element={<Navigate to="/intel" replace />} />
            <Route path="/digest" element={<Digest />} />
            <Route path="/digest/:week" element={<Digest />} />
            <Route path="/observables" element={<Observables />} />
            <Route path="/observables/:kind" element={<Observables />} />
            <Route path="/observables/:kind/*" element={<ObservableDetail />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </Suspense>
        </RouteErrorBoundary>
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
              DETECTION_EXPLORER // {__APP_VERSION__}
              <a
                href="https://github.com/InfoSecJay/threat-detection-explorer/issues/new?template=suggest-a-source.md"
                target="_blank"
                rel="noopener noreferrer"
                className="ml-4 text-matrix-500 hover:text-matrix-400 uppercase tracking-wider"
              >
                suggest a source
              </a>
              <a
                href="/api/docs"
                target="_blank"
                rel="noopener noreferrer"
                className="ml-4 text-matrix-500 hover:text-matrix-400 uppercase tracking-wider"
              >
                api docs
              </a>
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

/** Header UTC clock. Was a one-shot `new Date()` evaluated on mount,
 * so a tab left open showed a timestamp hours stale next to a
 * "SYSTEM ONLINE" indicator. Ticks once a second. */
function UtcClock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  return (
    <div className="text-xs font-mono text-gray-500">
      <span className="hidden md:inline">UTC </span>
      <span className="text-gray-400">{now.toISOString().slice(0, 19).replace('T', ' ')}</span>
    </div>
  );
}
