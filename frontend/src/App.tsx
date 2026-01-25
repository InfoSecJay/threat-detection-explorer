import { Routes, Route, Link, useLocation } from 'react-router-dom';
import { Home } from './pages/Home';
import { DetectionList } from './pages/DetectionList';
import { DetectionDetail } from './pages/DetectionDetail';
import { Compare } from './pages/Compare';
import { SideBySide } from './pages/SideBySide';

function NavLink({ to, children }: { to: string; children: React.ReactNode }) {
  const location = useLocation();
  const isActive = to === '/'
    ? location.pathname === '/'
    : location.pathname === to || location.pathname.startsWith(to + '/');

  return (
    <Link
      to={to}
      className={`px-4 py-2 rounded-lg transition-all ${
        isActive
          ? 'bg-cyan-500/20 text-cyan-400 font-medium border border-cyan-500/30'
          : 'text-gray-400 hover:text-cyan-400 hover:bg-cyber-800'
      }`}
    >
      {children}
    </Link>
  );
}

function App() {
  return (
    <div className="min-h-screen bg-cyber-950 flex flex-col">
      {/* Navigation */}
      <nav className="bg-cyber-900 border-b border-cyber-700 sticky top-0 z-50">
        <div className="max-w-[1600px] mx-auto px-4 py-3">
          <div className="flex items-center justify-between">
            <Link to="/" className="text-xl font-bold text-white hover:text-cyan-400 transition-colors">
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">
                Threat Detection
              </span>{' '}
              Explorer
            </Link>
            <div className="flex items-center gap-2">
              <NavLink to="/">Home</NavLink>
              <NavLink to="/detections">Detections</NavLink>
              <NavLink to="/compare">Compare</NavLink>
            </div>
          </div>
        </div>
      </nav>

      {/* Main content */}
      <main className="flex-1 max-w-[1600px] w-full mx-auto px-4 py-8">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/detections" element={<DetectionList />} />
          <Route path="/detections/:id" element={<DetectionDetail />} />
          <Route path="/compare" element={<Compare />} />
          <Route path="/compare/side-by-side" element={<SideBySide />} />
        </Routes>
      </main>

      {/* Footer */}
      <footer className="bg-cyber-900 border-t border-cyber-700 py-6">
        <div className="max-w-[1600px] mx-auto px-4 text-center text-gray-500 text-sm">
          <p>
            Built by{' '}
            <a
              href="https://www.linkedin.com/in/jay-tymchuk/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-cyan-500 hover:text-cyan-400 transition-colors"
            >
              Jay Tymchuk
            </a>
            {' '}&middot;{' '}
            <a
              href="https://github.com/InfoSecJay"
              target="_blank"
              rel="noopener noreferrer"
              className="text-cyan-500 hover:text-cyan-400 transition-colors"
            >
              GitHub
            </a>
          </p>
        </div>
      </footer>
    </div>
  );
}

export default App;
