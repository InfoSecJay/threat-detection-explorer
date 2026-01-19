import { Routes, Route, Link, useLocation } from 'react-router-dom';
import { Dashboard } from './pages/Dashboard';
import { DetectionList } from './pages/DetectionList';
import { DetectionDetail } from './pages/DetectionDetail';
import { Compare } from './pages/Compare';
import { RuleSources } from './pages/RuleSources';

function NavLink({ to, children }: { to: string; children: React.ReactNode }) {
  const location = useLocation();
  const isActive = location.pathname === to || location.pathname.startsWith(to + '/');

  return (
    <Link
      to={to}
      className={`px-4 py-2 rounded-lg transition-colors ${
        isActive
          ? 'bg-blue-100 text-blue-700 font-medium'
          : 'text-gray-600 hover:bg-gray-100'
      }`}
    >
      {children}
    </Link>
  );
}

function App() {
  return (
    <div className="min-h-screen bg-gray-50">
      {/* Navigation */}
      <nav className="bg-white shadow-sm border-b">
        <div className="max-w-[1600px] mx-auto px-4 py-3">
          <div className="flex items-center justify-between">
            <Link to="/" className="text-xl font-bold text-gray-900">
              Threat Detection Explorer
            </Link>
            <div className="flex items-center gap-2">
              <NavLink to="/">Dashboard</NavLink>
              <NavLink to="/detections">Detections</NavLink>
              <NavLink to="/compare">Compare</NavLink>
              <NavLink to="/sources">Sources</NavLink>
            </div>
          </div>
        </div>
      </nav>

      {/* Main content */}
      <main className="max-w-[1600px] mx-auto px-4 py-8">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/detections" element={<DetectionList />} />
          <Route path="/detections/:id" element={<DetectionDetail />} />
          <Route path="/compare" element={<Compare />} />
          <Route path="/sources" element={<RuleSources />} />
        </Routes>
      </main>

      {/* Footer */}
      <footer className="bg-white border-t mt-12 py-6">
        <div className="max-w-[1600px] mx-auto px-4 text-center text-gray-500 text-sm">
          <p>
            Threat Detection Explorer - Comparing detection rules from{' '}
            <a href="https://github.com/SigmaHQ/sigma" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">SigmaHQ</a>,{' '}
            <a href="https://github.com/elastic/detection-rules" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">Elastic</a>,{' '}
            <a href="https://github.com/splunk/security_content" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">Splunk</a>,{' '}
            <a href="https://github.com/sublime-security/sublime-rules" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">Sublime</a>,{' '}
            <a href="https://github.com/elastic/protections-artifacts" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">Elastic Protections</a>, and{' '}
            <a href="https://github.com/magicsword-io/LOLRMM" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">LOLRMM</a>
          </p>
        </div>
      </footer>
    </div>
  );
}

export default App;
