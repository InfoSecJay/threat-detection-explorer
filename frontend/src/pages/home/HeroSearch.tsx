/**
 * Home hero: the query bar is the page's first control, not a link to
 * one. Example chips are real queries that show the field syntax at a
 * glance; each opens the catalog with that query applied.
 */

import { useNavigate } from 'react-router-dom';
import { SearchBar } from '../../components/SearchBar';
import { clipSm } from '../../constants/style';

const EXAMPLES: { q: string; label: string }[] = [
  { q: 'actor:APT29 severity:high', label: 'actor:APT29 severity:high' },
  { q: 'process:mimikatz', label: 'process:mimikatz' },
  { q: 'quality:>=80 platform:windows', label: 'quality:>=80 platform:windows' },
  { q: 'eventid:4104 source:splunk', label: 'eventid:4104 source:splunk' },
  { q: 'tech:T1566 NOT source:sigma', label: 'tech:T1566 NOT source:sigma' },
];

export function HeroSearch() {
  const navigate = useNavigate();
  const open = (q: string) => navigate(`/detections?q=${encodeURIComponent(q)}`);

  return (
    <div className="space-y-3">
      <SearchBar value="" onSubmit={(q) => (q.trim() ? open(q.trim()) : navigate('/detections'))} />
      <div className="flex items-center gap-1.5 flex-wrap" aria-label="Example queries">
        <span className="text-[10px] font-mono text-gray-600 uppercase tracking-wider mr-1">try:</span>
        {EXAMPLES.map((e) => (
          <button
            key={e.q}
            type="button"
            onClick={() => open(e.q)}
            className="px-2 py-0.5 text-[11px] font-mono text-gray-400 bg-void-900 border border-void-700 hover:text-matrix-400 hover:border-matrix-500/40 transition-colors"
            style={clipSm}
          >
            {e.label}
          </button>
        ))}
      </div>
    </div>
  );
}
