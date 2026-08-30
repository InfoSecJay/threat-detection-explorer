/**
 * Home hero: the query bar is the page's first control, not a link to
 * one. Example chips are real queries that show the field syntax at a
 * glance; each opens the catalog with that query applied.
 */

import { useNavigate } from 'react-router-dom';
import { SearchBar } from '../../components/SearchBar';
import { clipSm } from '../../constants/style';

// Each example has to sell: a real question with a real answer set
// behind it (counts checked against production, 2026-08-29).
const EXAMPLES: { q: string; label: string; hint: string }[] = [
  { q: 'actor:"Salt Typhoon"', label: 'actor:"Salt Typhoon"', hint: 'every rule written for Salt Typhoon (G1045): ID tag, analytic story, or title' },
  { q: 'tech:T1219', label: 'tech:T1219', hint: 'remote access software -- AnyDesk, ScreenConnect, TeamViewer and 300+ RMM tools' },
  { q: 'tech:T1003.001 platform:windows', label: 'tech:T1003.001 platform:windows', hint: 'LSASS memory dumping on Windows, every vendor' },
  { q: 'usecase:Ransomware severity:high', label: 'usecase:Ransomware severity:high', hint: 'high-severity rules in a Ransomware analytic story' },
  { q: 'eventid:4104 source:splunk', label: 'eventid:4104 source:splunk', hint: 'Splunk rules keyed on PowerShell script-block logging' },
  { q: 'process:certutil.exe', label: 'process:certutil.exe', hint: 'rules that name certutil.exe in their logic' },
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
            title={e.hint}
          >
            {e.label}
          </button>
        ))}
      </div>
    </div>
  );
}
