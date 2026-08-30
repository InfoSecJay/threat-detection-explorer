import { Link, useLocation } from 'react-router-dom';
import { useDocumentMeta } from '../hooks/useDocumentMeta';
import { clipMd } from '../constants/style';

export function NotFound() {
  const { pathname } = useLocation();
  useDocumentMeta('Not found');
  return (
    <div className="max-w-2xl mx-auto py-16" data-testid="not-found">
      <div className="bg-void-850 border border-void-700 p-8" style={clipMd}>
        <div className="text-[10px] font-mono text-breach-400 uppercase tracking-[0.25em] mb-3">404 · no such page</div>
        <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">Nothing at <span className="font-mono text-matrix-400 normal-case">{pathname}</span></h1>
        <p className="text-sm text-gray-400 mt-3">
          Rule, technique and actor pages are addressed by id; if you followed a link from a digest or an export, the rule may have been removed upstream.
        </p>
        <ul className="mt-6 flex flex-wrap gap-x-6 gap-y-2 text-xs font-mono uppercase tracking-wider">
          <li><Link to="/detections" className="text-matrix-500 hover:text-matrix-400">Search the catalog</Link></li>
          <li><Link to="/mitre" className="text-matrix-500 hover:text-matrix-400">Browse ATT&amp;CK</Link></li>
          <li><Link to="/actors" className="text-matrix-500 hover:text-matrix-400">Threat actors</Link></li>
          <li><Link to="/" className="text-gray-400 hover:text-white">Home</Link></li>
        </ul>
      </div>
    </div>
  );
}
