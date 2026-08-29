// Extracted from pages/Actors.tsx (#23). Behaviour unchanged.
import { useState } from 'react';
import { actorsApi } from '../../services/api';
import { clipSm } from '../../constants/style';

export function BulkExportButton({
  params,
}: {
  params: Parameters<typeof actorsApi.downloadBulkNavigatorLayer>[0];
}) {
  const [exporting, setExporting] = useState(false);
  return (
    <button
      onClick={async () => {
        if (exporting) return;
        setExporting(true);
        try {
          await actorsApi.downloadBulkNavigatorLayer(params);
        } finally {
          setExporting(false);
        }
      }}
      disabled={exporting}
      className="text-[10px] font-mono text-cyan-400 hover:text-cyan-300 uppercase tracking-wider border border-cyan-500/30 hover:border-cyan-500/60 px-2 py-1 transition-colors disabled:opacity-50"
      style={clipSm}
      title="Download a combined ATT&CK Navigator layer for every actor matching the current filters, scored by our rule coverage"
    >
      {exporting ? '[ exporting… ]' : '[ export navigator layer ]'}
    </button>
  );
}

// ── Page ───────────────────────────────────────────────────────────
