import { useEffect, useState } from 'react';
import { useExport } from '../hooks/useDetections';
import type { SearchFilters } from '../types';

interface ExportModalProps {
  isOpen: boolean;
  onClose: () => void;
  filters: SearchFilters;
  selectedIds?: string[];
}

export function ExportModal({ isOpen, onClose, filters, selectedIds }: ExportModalProps) {
  const [format, setFormat] = useState<'json' | 'csv' | 'navigator' | 'observables'>('json');
  const [includeRaw, setIncludeRaw] = useState(false);
  const exportMutation = useExport();

  // Escape closes, like the filter sheet. Registered only while open.
  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const handleExport = () => {
    exportMutation.mutate(
      {
        format,
        filters: selectedIds?.length ? undefined : filters,
        ids: selectedIds,
        include_raw: includeRaw,
      },
      {
        onSuccess: () => {
          onClose();
        },
      }
    );
  };

  return (
    <div
      className="fixed inset-0 bg-black/70 flex items-center justify-center z-50"
      onClick={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="export-modal-title"
        className="bg-void-850 rounded-lg border border-void-700 shadow-xl p-6 w-full max-w-md"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 id="export-modal-title" className="text-xl font-bold text-white mb-4">Export Detections</h2>

        <div className="space-y-4">
          {/* Format selection */}
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">
              Export Format
            </label>
            <div className="flex gap-4">
              <label className="flex items-center text-gray-300 cursor-pointer">
                <input
                  type="radio"
                  name="format"
                  value="json"
                  checked={format === 'json'}
                  onChange={() => setFormat('json')}
                  className="mr-2 text-cyan-500 bg-void-900 border-void-600 focus:ring-cyan-500"
                />
                JSON
              </label>
              <label className="flex items-center text-gray-300 cursor-pointer">
                <input
                  type="radio"
                  name="format"
                  value="csv"
                  checked={format === 'csv'}
                  onChange={() => setFormat('csv')}
                  className="mr-2 text-cyan-500 bg-void-900 border-void-600 focus:ring-cyan-500"
                />
                CSV
              </label>
              <label className="flex items-center text-gray-300 cursor-pointer" title="ATT&CK Navigator layer: techniques scored by how many of these rules tag them">
                <input
                  type="radio"
                  name="format"
                  value="navigator"
                  checked={format === 'navigator'}
                  onChange={() => setFormat('navigator')}
                  className="mr-2 text-cyan-500 bg-void-900 border-void-600 focus:ring-cyan-500"
                />
                Navigator layer
              </label>
              <label className="flex items-center text-gray-300 cursor-pointer" title="One CSV row per observable value: rule, type, subtype, field, value, negated">
                <input
                  type="radio"
                  name="format"
                  value="observables"
                  checked={format === 'observables'}
                  onChange={() => setFormat('observables')}
                  className="mr-2 text-cyan-500 bg-void-900 border-void-600 focus:ring-cyan-500"
                />
                Observables CSV
              </label>
            </div>
          </div>

          {/* Include raw content (not applicable to a Navigator layer) */}
          {format === 'observables' ? (
            <p className="text-xs text-gray-500">
              One row per observable value the selected rules key on -- process names, event IDs, registry keys,
              API actions, paths, indicators -- typed, with the field it came from and whether it is an exclusion.
            </p>
          ) : format === 'navigator' ? (
            <p className="text-xs text-gray-500">
              A layer file for the ATT&amp;CK Navigator: each technique scored by how many of these rules tag it,
              with the rule titles as comments. Open it at mitre-attack.github.io/attack-navigator via
              &quot;Open Existing Layer&quot;.
            </p>
          ) : (
            <div>
              <label className="flex items-center text-gray-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={includeRaw}
                  onChange={(e) => setIncludeRaw(e.target.checked)}
                  className="mr-2 rounded bg-void-900 border-void-600 text-cyan-500 focus:ring-cyan-500"
                />
                <span className="text-sm">Include raw rule content</span>
              </label>
              <p className="text-xs text-gray-500 mt-1 ml-6">
                This will significantly increase file size
              </p>
            </div>
          )}

          {/* Export scope info */}
          <div className="bg-void-900 border border-void-700 p-3 rounded-lg">
            <p className="text-sm text-gray-400">
              {selectedIds?.length
                ? `Exporting ${selectedIds.length} selected detection(s)`
                : 'Exporting all detections matching current filters'}
            </p>
          </div>
        </div>

        {/* Buttons */}
        <div className="flex justify-end gap-3 mt-6">
          <button
            onClick={onClose}
            className="px-4 py-2 text-gray-300 border border-void-700 rounded hover:bg-void-800 transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleExport}
            disabled={exportMutation.isPending}
            className="px-4 py-2 bg-gradient-to-r from-cyan-500 to-blue-500 text-white rounded hover:from-cyan-400 hover:to-blue-400 disabled:opacity-50 transition-all"
          >
            {exportMutation.isPending ? 'Exporting...' : 'Export'}
          </button>
        </div>

        {exportMutation.isError && (
          <p className="mt-3 text-sm text-red-400">
            Export failed: {exportMutation.error.message}
          </p>
        )}
      </div>
    </div>
  );
}
