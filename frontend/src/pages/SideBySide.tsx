import { useSearchParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { compareApi } from '../services/api';
import { SideBySideComparison } from '../components/SideBySideComparison';

export function SideBySide() {
  const [searchParams] = useSearchParams();
  const idsParam = searchParams.get('ids') || '';
  const ids = idsParam.split(',').filter((id) => id.trim());

  const { data, isLoading, error } = useQuery({
    queryKey: ['side-by-side', ids],
    queryFn: () => compareApi.sideBySide(ids),
    enabled: ids.length >= 2,
  });

  if (ids.length < 2) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <Link
            to="/compare"
            className="flex items-center gap-2 text-gray-400 hover:text-matrix-400 transition-colors font-mono text-sm"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
            </svg>
            Back to Compare
          </Link>
        </div>

        <div
          className="p-8 text-center"
          style={{
            background: 'linear-gradient(180deg, rgba(15, 23, 42, 0.95) 0%, rgba(10, 15, 30, 0.98) 100%)',
            border: '1px solid rgba(255, 255, 255, 0.05)',
            borderRadius: '2px',
          }}
        >
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-void-800 mb-4">
            <svg className="w-8 h-8 text-matrix-500/50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
            </svg>
          </div>

          <h2 className="text-xl font-display font-bold text-white mb-3 tracking-wide">
            SIDE-BY-SIDE COMPARISON
          </h2>

          <p className="text-gray-400 mb-4 max-w-md mx-auto">
            Select 2 or more detections from the{' '}
            <Link to="/detections" className="text-matrix-400 hover:text-matrix-300 hover:underline">
              Detections page
            </Link>{' '}
            to compare their detection logic side by side.
          </p>

          <p className="text-xs font-mono text-gray-600">
            Use the checkboxes to select rules, then click "COMPARE"
          </p>
        </div>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <Link
            to="/compare"
            className="flex items-center gap-2 text-gray-400 hover:text-matrix-400 transition-colors font-mono text-sm"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
            </svg>
            Back to Compare
          </Link>
        </div>

        <div className="flex flex-col items-center justify-center py-16">
          <div className="relative w-12 h-12 mb-4">
            <div className="absolute inset-0 rounded-full border-2 border-matrix-500/20"></div>
            <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-matrix-500 animate-spin"></div>
          </div>
          <p className="text-sm font-mono text-gray-500">LOADING COMPARISON...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <Link
            to="/compare"
            className="flex items-center gap-2 text-gray-400 hover:text-matrix-400 transition-colors font-mono text-sm"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
            </svg>
            Back to Compare
          </Link>
        </div>

        <div
          className="p-4 flex items-center gap-3"
          style={{
            backgroundColor: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.2)',
            borderRadius: '2px',
          }}
        >
          <svg className="w-5 h-5 text-red-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <span className="text-sm font-mono text-red-400">
            ERROR: {(error as Error).message}
          </span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Navigation */}
      <div className="flex items-center gap-6">
        <Link
          to="/compare"
          className="flex items-center gap-2 text-gray-400 hover:text-matrix-400 transition-colors font-mono text-sm"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
          </svg>
          Back to Compare
        </Link>

        <div className="h-4 w-px bg-void-700" />

        <Link
          to="/detections"
          className="flex items-center gap-2 text-gray-500 hover:text-gray-300 transition-colors font-mono text-sm"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 10h16M4 14h16M4 18h16" />
          </svg>
          Select different rules
        </Link>
      </div>

      {data && <SideBySideComparison data={data} />}
    </div>
  );
}
