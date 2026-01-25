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
            className="text-cyan-400 hover:text-cyan-300"
          >
            &larr; Back to Compare
          </Link>
        </div>
        <div className="bg-cyber-850 rounded-lg border border-cyber-700 p-8 text-center">
          <h2 className="text-xl font-bold text-white mb-2">
            Side-by-Side Comparison
          </h2>
          <p className="text-gray-400 mb-4">
            Select 2-6 detections from the{' '}
            <Link to="/detections" className="text-cyan-400 hover:text-cyan-300">
              Detections page
            </Link>{' '}
            to compare them side by side.
          </p>
          <p className="text-sm text-gray-500">
            Use the checkboxes in the detection list to select rules, then click
            "Compare Selected" to view them here.
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
            className="text-cyan-400 hover:text-cyan-300"
          >
            &larr; Back to Compare
          </Link>
        </div>
        <div className="text-center py-8">
          <div className="animate-spin h-8 w-8 border-4 border-cyan-500 border-t-transparent rounded-full mx-auto"></div>
          <p className="mt-2 text-gray-400">Loading comparison...</p>
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
            className="text-cyan-400 hover:text-cyan-300"
          >
            &larr; Back to Compare
          </Link>
        </div>
        <div className="bg-red-500/20 text-red-400 border border-red-500/30 p-4 rounded-lg">
          Error loading comparison: {(error as Error).message}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Link
          to="/compare"
          className="text-cyan-400 hover:text-cyan-300"
        >
          &larr; Back to Compare
        </Link>
        <Link
          to="/detections"
          className="text-gray-400 hover:text-white text-sm"
        >
          Select different rules
        </Link>
      </div>

      {data && <SideBySideComparison data={data} />}
    </div>
  );
}
