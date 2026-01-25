import { useParams, Link } from 'react-router-dom';
import { RuleDetail } from '../components/RuleDetail';
import { useDetection } from '../hooks/useDetections';

export function DetectionDetail() {
  const { id } = useParams<{ id: string }>();
  const { data: detection, isLoading, error } = useDetection(id || '');

  if (isLoading) {
    return (
      <div className="text-center py-8">
        <div className="animate-spin h-8 w-8 border-4 border-cyan-500 border-t-transparent rounded-full mx-auto"></div>
        <p className="mt-2 text-gray-400">Loading detection...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-500/20 text-red-400 border border-red-500/30 p-4 rounded-lg">
        Error loading detection: {error.message}
      </div>
    );
  }

  if (!detection) {
    return (
      <div className="text-center py-8">
        <p className="text-gray-400">Detection not found</p>
        <Link to="/detections" className="text-cyan-400 hover:text-cyan-300 hover:underline mt-2 inline-block">
          Back to list
        </Link>
      </div>
    );
  }

  return (
    <div>
      <div className="mb-4">
        <Link
          to="/detections"
          className="text-cyan-400 hover:text-cyan-300 hover:underline flex items-center gap-1"
        >
          <span>&larr;</span> Back to list
        </Link>
      </div>

      <RuleDetail detection={detection} />

      {/* Related detections suggestion */}
      {detection.mitre_techniques.length > 0 && (
        <div className="mt-6 bg-cyber-850 rounded-lg border border-cyber-700 p-4">
          <h3 className="font-semibold text-white mb-2">Find Related Detections</h3>
          <div className="flex flex-wrap gap-2">
            {detection.mitre_techniques.slice(0, 5).map((tech) => (
              <Link
                key={tech}
                to={`/compare?technique=${tech}`}
                className="px-3 py-1 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-full text-sm hover:bg-cyan-500/30 transition-colors"
              >
                Compare {tech} across vendors
              </Link>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
