/**
 * Error boundary around the routed page tree. Two jobs:
 *
 * 1. A lazy route chunk that 404s after a redeploy used to unmount the
 *    whole app to a blank page. Here it triggers one automatic reload
 *    (rate-limited in staleChunk.ts) to pick up the new deploy.
 * 2. Anything else — or a reload that didn't help — renders a visible
 *    error panel with a reload action instead of a dead white screen.
 *
 * Mounted with key={location.pathname} so navigating to another page
 * resets the boundary and gives the app a clean retry.
 */

import { Component, type ReactNode } from 'react';
import { isChunkLoadError, reloadForStaleChunk } from '../utils/staleChunk';

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
  reloading: boolean;
}

export class RouteErrorBoundary extends Component<Props, State> {
  state: State = { error: null, reloading: false };

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error };
  }

  componentDidCatch(error: Error) {
    if (isChunkLoadError(error) && reloadForStaleChunk()) {
      // Reload is on its way; keep showing the quiet loading state
      // rather than flashing the error panel first.
      this.setState({ reloading: true });
    }
  }

  render() {
    const { error, reloading } = this.state;
    if (!error) return this.props.children;
    if (reloading) {
      return (
        <div className="flex items-center justify-center py-20">
          <div className="text-xs font-mono text-gray-500 animate-pulse">RELOADING_MODULE…</div>
        </div>
      );
    }
    const stale = isChunkLoadError(error);
    return (
      <div className="flex flex-col items-center justify-center py-20 gap-4" data-testid="route-error">
        <div className="text-sm font-mono text-breach-400 uppercase tracking-wider">
          {stale ? 'MODULE_LOAD_FAILURE' : 'PAGE_RENDER_FAILURE'}
        </div>
        <p className="text-xs font-mono text-gray-500 max-w-md text-center">
          {stale
            ? 'this page could not be fetched -- usually a new version of the site was just deployed. reload to pick it up.'
            : 'this page hit an unexpected error. reloading usually fixes it; if it keeps happening, please open an issue.'}
        </p>
        <button
          onClick={() => window.location.reload()}
          className="px-4 py-2 text-xs font-mono uppercase tracking-wider text-matrix-400 border border-matrix-500/40 hover:bg-matrix-500/10 transition-colors"
        >
          [ reload ]
        </button>
      </div>
    );
  }
}
