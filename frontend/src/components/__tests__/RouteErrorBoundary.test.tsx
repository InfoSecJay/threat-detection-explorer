import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen } from '@testing-library/react';

const reloadForStaleChunk = vi.fn();
vi.mock('../../utils/staleChunk', async () => {
  const actual = await vi.importActual<typeof import('../../utils/staleChunk')>('../../utils/staleChunk');
  return { ...actual, reloadForStaleChunk: (...a: []) => reloadForStaleChunk(...a) };
});

import { RouteErrorBoundary } from '../RouteErrorBoundary';

function Bomb({ message }: { message: string }): never {
  throw new Error(message);
}

describe('RouteErrorBoundary', () => {
  beforeEach(() => {
    // React logs caught render errors; keep test output clean.
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });
  afterEach(() => {
    vi.restoreAllMocks();
    reloadForStaleChunk.mockReset();
  });

  it('renders children when nothing throws', () => {
    render(<RouteErrorBoundary><div>page content</div></RouteErrorBoundary>);
    expect(screen.getByText('page content')).toBeInTheDocument();
  });

  it('shows a visible error panel with a reload action instead of a blank page', () => {
    render(<RouteErrorBoundary><Bomb message="boom" /></RouteErrorBoundary>);
    expect(screen.getByTestId('route-error')).toHaveTextContent('PAGE_RENDER_FAILURE');
    expect(screen.getByRole('button', { name: /reload/i })).toBeInTheDocument();
    expect(reloadForStaleChunk).not.toHaveBeenCalled();
  });

  it('auto-reloads once when a lazy chunk fails after a redeploy', () => {
    reloadForStaleChunk.mockReturnValue(true);
    render(
      <RouteErrorBoundary>
        <Bomb message="Failed to fetch dynamically imported module: /assets/DetectionList-abc123.js" />
      </RouteErrorBoundary>,
    );
    expect(reloadForStaleChunk).toHaveBeenCalledTimes(1);
    // While the reload is in flight the quiet loading state shows, not the error panel.
    expect(screen.getByText('RELOADING_MODULE…')).toBeInTheDocument();
  });

  it('falls back to the error panel when the reload was already spent', () => {
    reloadForStaleChunk.mockReturnValue(false);
    render(
      <RouteErrorBoundary>
        <Bomb message="Importing a module script failed." />
      </RouteErrorBoundary>,
    );
    expect(screen.getByTestId('route-error')).toHaveTextContent('MODULE_LOAD_FAILURE');
  });
});
