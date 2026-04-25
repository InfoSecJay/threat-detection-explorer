/**
 * Vitest setup file. Runs once before any test file.
 *
 * Wires `@testing-library/jest-dom` matchers (toBeInTheDocument,
 * toHaveTextContent, etc.) into vitest's `expect`, and registers an
 * `afterEach` hook to unmount any component left mounted by a test.
 */

import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

afterEach(() => {
  cleanup();
});
