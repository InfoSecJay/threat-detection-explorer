import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
// The tool table is checked against the MCP server's registerTool calls
// by mcp/test/site-copies.test.ts (Vite will not import files outside
// frontend/, and the frontend has no Node types to read them).

vi.mock('../../hooks/useDetections', () => ({
  useStatistics: () => ({ data: { total: 15807 } }),
}));

import { McpServer } from '../McpServer';
import { CLIENTS, MCP_PACKAGE, TOOLS, WORKFLOWS } from '../mcp/content';

describe('McpServer page', () => {
  it('every workflow names only tools from the table', () => {
    const names = TOOLS.map((t) => t.name);
    expect(new Set(names).size).toBe(names.length);
    for (const w of WORKFLOWS) {
      for (const tool of w.tools) expect(names, `${w.title} -> ${tool}`).toContain(tool);
    }
  });

  it('every install snippet runs the published package', () => {
    expect(MCP_PACKAGE).toBe('detection-explorer-mcp');
    for (const c of CLIENTS) expect(c.code, c.name).toContain('npx');
    for (const c of CLIENTS) expect(c.code, c.name).toContain(MCP_PACKAGE);
  });

  it('renders install, prompts, differences and tools with the live rule count', () => {
    render(
      <MemoryRouter>
        <McpServer />
      </MemoryRouter>,
    );
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('MCP Server');
    for (const heading of ['Install', 'What you can ask', 'Why this server', 'Tools', 'Notes']) {
      expect(screen.getByRole('heading', { level: 2, name: heading })).toBeInTheDocument();
    }
    expect(screen.getAllByText(/15,807/).length).toBeGreaterThan(0);
    expect(screen.getByText(/claude mcp add detection-explorer -- npx -y detection-explorer-mcp/)).toBeInTheDocument();
    expect(screen.getAllByRole('row')).toHaveLength(TOOLS.length + 1);
    expect(document.title).toContain('MCP server');
  });
});
