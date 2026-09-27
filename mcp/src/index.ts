#!/usr/bin/env node
// Detection Explorer MCP server over stdio.
//
//   npx -y detection-explorer-mcp
//
// DETECTION_EXPLORER_API_URL points it at another deployment (default
// https://detectionexplorer.io/api/v1). stdout carries the protocol, so
// diagnostics go to stderr only.

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { DetectionExplorerClient } from "./client.js";
import { createServer } from "./server.js";
import { VERSION } from "./version.js";

async function main(): Promise<void> {
  const client = new DetectionExplorerClient({ baseUrl: process.env.DETECTION_EXPLORER_API_URL });
  const server = createServer(client);
  await server.connect(new StdioServerTransport());
  console.error(`detection-explorer-mcp ${VERSION} ready (API ${client.baseUrl})`);
}

main().catch((error) => {
  console.error("detection-explorer-mcp failed to start:", error);
  process.exit(1);
});
