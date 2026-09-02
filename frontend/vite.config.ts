/// <reference types="vitest" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'
import { execSync } from 'child_process'

// Version shown in the header/footer must move with deploys (teardown R25).
// Vercel builds from a shallow clone, so fall back to its commit env var.
function buildVersion(): string {
  try {
    return execSync('git describe --tags --always --dirty', { stdio: ['ignore', 'pipe', 'ignore'] })
      .toString()
      .trim()
  } catch {
    const sha = process.env.VERCEL_GIT_COMMIT_SHA
    return sha ? sha.slice(0, 8) : 'dev'
  }
}

/** Headline numbers baked into the bundle at build time (teardown F07 /
 * #82 S2.7) so the home page's first paint shows real counts instead of
 * dashes while the live queries are in flight. The live values replace
 * them as soon as they arrive; the corpus moves by tens of rules a day,
 * so a snapshot from the last deploy is close, never fabricated.
 *
 * Production builds only. Any failure (no network in CI, API down)
 * yields `null` and the page falls back to its pending state -- a
 * build must never fail because the API blinked. */
type BakedSnapshot = {
  rules: number
  coverage: { covered: number; total: number; percent: number }
  last_sync: string | null
  baked_at: string
}

async function bakeSnapshot(): Promise<BakedSnapshot | null> {
  const base = (process.env.SNAPSHOT_API_URL || 'https://detectionexplorer.io/api').replace(/\/$/, '')
  const get = async (p: string) => {
    const res = await fetch(`${base}${p}`, { signal: AbortSignal.timeout(8000) })
    if (!res.ok) throw new Error(`${p}: ${res.status}`)
    return res.json()
  }
  try {
    const [stats, coverage, repos] = await Promise.all([
      get('/detections/statistics'),
      get('/compare/coverage-matrix?include_subtechniques=false'),
      get('/repositories'),
    ])
    const s = coverage.summary
    const lastSync = (repos as { last_sync_at?: string | null }[])
      .map((r) => r.last_sync_at)
      .filter((d): d is string => !!d)
      .sort()
      .pop()
    const snap: BakedSnapshot = {
      rules: Number(stats.total),
      coverage: {
        covered: Number(s.techniques_with_any_coverage),
        total: Number(s.total_techniques),
        percent: Number(s.overall_coverage_percent),
      },
      last_sync: lastSync ?? null,
      baked_at: new Date().toISOString(),
    }
    if (!Number.isFinite(snap.rules) || !Number.isFinite(snap.coverage.total)) throw new Error('bad shape')
    console.log(`[snapshot] baked ${snap.rules} rules, ${snap.coverage.covered}/${snap.coverage.total} techniques`)
    return snap
  } catch (err) {
    console.warn(`[snapshot] not baked (${(err as Error).message}); first paint will show placeholders`)
    return null
  }
}

export default defineConfig(async ({ command, mode }) => ({
  plugins: [react()],
  define: {
    __APP_VERSION__: JSON.stringify(buildVersion()),
    __DE_SNAPSHOT__: JSON.stringify(
      command === 'build' && mode === 'production' ? await bakeSnapshot() : null,
    ),
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    css: false,
  },
}))
