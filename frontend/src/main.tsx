import React from 'react'
import ReactDOM from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router-dom'
import { Analytics } from '@vercel/analytics/react'
import App from './App'
import { MitreProvider } from './contexts/MitreContext'
import { reloadForStaleChunk } from './utils/staleChunk'
import './index.css'

// Vite reports failed module/CSS preloads (typically hashed chunks that
// vanished with a redeploy) via this event. Reload once to pick up the
// fresh manifest; without preventDefault the import would reject and
// blank the page instead.
window.addEventListener('vite:preloadError', (event) => {
  if (reloadForStaleChunk()) event.preventDefault()
})

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000, // 5 minutes
      retry: 1,
    },
  },
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      {/* v7_startTransition: route changes render inside a React
          transition, so the current page stays visible while a lazy
          route's chunk downloads instead of the whole page being
          swapped for the Suspense fallback (the "flicker"). */}
      <BrowserRouter future={{ v7_startTransition: true }}>
        <MitreProvider>
          <App />
        </MitreProvider>
      </BrowserRouter>
      {/* Vercel Web Analytics: cookieless page-view beacon to /_vercel/insights;
          Jay enabled it 2026-09-10 (reverses the 08-31 skip decision on #96). */}
      <Analytics />
    </QueryClientProvider>
  </React.StrictMode>,
)
