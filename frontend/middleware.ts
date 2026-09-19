/** Vercel Routing Middleware (#160, DX-18): a real HTTP 404 for paths
 * the SPA cannot render.
 *
 * vercel.json's catch-all rewrite serves index.html with a 200 for
 * every URL, so /nonexistent-page-xyz was a soft 404 that crawlers
 * index and never drop. Paths outside the route table now get the
 * same shell (the client still renders the in-app not-found page)
 * with status 404 and a noindex header. Known routes fall through
 * untouched, so the bot-facing prerender rewrites still apply.
 *
 * Fails open: any error, or a shell fetch that is not OK, continues
 * to the normal response rather than breaking the page. Static files
 * (robots.txt, favicon.svg, sitemap*.xml) have their own handlers
 * and are skipped by the extension check; the matcher already leaves
 * /api, /assets and /fonts alone. */
import { isKnownRoute } from './src/routes/knownRoutes';

export const config = { matcher: ['/((?!api/|assets/|fonts/).*)'] };

export default async function middleware(request: Request): Promise<Response | undefined> {
  try {
    const url = new URL(request.url);
    if (/\.[a-z0-9]+$/i.test(url.pathname) || isKnownRoute(url.pathname)) return undefined;
    const shell = await fetch(new URL('/index.html', url.origin));
    if (!shell.ok) return undefined;
    return new Response(await shell.text(), {
      status: 404,
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'public, max-age=0, must-revalidate',
        'x-robots-tag': 'noindex',
      },
    });
  } catch {
    return undefined;
  }
}
