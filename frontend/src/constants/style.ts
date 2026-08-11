/**
 * Shared style primitives used across the app.
 *
 * Two kinds of constants live here:
 *  1. Clip-path corner cuts — the angled-corner polygon used as inline
 *     style on most cards / panels. Centralizing them means when the
 *     visual language changes (different corner size, different
 *     polygon shape) we update one place instead of N inlined strings.
 *  2. `sourceTheme` — Tailwind class bundles per source, used by pages
 *     that need a coordinated set of dot / text / border / bg classes.
 *     Pages that only need a hex color can keep using `sourceColors`
 *     from `./sources`; pages that need bare Tailwind border/bg classes
 *     can use `sourceTailwind`.
 */

export const clipSm = {
  clipPath:
    'polygon(0 0, calc(100% - 8px) 0, 100% 8px, 100% 100%, 8px 100%, 0 calc(100% - 8px))',
} as const;

export const clipMd = {
  clipPath:
    'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))',
} as const;

export const clipLg = {
  clipPath:
    'polygon(0 0, calc(100% - 16px) 0, 100% 16px, 100% 100%, 16px 100%, 0 calc(100% - 16px))',
} as const;

export const clipXl = {
  clipPath:
    'polygon(0 0, calc(100% - 24px) 0, 100% 24px, 100% 100%, 24px 100%, 0 calc(100% - 24px))',
} as const;

export interface SourceTheme {
  name: string;
  /** Solid background — for dots and accent bars. e.g. `bg-blue-500`. */
  dot: string;
  /** Mid-tone text colour. e.g. `text-blue-400`. */
  text: string;
  /** Translucent border. e.g. `border-blue-500/30`. */
  border: string;
  /** Translucent fill. e.g. `bg-blue-500/20`. */
  bg: string;
}

export const sourceTheme: Record<string, SourceTheme> = {
  sigma:               { name: 'SigmaHQ',       dot: 'bg-blue-500',   text: 'text-blue-400',   border: 'border-blue-500/30',   bg: 'bg-blue-500/20' },
  elastic:             { name: 'Elastic',       dot: 'bg-amber-500',  text: 'text-amber-400',  border: 'border-amber-500/30',  bg: 'bg-amber-500/20' },
  splunk:              { name: 'Splunk',        dot: 'bg-green-500',  text: 'text-green-400',  border: 'border-green-500/30',  bg: 'bg-green-500/20' },
  sublime:             { name: 'Sublime',       dot: 'bg-purple-500', text: 'text-purple-400', border: 'border-purple-500/30', bg: 'bg-purple-500/20' },
  elastic_protections: { name: 'Elastic Prot.', dot: 'bg-orange-500', text: 'text-orange-400', border: 'border-orange-500/30', bg: 'bg-orange-500/20' },
  lolrmm:              { name: 'LOLRMM',        dot: 'bg-pink-500',   text: 'text-pink-400',   border: 'border-pink-500/30',   bg: 'bg-pink-500/20' },
  elastic_hunting:     { name: 'Elastic Hunt',  dot: 'bg-violet-500', text: 'text-violet-400', border: 'border-violet-500/30', bg: 'bg-violet-500/20' },
  sentinel:            { name: 'Sentinel',      dot: 'bg-sky-500',    text: 'text-sky-400',    border: 'border-sky-500/30',    bg: 'bg-sky-500/20' },
  google_secops:       { name: 'Google SecOps', dot: 'bg-lime-500',   text: 'text-lime-400',   border: 'border-lime-500/30',   bg: 'bg-lime-500/20' },
  okta: { name: 'Okta',       dot: 'bg-teal-500',   text: 'text-teal-400',   border: 'border-teal-500/30',   bg: 'bg-teal-500/20' },
  auth0:               { name: 'Auth0',         dot: 'bg-rose-500',   text: 'text-rose-400',   border: 'border-rose-500/30',   bg: 'bg-rose-500/20' },
  panther:             { name: 'Panther',       dot: 'bg-fuchsia-500',text: 'text-fuchsia-400',border: 'border-fuchsia-500/30',bg: 'bg-fuchsia-500/20' },
};
