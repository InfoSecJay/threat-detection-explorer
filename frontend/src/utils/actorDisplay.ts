/**
 * Display helpers for actor context enrichment (MISP galaxy fields).
 * Shared between the /actors cards, table view, and detail page.
 */

/** ISO-2 country code -> regional-indicator emoji flag. */
export function countryFlag(iso2: string): string {
  const cc = iso2.trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(cc)) return '';
  const A = 0x1f1e6;
  return String.fromCodePoint(
    A + cc.charCodeAt(0) - 65,
    A + cc.charCodeAt(1) - 65
  );
}

const COUNTRY_NAMES: Record<string, string> = {
  CN: 'China', RU: 'Russia', KP: 'North Korea', IR: 'Iran', US: 'United States',
  IN: 'India', PK: 'Pakistan', VN: 'Vietnam', KR: 'South Korea', TR: 'Turkiye',
  IL: 'Israel', BY: 'Belarus', LB: 'Lebanon', SY: 'Syria', AE: 'UAE',
  UA: 'Ukraine', NG: 'Nigeria', BR: 'Brazil', GE: 'Georgia', ES: 'Spain',
  FR: 'France', GB: 'United Kingdom', DE: 'Germany', IT: 'Italy', RO: 'Romania',
  SA: 'Saudi Arabia', ID: 'Indonesia', MY: 'Malaysia', TN: 'Tunisia', GZ: 'Gaza',
};

/** Country display name, falling back to the raw code. */
export function countryName(iso2: string): string {
  return COUNTRY_NAMES[iso2.trim().toUpperCase()] ?? iso2.toUpperCase();
}

/** Badge classes per normalized motivation enum value. */
export const MOTIVATION_STYLE: Record<string, string> = {
  espionage: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
  ransomware: 'bg-breach-500/10 text-breach-400 border-breach-500/30',
  'financial-crime': 'bg-amber-500/10 text-amber-400 border-amber-500/30',
  destructive: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
  hacktivism: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
  unknown: 'bg-void-800 text-gray-500 border-void-700',
};

/** Weighted-coverage bar color by threshold: red < 0.4, amber 0.4-0.7,
 *  green above. Muted gray when the score is null (no data). */
export function coverageBarClass(weighted: number | null): string {
  if (weighted === null) return 'bg-gray-700';
  if (weighted < 0.4) return 'bg-breach-500/70';
  if (weighted <= 0.7) return 'bg-amber-500/70';
  return 'bg-matrix-500/70';
}

export function coverageTextClass(weighted: number | null): string {
  if (weighted === null) return 'text-gray-600';
  if (weighted < 0.4) return 'text-breach-400';
  if (weighted <= 0.7) return 'text-amber-400';
  return 'text-matrix-500';
}

/** Gap counts above this get the red accent on cards + table. */
export const GAP_ACCENT_THRESHOLD = 5;
