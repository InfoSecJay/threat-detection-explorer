import { describe, it, expect } from 'vitest';
import { clipSm, clipMd, clipLg, clipXl, sourceTheme } from '../style';

describe('style constants', () => {
  it('clip variants all hold a single clipPath property with a polygon value', () => {
    for (const [name, clip] of [['clipSm', clipSm], ['clipMd', clipMd], ['clipLg', clipLg], ['clipXl', clipXl]] as const) {
      expect(Object.keys(clip), `${name} only exposes clipPath`).toEqual(['clipPath']);
      expect(clip.clipPath, `${name} is a polygon`).toMatch(/^polygon\(/);
    }
  });

  it('clip variants encode the corner size in the polygon string', () => {
    expect(clipSm.clipPath).toContain('8px');
    expect(clipMd.clipPath).toContain('12px');
    expect(clipLg.clipPath).toContain('16px');
    expect(clipXl.clipPath).toContain('24px');
  });

  it('sourceTheme covers every supported source with a complete bundle', () => {
    const required = [
      'sigma', 'elastic', 'splunk', 'sublime',
      'elastic_protections', 'lolrmm', 'elastic_hunting', 'sentinel',
      'google_secops', 'okta', 'auth0',
    ];
    for (const src of required) {
      const theme = sourceTheme[src];
      expect(theme, `${src} is in sourceTheme`).toBeDefined();
      expect(theme.name).toBeTruthy();
      expect(theme.dot).toMatch(/^bg-/);
      expect(theme.text).toMatch(/^text-/);
      expect(theme.border).toMatch(/^border-/);
      expect(theme.bg).toMatch(/^bg-/);
    }
  });
});
