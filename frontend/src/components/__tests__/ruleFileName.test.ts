/** Download filename derivation (#128): upstream basename, byte-safe. */

import { describe, it, expect } from 'vitest';
import { ruleFileName } from '../../utils/downloadRule';
import type { Detection } from '../../types';

const d = (source_file: string): Detection =>
  ({ id: 'abc-123', source_file } as Detection);

describe('ruleFileName', () => {
  it('takes the upstream basename with its extension', () => {
    expect(ruleFileName(d('rules/windows/proc_creation_win_foo.yml'))).toBe(
      'proc_creation_win_foo.yml',
    );
    expect(ruleFileName(d('rules\\windows\\evil.toml'))).toBe('evil.toml');
    expect(ruleFileName(d('detections/aws_cloudtrail.py'))).toBe('aws_cloudtrail.py');
  });

  it('names a GitLab rule after its file and Sigma id, as YAML', () => {
    // The file is Markdown holding several Sigma rules; the download is
    // one rule's YAML, so two rules of a file must not collide.
    const file = 'Detections/platforms/GitLab/Threat Detections/deploy_key_created.md';
    const rule = (rule_id: string | null, source = 'gitlab') =>
      ({ id: 'abc-123', source, source_file: file, rule_id } as Detection);
    expect(ruleFileName(rule('f8092817-3c2e-4c4e-b3e7-299936b2098f'))).toBe('deploy_key_created.f8092817.yml');
    expect(ruleFileName(rule('4ec1d73a-3094-461b-8eea-794834dac855'))).toBe('deploy_key_created.4ec1d73a.yml');
    expect(ruleFileName(rule(null))).toBe('deploy_key_created.yml');
    // Only for the gitlab source: another source's .md keeps its name.
    expect(ruleFileName(rule('f8092817-3c2e', 'sigma'))).toBe('deploy_key_created.md');
  });

  it('falls back to the rule id on pathological names', () => {
    expect(ruleFileName(d(''))).toBe('abc-123.txt');
    expect(ruleFileName(d('no_extension'))).toBe('abc-123.txt');
    expect(ruleFileName(d('weird/<>:"|?.yml'))).toBe('abc-123.txt');
  });
});
