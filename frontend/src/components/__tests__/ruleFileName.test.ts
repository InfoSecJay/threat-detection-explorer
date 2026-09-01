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

  it('falls back to the rule id on pathological names', () => {
    expect(ruleFileName(d(''))).toBe('abc-123.txt');
    expect(ruleFileName(d('no_extension'))).toBe('abc-123.txt');
    expect(ruleFileName(d('weird/<>:"|?.yml'))).toBe('abc-123.txt');
  });
});
