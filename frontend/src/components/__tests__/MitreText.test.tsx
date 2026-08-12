/**
 * Unit tests for the MITRE description renderer.
 *
 * MITRE STIX text carries [label](url) links, (Citation: ...) markers,
 * and <code> spans. Links to ATT&CK entities route internally when the
 * caller's resolveRoute confirms the object exists in our catalog and
 * stay external otherwise; citations become numbered superscript
 * markers matched against external_references by source_name; code
 * spans render as <code>; stripMitreMarkup gives tooltip-safe plain
 * text.
 */

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import {
  MitreText,
  MitreReferences,
  resolveCitations,
  stripMitreMarkup,
} from '../MitreText';
import type { MitreRef } from '../MitreText';

const BLACKOASIS =
  '[BlackOasis](https://attack.mitre.org/groups/G0063) is a Middle Eastern threat group ' +
  'that is believed to be a customer of Gamma Group. (Citation: Securelist BlackOasis Oct 2017) ' +
  'A group known by Microsoft as [NEODYMIUM](https://attack.mitre.org/groups/G0055) is reportedly ' +
  'associated closely with [BlackOasis](https://attack.mitre.org/groups/G0063) operations. ' +
  '(Citation: CyberScoop BlackOasis Oct 2017)';

const REFS: MitreRef[] = [
  {
    source_name: 'Securelist BlackOasis Oct 2017',
    url: 'https://securelist.com/blackoasis',
    description: 'Kaspersky writeup.',
  },
];

function renderText(text: string, props?: Parameters<typeof MitreText>[0] extends infer P ? Partial<P> : never) {
  return render(
    <MemoryRouter>
      <MitreText text={text} {...props} />
    </MemoryRouter>
  );
}

describe('MitreText links', () => {
  it('renders attack.mitre.org links as external anchors when no resolver is given', () => {
    renderText(BLACKOASIS);
    const links = screen.getAllByRole('link', { name: 'BlackOasis' });
    expect(links).toHaveLength(2);
    expect(links[0].getAttribute('href')).toBe('https://attack.mitre.org/groups/G0063');
    expect(links[0].getAttribute('target')).toBe('_blank');
  });

  it('rewrites ATT&CK entity links onto internal routes when the resolver knows them', () => {
    const resolveRoute = (url: string) =>
      url.includes('/groups/G0063') ? '/actors/G0063' : null;
    renderText(BLACKOASIS, { resolveRoute });
    const internal = screen.getAllByRole('link', { name: 'BlackOasis' });
    // Internal links have no target=_blank and route to /actors/G0063.
    expect(internal[0].getAttribute('href')).toBe('/actors/G0063');
    expect(internal[0].getAttribute('target')).toBeNull();
    // G0055 was not resolvable -> stays external to its real URL.
    expect(screen.getByRole('link', { name: 'NEODYMIUM' }).getAttribute('href')).toBe(
      'https://attack.mitre.org/groups/G0055'
    );
  });

  it('renders non-MITRE links as external anchors', () => {
    renderText('See [the report](https://example.com/report) for details.');
    const a = screen.getByRole('link', { name: 'the report' });
    expect(a.getAttribute('href')).toBe('https://example.com/report');
    expect(a.getAttribute('target')).toBe('_blank');
  });
});

describe('MitreText citations', () => {
  it('replaces citation tokens with numbered superscript markers', () => {
    const { container } = renderText(BLACKOASIS, { references: REFS });
    expect(container.textContent).not.toContain('Citation:');
    expect(container.textContent).toContain('customer of Gamma Group.');
    const sups = container.querySelectorAll('sup');
    expect(sups).toHaveLength(2);
    expect(sups[0].textContent).toBe('[1]');
    expect(sups[1].textContent).toBe('[2]');
  });

  it('links matched markers to the reference URL, leaves unmatched plain', () => {
    const { container } = renderText(BLACKOASIS, { references: REFS });
    const sups = container.querySelectorAll('sup');
    // [1] Securelist — matched.
    expect(sups[0].querySelector('a')?.getAttribute('href')).toBe(
      'https://securelist.com/blackoasis'
    );
    // [2] CyberScoop — not in refs, plain marker, no link.
    expect(sups[1].querySelector('a')).toBeNull();
  });

  it('reuses one number for repeat citations of the same source', () => {
    const text = 'One. (Citation: Foo) Two. (Citation: Foo) Three. (Citation: Bar)';
    const { container } = renderText(text);
    const nums = [...container.querySelectorAll('sup')].map((s) => s.textContent);
    expect(nums).toEqual(['[1]', '[1]', '[2]']);
  });
});

describe('resolveCitations', () => {
  it('numbers citations by first appearance and matches by source_name', () => {
    const entries = resolveCitations(BLACKOASIS, REFS);
    expect(entries).toHaveLength(2);
    expect(entries[0].num).toBe(1);
    expect(entries[0].ref?.url).toBe('https://securelist.com/blackoasis');
    expect(entries[1].num).toBe(2);
    expect(entries[1].source_name).toBe('CyberScoop BlackOasis Oct 2017');
    expect(entries[1].ref).toBeNull();
  });
});

describe('MitreReferences', () => {
  it('lists cited refs numbered, then uncited refs unnumbered', () => {
    const refs: MitreRef[] = [
      ...REFS,
      { source_name: 'Unrelated Source', url: 'https://example.com/other' },
    ];
    const citations = resolveCitations(BLACKOASIS, refs);
    const { container } = render(
      <MemoryRouter>
        <MitreReferences citations={citations} references={refs} />
      </MemoryRouter>
    );
    const items = container.querySelectorAll('li');
    expect(items).toHaveLength(3); // 2 cited + 1 uncited
    expect(items[0].textContent).toContain('[1]');
    expect(items[0].querySelector('a')?.getAttribute('href')).toBe(
      'https://securelist.com/blackoasis'
    );
    // Unmatched citation appears with its number but no link.
    expect(items[1].textContent).toContain('[2]');
    expect(items[1].querySelector('a')).toBeNull();
    // Uncited ref appended, unnumbered.
    expect(items[2].querySelector('a')?.getAttribute('href')).toBe(
      'https://example.com/other'
    );
  });
});

describe('MitreText structure', () => {
  it('renders <code> spans as code elements', () => {
    const { container } = renderText('Adversaries may abuse <code>rundll32.exe</code> to proxy.');
    const code = container.querySelector('code');
    expect(code?.textContent).toBe('rundll32.exe');
  });

  it('splits paragraphs on blank lines', () => {
    const { container } = renderText('First paragraph.\n\nSecond paragraph.');
    expect(container.querySelectorAll('p')).toHaveLength(2);
  });
});

describe('stripMitreMarkup', () => {
  it('collapses links to labels and drops citations and code tags', () => {
    expect(stripMitreMarkup(BLACKOASIS)).toBe(
      'BlackOasis is a Middle Eastern threat group that is believed to be a customer of ' +
        'Gamma Group. A group known by Microsoft as NEODYMIUM is reportedly associated ' +
        'closely with BlackOasis operations.'
    );
    expect(stripMitreMarkup('Abuse <code>cmd.exe</code> here')).toBe('Abuse cmd.exe here');
  });
});
