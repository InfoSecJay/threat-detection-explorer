/**
 * Unit tests for the MITRE description renderer.
 *
 * MITRE STIX text carries [label](url) links, (Citation: ...) markers,
 * and <code> spans. The G0063/BlackOasis description was rendering all
 * of that verbatim — these tests pin the fix: links become anchors
 * (internal route for attack.mitre.org entities we host), citations
 * disappear, code spans render as <code>, and stripMitreMarkup gives
 * tooltip-safe plain text.
 */

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { MitreText, stripMitreMarkup } from '../MitreText';

const BLACKOASIS =
  '[BlackOasis](https://attack.mitre.org/groups/G0063) is a Middle Eastern threat group ' +
  'that is believed to be a customer of Gamma Group. (Citation: Securelist BlackOasis Oct 2017) ' +
  'A group known by Microsoft as [NEODYMIUM](https://attack.mitre.org/groups/G0055) is reportedly ' +
  'associated closely with [BlackOasis](https://attack.mitre.org/groups/G0063) operations. ' +
  '(Citation: CyberScoop BlackOasis Oct 2017)';

function renderText(text: string) {
  return render(
    <MemoryRouter>
      <MitreText text={text} />
    </MemoryRouter>
  );
}

describe('MitreText', () => {
  it('renders attack.mitre.org group links as internal actor routes', () => {
    renderText(BLACKOASIS);
    const links = screen.getAllByRole('link', { name: 'BlackOasis' });
    expect(links).toHaveLength(2);
    expect(links[0].getAttribute('href')).toBe('/actors/G0063');
    expect(screen.getByRole('link', { name: 'NEODYMIUM' }).getAttribute('href')).toBe(
      '/actors/G0055'
    );
  });

  it('strips citation markers from rendered output', () => {
    const { container } = renderText(BLACKOASIS);
    expect(container.textContent).not.toContain('Citation:');
    expect(container.textContent).toContain('customer of Gamma Group.');
  });

  it('routes software and sub-technique links internally', () => {
    renderText(
      'Uses [FinFisher](https://attack.mitre.org/software/S0182) and ' +
        '[PowerShell](https://attack.mitre.org/techniques/T1059/001).'
    );
    expect(screen.getByRole('link', { name: 'FinFisher' }).getAttribute('href')).toBe(
      '/actors/S0182'
    );
    expect(screen.getByRole('link', { name: 'PowerShell' }).getAttribute('href')).toBe(
      '/mitre/T1059.001'
    );
  });

  it('renders non-MITRE links as external anchors', () => {
    renderText('See [the report](https://example.com/report) for details.');
    const a = screen.getByRole('link', { name: 'the report' });
    expect(a.getAttribute('href')).toBe('https://example.com/report');
    expect(a.getAttribute('target')).toBe('_blank');
  });

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
