/**
 * Rule history timeline (#127): newest first, labelled Last updated /
 * Changed / Created, authors and commit links from upstream, a Created
 * entry from the rule date when history is capped, and an honest empty
 * state before the first sync captures anything.
 */
import { describe, it, expect } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import { HistoryTimeline } from '../HistoryTimeline';

const REPO = 'https://github.com/SigmaHQ/sigma.git';
const touch = (i: number, date: string) => ({ sha: `abc${i}`.padEnd(8, '0'), author: `Author ${i}`, date, subject: `change ${i}` });

describe('HistoryTimeline', () => {
  it('labels newest as Last updated and oldest as Created, linking commits', () => {
    const touches = [touch(1, '2026-08-01T00:00:00Z'), touch(2, '2026-03-01T00:00:00Z'), touch(3, '2025-01-01T00:00:00Z')];
    render(<HistoryTimeline touches={touches} createdDate="2025-01-01T00:00:00Z" repoUrl={REPO} />);
    const items = within(screen.getByTestId('history-timeline')).getAllByRole('listitem');
    expect(items).toHaveLength(3);
    expect(items[0]).toHaveTextContent('Last updated');
    expect(items[0]).toHaveTextContent('Author 1');
    expect(items[1]).toHaveTextContent('Changed');
    expect(items[2]).toHaveTextContent('Created');
    const links = screen.getAllByTitle('Open the upstream commit');
    expect(links).toHaveLength(3);
    expect(links[0]).toHaveAttribute('href', 'https://github.com/SigmaHQ/sigma/commit/abc10000');
  });

  it('adds a Created entry from the rule date when history is capped', () => {
    const touches = Array.from({ length: 10 }, (_, i) => touch(i, `2026-0${(i % 8) + 1}-15T00:00:00Z`));
    render(<HistoryTimeline touches={touches} createdDate="2021-06-01T00:00:00Z" repoUrl={REPO} />);
    const items = within(screen.getByTestId('history-timeline')).getAllByRole('listitem');
    expect(items[items.length - 2]).toHaveTextContent('Created (earlier changes not shown)');
    expect(items[items.length - 1]).toHaveTextContent('Showing the last 10 upstream changes.');
  });

  it('shows the removal as the newest entry for tombstoned rules', () => {
    render(<HistoryTimeline touches={[touch(1, '2026-01-01T00:00:00Z')]} createdDate={null} repoUrl={REPO} removedAt="2026-09-01T00:00:00Z" />);
    const items = within(screen.getByTestId('history-timeline')).getAllByRole('listitem');
    expect(items[0]).toHaveTextContent('Removed upstream');
    expect(items[1]).toHaveTextContent('Created');
  });

  it('renders an honest empty state with nothing captured', () => {
    render(<HistoryTimeline touches={[]} createdDate={null} repoUrl={REPO} />);
    expect(screen.getByTestId('history-empty')).toHaveTextContent('No upstream history captured');
  });

  it('falls back to the rule date alone when touches are missing', () => {
    render(<HistoryTimeline touches={undefined} createdDate="2024-02-02T00:00:00Z" repoUrl={null} />);
    const items = within(screen.getByTestId('history-timeline')).getAllByRole('listitem');
    expect(items).toHaveLength(1);
    expect(items[0]).toHaveTextContent('Created');
    expect(items[0]).toHaveTextContent('2024-02-02');
  });
});
