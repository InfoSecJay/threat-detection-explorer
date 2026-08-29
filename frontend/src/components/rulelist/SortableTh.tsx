/** Sortable column header: a real <button> inside the <th> so the sort
 * is reachable by keyboard, with aria-sort announcing the state (#50). */

export interface SortState {
  sortBy?: string;
  sortOrder?: string;
  onSort: (field: string) => void;
}

export function SortableTh({
  field, label, title, pad = 'px-3', sortBy, sortOrder, onSort,
}: SortState & {
  field: string; label: string; title?: string; pad?: string;
}) {
  const active = sortBy === field;
  const ariaSort = active ? (sortOrder === 'asc' ? 'ascending' : 'descending') : 'none';
  return (
    <th aria-sort={ariaSort} className={`${pad} py-3 text-left`} title={title}>
      <button
        type="button"
        onClick={() => onSort(field)}
        className="text-xs font-display font-semibold text-gray-500 uppercase tracking-wider hover:text-matrix-500 focus-visible:text-matrix-400 focus-visible:underline focus:outline-none transition-colors whitespace-nowrap"
      >
        {label}{active && <span className="ml-1 text-matrix-500">{sortOrder === 'asc' ? '\u2191' : '\u2193'}</span>}
      </button>
    </th>
  );
}
