/** Collapsible section header with the active-selection count. */

export function SectionHeader({
  title, count, expanded, onToggle,
}: {
  title: string;
  count?: number;
  expanded: boolean;
  onToggle: () => void;
}) {
  return (
    <button
      onClick={onToggle}
      className="w-full flex items-center justify-between py-2 text-left group"
    >
      <span className="text-xs font-display font-semibold text-gray-400 uppercase tracking-wider group-hover:text-matrix-500 transition-colors">
        {title}
        {count !== undefined && count > 0 && (
          <span className="ml-2 text-matrix-500">({count})</span>
        )}
      </span>
      <svg
        className={`w-4 h-4 text-gray-500 transition-transform ${expanded ? 'rotate-180' : ''}`}
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
      >
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
      </svg>
    </button>
  );
}
