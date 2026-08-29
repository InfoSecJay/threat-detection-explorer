// Cap visible tags per cell; overflow collapses into a "+N" tag
const MAX_VISIBLE_TAGS = 3;

export function TagList({ items, colorClass }: { items: string[] | null | undefined; colorClass: string }) {
  if (!items || items.length === 0) {
    return <span className="text-xs text-gray-600">-</span>;
  }

  const visible = items.slice(0, MAX_VISIBLE_TAGS);
  const hidden = items.slice(MAX_VISIBLE_TAGS);

  return (
    <div className="flex flex-wrap gap-1">
      {visible.map((item) => (
        <span
          key={item}
          className={`px-1.5 py-0.5 text-xs font-mono border ${
            item === 'unknown'
              ? 'bg-gray-500/15 text-gray-500 border-gray-500/30 italic'
              : colorClass
          }`}
        >
          {item}
        </span>
      ))}
      {hidden.length > 0 && (
        <span
          className="px-1.5 py-0.5 text-xs font-mono border bg-gray-500/10 text-gray-400 border-gray-500/30"
          title={hidden.join(', ')}
        >
          +{hidden.length}
        </span>
      )}
    </div>
  );
}
