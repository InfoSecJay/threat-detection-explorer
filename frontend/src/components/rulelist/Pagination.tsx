/** Page strip: PREV / numbered window with ellipses / NEXT. */

function visiblePages(currentPage: number, totalPages: number): (number | string)[] {
  const pages: (number | string)[] = [];
  const maxVisible = 5;

  if (totalPages <= maxVisible + 2) {
    for (let i = 1; i <= totalPages; i++) pages.push(i);
  } else {
    pages.push(1);
    if (currentPage > 3) pages.push('...');
    const start = Math.max(2, currentPage - 1);
    const end = Math.min(totalPages - 1, currentPage + 1);
    for (let i = start; i <= end; i++) pages.push(i);
    if (currentPage < totalPages - 2) pages.push('...');
    pages.push(totalPages);
  }
  return pages;
}

export function Pagination({ currentPage, totalPages, onPageChange }: { currentPage: number; totalPages: number; onPageChange: (page: number) => void }) {
  return (
    <div className="flex items-center justify-between mt-4">
      <div className="text-sm font-mono text-gray-500">
        PAGE <span className="text-matrix-500">{currentPage}</span> / {totalPages}
      </div>
      <div className="flex items-center gap-1">
        <button
          onClick={() => onPageChange(currentPage - 1)}
          disabled={currentPage === 1}
          className="px-3 py-1.5 border border-void-700 text-xs font-display text-gray-300 disabled:opacity-30 disabled:cursor-not-allowed hover:bg-void-800 hover:border-matrix-500/30 transition-all"
        >
          PREV
        </button>
        {visiblePages(currentPage, totalPages).map((page, idx) => (
          typeof page === 'number' ? (
            <button
              key={idx}
              onClick={() => onPageChange(page)}
              className={`px-3 py-1.5 border text-xs font-mono transition-all ${
                page === currentPage
                  ? 'bg-matrix-500/10 text-matrix-500 border-matrix-500/30'
                  : 'border-void-700 text-gray-300 hover:bg-void-800 hover:border-matrix-500/30'
              }`}
            >
              {page}
            </button>
          ) : (
            <span key={idx} className="px-2 text-gray-600">
              {page}
            </span>
          )
        ))}
        <button
          onClick={() => onPageChange(currentPage + 1)}
          disabled={currentPage === totalPages}
          className="px-3 py-1.5 border border-void-700 text-xs font-display text-gray-300 disabled:opacity-30 disabled:cursor-not-allowed hover:bg-void-800 hover:border-matrix-500/30 transition-all"
        >
          NEXT
        </button>
      </div>
    </div>
  );
}
