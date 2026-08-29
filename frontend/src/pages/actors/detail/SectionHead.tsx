export function SectionHead({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div className="flex items-baseline gap-3 mb-3 flex-wrap">
      <span className="w-1 h-4 bg-matrix-500 shrink-0" aria-hidden="true" />
      <h2 className="text-base font-display font-bold text-white tracking-wider uppercase">
        {title}
      </h2>
      {subtitle && (
        <span className="text-[10px] text-gray-500 font-mono uppercase tracking-wider">
          // {subtitle}
        </span>
      )}
    </div>
  );
}
