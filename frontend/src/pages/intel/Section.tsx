/** Shared shell components used across every Intel sub-section. */

export function Section({
  title,
  subtitle,
  action,
  children,
}: {
  title: string;
  subtitle?: string;
  action?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section>
      <div className="flex items-baseline justify-between gap-3 mb-3 flex-wrap">
        <div className="flex items-baseline gap-3 min-w-0">
          <span className="w-1 h-4 bg-matrix-500 shrink-0" aria-hidden="true" />
          <h2 className="text-base font-display font-bold text-white tracking-wider uppercase">
            {title}
          </h2>
          {subtitle && (
            <span className="text-[10px] text-gray-500 font-mono uppercase tracking-wider truncate">
              // {subtitle}
            </span>
          )}
        </div>
        {action && <div className="shrink-0">{action}</div>}
      </div>
      {children}
    </section>
  );
}

export function SkeletonRow({ height = 'h-8' }: { height?: string }) {
  return <div className={`${height} bg-void-800 animate-pulse rounded-sm`} />;
}

export function EmptyLabel({ label }: { label: string }) {
  return <div className="text-center py-6 text-gray-500 font-mono text-xs">{label}</div>;
}
