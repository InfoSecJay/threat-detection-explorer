/** One checkbox row in the sidebar: optional colour dot, label, and
 * the live facet count. */

/** Count badge rendered on every facet option -- shows how many rules
 * the option matches under the current query, dimmed when zero so
 * users stop clicking into empty result sets. 11px at dim-500 clears
 * WCAG AA (DX-20 / #162: the 10px gray-600 version read 2.5:1); the
 * zero state is an inactive cue and stays one step dimmer. */
export function FacetCount({ count }: { count: number | undefined }) {
  return (
    <span
      className={`ml-auto text-[11px] font-mono shrink-0 tabular-nums ${
        count ? 'text-dim-500' : 'text-gray-500'
      }`}
    >
      {(count || 0).toLocaleString()}
    </span>
  );
}

export function CheckboxOption({
  checked, onChange, label, color, title, count, labelClass = '',
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: string;
  color?: string;
  title?: string;
  count: number | undefined;
  labelClass?: string;
}) {
  return (
    <label className="flex items-center gap-2 py-1.5 px-2 rounded cursor-pointer hover:bg-void-800 transition-colors group">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="w-3.5 h-3.5 rounded-sm bg-void-900 border-void-600 text-matrix-500 focus:ring-matrix-500/50 focus:ring-offset-void-900"
      />
      {color && <span className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />}
      <span className={`text-sm text-gray-400 group-hover:text-white transition-colors ${labelClass}`} title={title}>
        {label}
      </span>
      <FacetCount count={count} />
    </label>
  );
}
