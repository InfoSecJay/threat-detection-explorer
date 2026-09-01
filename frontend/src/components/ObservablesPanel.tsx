/**
 * ObservablesPanel — the typed view of what a rule's logic keys on
 * (observables v2). Replaces the legacy flat chip lists with the
 * structured form the per-source extractors emit: grouped by
 * observable TYPE, one row per source FIELD with its values, subtype
 * label, and an explicit NOT marker for negated conditions (an
 * exclusion is the opposite of a match — flattening it into the same
 * chip list misled readers).
 *
 * Vocabulary (type/subtype) is pinned in backend
 * taxonomy/canonical.py; the display maps below only prettify.
 */

import { Link } from 'react-router-dom';
import type { Detection } from '../types';
import { kindFor, observableUrl, OBSERVABLE_KIND_LABEL } from '../utils/observableLinks';

type Observable = NonNullable<Detection['extracted_observables']>[number];

const TYPE_ORDER = [
  'process', 'file', 'registry', 'network', 'dns', 'email', 'cloud',
  'identity', 'authentication', 'endpoint', 'event', 'other',
];

const TYPE_STYLE: Record<string, { label: string; chip: string; dot: string }> = {
  process:        { label: 'Process',        chip: 'bg-red-500/15 text-red-300 border-red-500/30',             dot: 'bg-red-500' },
  file:           { label: 'File',           chip: 'bg-orange-500/15 text-orange-300 border-orange-500/30',    dot: 'bg-orange-500' },
  registry:       { label: 'Registry',       chip: 'bg-purple-500/15 text-purple-300 border-purple-500/30',    dot: 'bg-purple-500' },
  network:        { label: 'Network',        chip: 'bg-blue-500/15 text-blue-300 border-blue-500/30',          dot: 'bg-blue-500' },
  dns:            { label: 'DNS',            chip: 'bg-sky-500/15 text-sky-300 border-sky-500/30',             dot: 'bg-sky-500' },
  email:          { label: 'Email',          chip: 'bg-pink-500/15 text-pink-300 border-pink-500/30',          dot: 'bg-pink-500' },
  cloud:          { label: 'Cloud',          chip: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',          dot: 'bg-cyan-500' },
  identity:       { label: 'Identity',       chip: 'bg-teal-500/15 text-teal-300 border-teal-500/30',          dot: 'bg-teal-500' },
  authentication: { label: 'Authentication', chip: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30', dot: 'bg-emerald-500' },
  endpoint:       { label: 'Endpoint',       chip: 'bg-lime-500/15 text-lime-300 border-lime-500/30',          dot: 'bg-lime-500' },
  event:          { label: 'Event',          chip: 'bg-amber-500/15 text-amber-300 border-amber-500/30',       dot: 'bg-amber-500' },
  other:          { label: 'Other',          chip: 'bg-gray-500/15 text-gray-300 border-gray-500/30',          dot: 'bg-gray-500' },
};

function humanize(subtype: string): string {
  return subtype.replace(/_/g, ' ');
}

const MAX_VALUES = 12;

export function ObservablesPanel({
  observables,
  sourceTables,
  complexity,
  eventIdLabels,
}: {
  observables: Observable[];
  sourceTables: string[];
  complexity?: string;
  /** {event id: label} from useEventIds(); labels event-ID chips
   * ("4688 Process created"). Optional so the panel stays pure. */
  eventIdLabels?: Record<string, string>;
}) {
  const groups = new Map<string, Observable[]>();
  for (const o of observables) {
    if (!o || !Array.isArray(o.values) || o.values.length === 0) continue;
    const t = TYPE_STYLE[o.type] ? o.type : 'other';
    if (!groups.has(t)) groups.set(t, []);
    groups.get(t)!.push(o);
  }
  const orderedTypes = TYPE_ORDER.filter((t) => groups.has(t));

  return (
    <div data-testid="observables-panel">
      <div className="flex items-center gap-2 mb-3">
        <label className="text-xs font-medium text-gray-500 uppercase tracking-wide">
          Observables
        </label>
        <span className="text-[10px] font-mono text-gray-600">
          what the logic keys on, extracted from the rule
        </span>
        {complexity && complexity !== 'unknown' && (
          <span
            className={`ml-auto px-2 py-0.5 rounded text-xs font-semibold capitalize border ${
              complexity === 'simple'
                ? 'bg-green-500/20 text-green-400 border-green-500/30'
                : complexity === 'moderate'
                  ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
                  : 'bg-red-500/20 text-red-400 border-red-500/30'
            }`}
          >
            {complexity} query
          </span>
        )}
      </div>

      {sourceTables.length > 0 && (
        <div className="mb-3 flex items-start gap-2">
          <span className="text-[11px] font-mono text-gray-500 uppercase w-24 shrink-0 pt-0.5">Reads from</span>
          <div className="flex flex-wrap gap-1.5">
            {sourceTables.map((t) => (
              <span key={t} className="px-2 py-0.5 border rounded text-xs font-mono bg-emerald-500/15 text-emerald-300 border-emerald-500/30">
                {t}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="space-y-3">
        {orderedTypes.map((type) => {
          const style = TYPE_STYLE[type];
          return (
            <div key={type} data-testid={`observable-group-${type}`}>
              <div className="flex items-center gap-2 mb-1.5">
                <span className={`w-1.5 h-1.5 rounded-full ${style.dot}`} />
                <span className="text-[11px] font-display font-semibold uppercase tracking-wider text-gray-400">
                  {style.label}
                </span>
              </div>
              <div className="space-y-1.5 pl-3.5 border-l border-void-700">
                {groups.get(type)!.map((o, i) => {
                  const values = o.values.slice(0, MAX_VALUES);
                  const overflow = o.values.length - values.length;
                  return (
                    <div key={`${o.field}-${i}`} className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
                      {o.negated && (
                        <span
                          className="px-1.5 py-0.5 text-[10px] font-mono font-bold uppercase bg-breach-500/20 text-breach-400 border border-breach-500/40 rounded"
                          title="Exclusion: the rule does NOT match these values"
                        >
                          NOT
                        </span>
                      )}
                      <span className="text-xs font-mono text-gray-300" title={`Source field: ${o.field}`}>
                        {o.field}
                      </span>
                      <span className="text-[10px] font-mono text-gray-600">{humanize(o.subtype)}</span>
                      <div className="flex flex-wrap gap-1">
                        {values.map((v, j) => {
                          const eventLabel =
                            o.subtype === 'event_id' && eventIdLabels ? eventIdLabels[String(v)] : undefined;
                          const kind = kindFor(o.type, o.subtype);
                          const chip = (
                            <>
                              {v}
                              {eventLabel && (
                                <span className="ml-1 font-sans text-[10px] opacity-75">{eventLabel}</span>
                              )}
                            </>
                          );
                          const cls = `px-1.5 py-0.5 border rounded text-xs font-mono break-all ${style.chip}`;
                          // Values with an observable page link to it: "every
                          // rule across vendors that keys on this value".
                          return kind && v ? (
                            <Link
                              key={`${v}-${j}`}
                              to={observableUrl(kind, String(v))}
                              className={`${cls} hover:brightness-125 underline decoration-dotted underline-offset-2`}
                              title={eventLabel ? `${v} - ${eventLabel}` : `Every rule referencing this ${OBSERVABLE_KIND_LABEL[kind].toLowerCase()}`}
                            >
                              {chip}
                            </Link>
                          ) : (
                            <span
                              key={`${v}-${j}`}
                              className={cls}
                              title={eventLabel ? `${v} - ${eventLabel}` : undefined}
                            >
                              {chip}
                            </span>
                          );
                        })}
                        {overflow > 0 && (
                          <span className="px-1.5 py-0.5 text-[10px] font-mono text-gray-500" title={o.values.slice(MAX_VALUES).join('\n')}>
                            +{overflow} more
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
