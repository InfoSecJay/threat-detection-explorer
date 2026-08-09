/**
 * Query Reference — user-facing docs for the search bar syntax + the
 * full field registry. Hydrated from /query/fields so any queryable
 * dimension added to the backend parser shows up here automatically.
 *
 * Doubles as the source-of-truth schema doc for the project's public
 * API: it lists every field a rule normalizes into and how to query
 * each. Linked from the search bar's `?` icon, About page, and the
 * Resources dropdown in the nav.
 */

import { Link } from 'react-router-dom';
import { useQueryFields } from '../hooks/useQueryFields';
import { clipSm, clipMd } from '../constants/style';

const RECIPES: Array<{ title: string; query: string; explains: string }> = [
  {
    title: 'High-severity Windows rules',
    query: 'platform:windows AND severity:high',
    explains: 'Cross-source view of the most critical Windows content.',
  },
  {
    title: 'APT29 activity',
    query: 'actor:APT29',
    explains: 'Resolves the group name to G0016 and matches every rule tagged with it.',
  },
  {
    title: 'Cobalt Strike detections in Splunk',
    query: 'malware:"Cobalt Strike" AND source:splunk',
    explains: 'Multi-word values need quotes. `malware:` also accepts the S-ID directly.',
  },
  {
    title: 'Credential dumping without linux noise',
    query: 'tech:T1003 NOT platform:linux',
    explains: 'NOT excludes matching rules; combines cleanly with any other filter.',
  },
  {
    title: 'Anything mentioning Mimikatz outside actor tags',
    query: 'content:mimikatz NOT malware:Mimikatz',
    explains: 'Free-text `content:` searches raw rule body — useful for finding gaps in vendor tagging.',
  },
];

const OPERATORS: Array<{ token: string; desc: string; example: string }> = [
  { token: 'field:value', desc: 'Match a specific field.', example: 'severity:high' },
  { token: 'field:"phrase"', desc: 'Quote multi-word values.', example: 'title:"cobalt strike"' },
  { token: 'AND', desc: 'Both sides must match.', example: 'source:sigma AND severity:high' },
  { token: 'OR', desc: 'Either side matches.', example: 'source:sigma OR source:elastic' },
  { token: 'NOT', desc: 'Excludes matching rules.', example: 'severity:critical NOT source:sigma' },
  { token: '( ... )', desc: 'Grouping / precedence.', example: '(source:sigma OR source:elastic) AND severity:high' },
  { token: '*', desc: 'Wildcard.', example: 'title:power*' },
  { token: 'bare word', desc: 'No prefix = substring across title + description + tags.', example: 'powershell' },
];

export function QueryReference() {
  const { data, isLoading } = useQueryFields();
  const fields = data?.fields || [];

  return (
    <div className="space-y-8 max-w-5xl">
      <div>
        <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">
          Query Reference
        </h1>
        <p className="text-xs text-gray-500 mt-1 font-mono">
          how to query the detection catalog — syntax + every field you can filter on
        </p>
      </div>

      {/* Try it strip */}
      <div
        className="bg-gradient-to-r from-matrix-500/10 via-cyan-500/5 to-transparent border border-matrix-500/30 px-5 py-4"
        style={clipMd}
      >
        <div className="text-[10px] font-mono text-matrix-400 uppercase tracking-[0.2em] mb-2">
          Try it
        </div>
        <div className="text-xs font-mono text-gray-300 leading-relaxed">
          Copy any recipe below and paste it into the search bar on{' '}
          <Link to="/detections" className="text-matrix-500 hover:text-matrix-400 border-b border-dotted border-matrix-500/40">
            /detections
          </Link>{' '}
          — or click a recipe to open the filtered view directly.
        </div>
      </div>

      {/* Recipes */}
      <section>
        <SectionHead title="Recipes" subtitle="real queries a DE would run" />
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {RECIPES.map((r) => (
            <Link
              key={r.query}
              to={`/detections?q=${encodeURIComponent(r.query)}`}
              className="group block bg-void-850 border border-void-700 hover:border-matrix-500/50 p-3 transition-colors"
              style={clipSm}
            >
              <div className="text-xs font-display font-semibold text-white mb-1 group-hover:text-matrix-400">
                {r.title}
              </div>
              <div className="text-xs font-mono text-matrix-500 mb-1.5 break-all">
                {r.query}
              </div>
              <div className="text-[11px] text-gray-500 leading-snug">
                {r.explains}
              </div>
            </Link>
          ))}
        </div>
      </section>

      {/* Operators */}
      <section>
        <SectionHead title="Syntax" subtitle="lucene-flavored operators supported by the bar" />
        <div className="border border-void-700 overflow-x-auto" style={clipSm}>
          <table className="w-full text-xs font-mono">
            <thead className="bg-void-900 text-gray-500 uppercase tracking-wider">
              <tr>
                <th className="px-3 py-2 text-left font-display font-semibold w-40">Token</th>
                <th className="px-3 py-2 text-left font-display font-semibold">Description</th>
                <th className="px-3 py-2 text-left font-display font-semibold">Example</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-void-800">
              {OPERATORS.map((op) => (
                <tr key={op.token} className="hover:bg-void-850">
                  <td className="px-3 py-2 text-matrix-500 whitespace-nowrap">{op.token}</td>
                  <td className="px-3 py-2 text-gray-300">{op.desc}</td>
                  <td className="px-3 py-2 text-cyan-400">
                    <code>{op.example}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-3 text-[11px] font-mono text-gray-500 leading-relaxed">
          Adjacent tokens without an explicit operator behave as AND. Fuzzy (~) and
          proximity queries are not supported. Malformed queries return an inline
          error under the search bar with a position hint.
        </div>
      </section>

      {/* Field reference */}
      <section>
        <SectionHead
          title="Fields"
          subtitle={isLoading ? 'loading…' : `${fields.length} queryable fields`}
        />
        {isLoading ? (
          <div className="h-40 bg-void-800 animate-pulse" style={clipSm} />
        ) : (
          <div className="space-y-2">
            {fields.map((f) => (
              <div
                key={f.aliases.join('|')}
                className="bg-void-850 border border-void-700 px-4 py-3"
                style={clipSm}
              >
                <div className="flex items-baseline gap-2 flex-wrap mb-1.5">
                  {f.aliases.map((a, i) => (
                    <span key={a} className="text-xs font-mono">
                      <span className="text-matrix-500">{a}</span>
                      <span className="text-matrix-500/60">:</span>
                      {i < f.aliases.length - 1 && <span className="text-gray-600 mx-1">·</span>}
                    </span>
                  ))}
                  <span className="ml-auto text-[10px] font-mono text-gray-600 uppercase tracking-wider">
                    {f.kind === 'list_mitre_group' || f.kind === 'list_mitre_software'
                      ? 'lookup'
                      : f.kind === 'list'
                        ? 'multi'
                        : f.kind === 'text_multi'
                          ? 'multi-text'
                          : 'text'}
                  </span>
                </div>
                <div className="text-xs text-gray-300 mb-2 leading-snug">
                  {f.description}
                </div>
                {f.examples.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {f.examples.map((ex) => (
                      <Link
                        key={ex}
                        to={`/detections?q=${encodeURIComponent(ex)}`}
                        className="text-[10px] font-mono text-cyan-400 bg-cyan-500/5 border border-cyan-500/20 px-1.5 py-0.5 hover:bg-cyan-500/10 hover:border-cyan-500/40 transition-colors"
                      >
                        {ex}
                      </Link>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Keyboard shortcuts */}
      <section>
        <SectionHead title="Keyboard" subtitle="site-wide shortcuts on the Detections page" />
        <div className="border border-void-700 overflow-x-auto" style={clipSm}>
          <table className="w-full text-xs font-mono">
            <thead className="bg-void-900 text-gray-500 uppercase tracking-wider">
              <tr>
                <th className="px-3 py-2 text-left font-display font-semibold w-32">Key</th>
                <th className="px-3 py-2 text-left font-display font-semibold">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-void-800">
              <tr className="hover:bg-void-850">
                <td className="px-3 py-2 text-matrix-500"><kbd>/</kbd></td>
                <td className="px-3 py-2 text-gray-300">Focus the search bar.</td>
              </tr>
              <tr className="hover:bg-void-850">
                <td className="px-3 py-2 text-matrix-500"><kbd>Cmd</kbd> / <kbd>Ctrl</kbd> + <kbd>F</kbd></td>
                <td className="px-3 py-2 text-gray-300">Open the filters sheet.</td>
              </tr>
              <tr className="hover:bg-void-850">
                <td className="px-3 py-2 text-matrix-500"><kbd>↑</kbd> <kbd>↓</kbd></td>
                <td className="px-3 py-2 text-gray-300">Navigate typeahead suggestions in the search bar.</td>
              </tr>
              <tr className="hover:bg-void-850">
                <td className="px-3 py-2 text-matrix-500"><kbd>Tab</kbd> / <kbd>Enter</kbd></td>
                <td className="px-3 py-2 text-gray-300">Accept the highlighted suggestion. Enter with no highlight submits the query.</td>
              </tr>
              <tr className="hover:bg-void-850">
                <td className="px-3 py-2 text-matrix-500"><kbd>Esc</kbd></td>
                <td className="px-3 py-2 text-gray-300">Close the typeahead / dismiss the filter sheet.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* Footnote — schema note */}
      <section>
        <SectionHead title="Notes" subtitle="the small print" />
        <ul className="text-xs text-gray-400 space-y-2 leading-relaxed">
          <li>
            <span className="text-matrix-500">•</span> MITRE Group / Software aliases resolve
            automatically. <code className="text-cyan-400 bg-void-800 px-1">actor:&quot;Cozy Bear&quot;</code>{' '}
            and <code className="text-cyan-400 bg-void-800 px-1">actor:G0016</code> return the
            same rules.
          </li>
          <li>
            <span className="text-matrix-500">•</span> List fields (techniques, groups, tags…)
            use exact-value matching. <code className="text-cyan-400 bg-void-800 px-1">tech:T1059</code>{' '}
            matches only T1059, never T1059.001.
          </li>
          <li>
            <span className="text-matrix-500">•</span> Bare text with no colon searches title,
            description, and tags. To search inside the rule body itself use{' '}
            <code className="text-cyan-400 bg-void-800 px-1">content:</code>.
          </li>
          <li>
            <span className="text-matrix-500">•</span> Query URLs are shareable —{' '}
            <code className="text-cyan-400 bg-void-800 px-1">/detections?q=…</code> preserves the
            full query.
          </li>
        </ul>
      </section>
    </div>
  );
}

function SectionHead({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div className="flex items-baseline gap-3 mb-3">
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
