/**
 * MCP server (#92 S4.10): how to connect an AI assistant to the corpus
 * through the detection-explorer-mcp package, what it can answer, and
 * the tools it exposes. Static content plus the live rule count; the
 * content lives in ./mcp/content.ts.
 */

import { Link } from 'react-router-dom';
import { CopyButton } from '../components/ruledetail/CopyButton';
import { useDocumentMeta } from '../hooks/useDocumentMeta';
import { useStatistics } from '../hooks/useDetections';
import { clipSm, clipMd } from '../constants/style';
import { CLIENTS, DIFFERENCES, MCP_PACKAGE, NPM_URL, SOURCE_URL, TOOLS, WORKFLOWS } from './mcp/content';

export function McpServer() {
  useDocumentMeta(
    'MCP server',
    'Connect Claude, Cursor or VS Code to 15,000+ open-source detection rules: search, diff, porting gaps and ATT&CK actor coverage through the detection-explorer-mcp server.',
  );
  const { data: stats } = useStatistics();
  const ruleCount = stats?.total ? stats.total.toLocaleString('en-US') : '15,000+';

  return (
    <div className="space-y-8 max-w-5xl">
      <div>
        <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">MCP Server</h1>
        <p className="text-xs text-gray-500 mt-1 font-mono">
          {MCP_PACKAGE} // ask your AI assistant about {ruleCount} detection rules
        </p>
      </div>

      <div
        className="bg-gradient-to-r from-matrix-500/10 via-cyan-500/5 to-transparent border border-matrix-500/30 px-5 py-4 space-y-2"
        style={clipMd}
      >
        <p className="text-sm text-gray-200 leading-relaxed">
          Connect Claude, Cursor, VS Code or any{' '}
          <a
            href="https://modelcontextprotocol.io"
            target="_blank"
            rel="noopener noreferrer"
            className="text-matrix-500 hover:text-matrix-400 border-b border-dotted border-matrix-500/40"
          >
            MCP
          </a>{' '}
          client to the Detection Explorer corpus. Your assistant can search {ruleCount} rules from thirteen
          repositories, open and diff them observable by observable, find rules one vendor has and another lacks,
          and score ATT&amp;CK coverage for a threat actor against the repositories you actually run.
        </p>
        <p className="text-xs font-mono text-gray-400">
          Needs Node.js 20 or newer. No account or API key.
        </p>
      </div>

      <section>
        <SectionHead title="Install" subtitle="pick your client" />
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          {CLIENTS.map((c) => (
            <div key={c.name} className="bg-void-850 border border-void-700 p-4 min-w-0" style={clipSm}>
              <div className="flex items-start justify-between gap-3 mb-2">
                <div className="min-w-0">
                  <div className="text-sm font-display font-semibold text-white">{c.name}</div>
                  <div className="text-[11px] font-mono text-gray-500 break-words">{c.where}</div>
                </div>
                <CopyButton text={c.code} label="Copy" />
              </div>
              <pre className="text-xs font-mono text-cyan-300 bg-void-900 border border-void-800 p-3 overflow-x-auto whitespace-pre">
                <code>{c.code}</code>
              </pre>
              {c.note && <p className="mt-2 text-[11px] text-gray-500 leading-snug">{c.note}</p>}
            </div>
          ))}
        </div>
      </section>

      <section>
        <SectionHead title="What you can ask" subtitle="copy a prompt into your assistant" />
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {WORKFLOWS.map((w) => (
            <div key={w.title} className="bg-void-850 border border-void-700 p-4 flex flex-col gap-2 min-w-0" style={clipSm}>
              <div className="flex items-start justify-between gap-3">
                <div className="text-sm font-display font-semibold text-white">{w.title}</div>
                <CopyButton text={w.prompt} label="Copy" />
              </div>
              <p className="text-xs font-mono text-matrix-400 leading-relaxed">&quot;{w.prompt}&quot;</p>
              <p className="text-[11px] text-gray-400 leading-snug">{w.why}</p>
              <div className="flex flex-wrap gap-1.5 mt-auto pt-1">
                {w.tools.map((t) => (
                  <span
                    key={t}
                    className="text-[10px] font-mono text-cyan-400 bg-cyan-500/5 border border-cyan-500/20 px-1.5 py-0.5"
                  >
                    {t}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      <section>
        <SectionHead title="Why this server" subtitle="what the corpus behind it does differently" />
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {DIFFERENCES.map((d) => (
            <div key={d.title} className="bg-void-850 border border-void-700 p-4" style={clipSm}>
              <div className="text-sm font-display font-semibold text-white mb-1.5">{d.title}</div>
              <p className="text-xs text-gray-400 leading-relaxed">{d.body}</p>
            </div>
          ))}
        </div>
      </section>

      <section>
        <SectionHead title="Tools" subtitle={`${TOOLS.length} read-only tools`} />
        <div className="border border-void-700 overflow-x-auto" style={clipSm}>
          <table className="w-full text-xs font-mono">
            <thead className="bg-void-900 text-gray-500 uppercase tracking-wider">
              <tr>
                <th scope="col" className="px-3 py-2 text-left font-display font-semibold w-52">Tool</th>
                <th scope="col" className="px-3 py-2 text-left font-display font-semibold">What it answers</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-void-800">
              {TOOLS.map((t) => (
                <tr key={t.name} className="hover:bg-void-850">
                  <td className="px-3 py-2 text-matrix-500 whitespace-nowrap">{t.name}</td>
                  <td className="px-3 py-2 text-gray-300">{t.does}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section>
        <SectionHead title="Notes" subtitle="limits, licensing, source" />
        <ul className="text-xs text-gray-400 space-y-2 leading-relaxed">
          <li>
            <span className="text-matrix-500">&bull;</span> Coverage answers describe public rules, not the detections
            deployed in any environment. How each number is counted is on the{' '}
            <Link to="/methodology" className="text-matrix-500 hover:text-matrix-400">methodology</Link> page.
          </li>
          <li>
            <span className="text-matrix-500">&bull;</span> The public API allows 40 requests per 10 seconds per IP. The
            server waits out one rate-limit response, then tells the assistant to slow down.
          </li>
          <li>
            <span className="text-matrix-500">&bull;</span> Rules keep their upstream licenses. Check a rule&apos;s
            license on its page before redistributing its content.
          </li>
          <li>
            <span className="text-matrix-500">&bull;</span> The search syntax the assistant uses is the one on the{' '}
            <Link to="/query" className="text-matrix-500 hover:text-matrix-400">query reference</Link>.
          </li>
          <li>
            <span className="text-matrix-500">&bull;</span> Package on{' '}
            <a href={NPM_URL} target="_blank" rel="noopener noreferrer" className="text-matrix-500 hover:text-matrix-400">
              npm
            </a>
            , source and issues on{' '}
            <a href={SOURCE_URL} target="_blank" rel="noopener noreferrer" className="text-matrix-500 hover:text-matrix-400">
              GitHub
            </a>
            . Apache-2.0.
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
      <h2 className="text-base font-display font-bold text-white tracking-wider uppercase">{title}</h2>
      {subtitle && (
        <span className="text-[10px] text-gray-500 font-mono uppercase tracking-wider">// {subtitle}</span>
      )}
    </div>
  );
}
