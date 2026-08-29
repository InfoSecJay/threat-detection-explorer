/** Syntax-highlighted rule text with the site's dark code styling. */

import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism';

const languageMap: Record<string, string> = {
  sigma: 'yaml',
  yaml: 'yaml',
  eql: 'sql',
  kql: 'sql',
  esql: 'sql',
  spl: 'sql',
  splunk: 'sql',
  mql: 'javascript',
  yara: 'c',
  lucene: 'javascript',
  json: 'json',
  unknown: 'yaml',
};

export function CodeBlock({ language, code, fallback }: { language: string | null | undefined; code: string | null | undefined; fallback: string }) {
  return (
    <div className="rounded-lg overflow-hidden border border-void-700">
      <SyntaxHighlighter
        language={languageMap[language?.toLowerCase() || 'unknown'] || 'yaml'}
        style={oneDark}
        customStyle={{
          margin: 0,
          padding: '1rem',
          fontSize: '0.875rem',
          lineHeight: '1.625',
          background: 'rgb(17, 24, 39)',
        }}
        showLineNumbers
        lineNumberStyle={{
          minWidth: '2.5em',
          paddingRight: '1em',
          color: '#4b5563',
          borderRight: '1px solid #374151',
          marginRight: '1em',
        }}
      >
        {code || fallback}
      </SyntaxHighlighter>
    </div>
  );
}
