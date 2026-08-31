import { useEffect } from 'react';

const SITE = 'Detection Explorer';
const DEFAULT_DESCRIPTION =
  'Open-source detection rules from thirteen repositories in one schema, mapped to MITRE ATT&CK, with the observables each rule keys on.';

/** Per-page <title> and meta description so shared links and search
 * results say what the page is. Restores the defaults on unmount. */
export function useDocumentMeta(title: string | null | undefined, description?: string | null) {
  useEffect(() => {
    if (typeof document === 'undefined') return;
    const prevTitle = document.title;
    const meta = document.querySelector('meta[name="description"]') as HTMLMetaElement | null;
    const prevDesc = meta?.content;
    document.title = title ? `${title} · ${SITE}` : SITE;
    if (meta) meta.content = (description || DEFAULT_DESCRIPTION).slice(0, 300);
    return () => {
      document.title = prevTitle;
      if (meta && prevDesc !== undefined) meta.content = prevDesc;
    };
  }, [title, description]);
}
