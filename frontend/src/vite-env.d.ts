/// <reference types="vite/client" />

// Injected at build time by the `define` block in vite.config.ts.
declare const __APP_VERSION__: string;
// Headline counts baked at build (production only; null in dev/tests).
// Shape mirrors BakedSnapshot in vite.config.ts; typed in constants/snapshot.ts.
declare const __DE_SNAPSHOT__: unknown;

interface ImportMetaEnv {
  readonly VITE_API_URL: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
