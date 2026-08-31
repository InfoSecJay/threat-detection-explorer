/// <reference types="vite/client" />

// Injected at build time by the `define` block in vite.config.ts.
declare const __APP_VERSION__: string;

interface ImportMetaEnv {
  readonly VITE_API_URL: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
