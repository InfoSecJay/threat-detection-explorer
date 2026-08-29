// ESLint flat config (ESLint 9 + typescript-eslint 8). Issue #45.
//
// Mirrors the Vite react-ts template so the rule set is conventional:
// recommended JS + TS rules, React hooks correctness, and the
// react-refresh guard that keeps HMR working. `tsc --noEmit` already
// enforces unused locals/params, so the TS unused-vars rule here is
// tuned to agree with it (underscore-prefixed names are intentional).
import js from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist', 'node_modules', 'coverage'] },
  {
    files: ['**/*.{ts,tsx}'],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2020,
      globals: { ...globals.browser, ...globals.node },
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    linterOptions: {
      reportUnusedDisableDirectives: 'error',
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'react-refresh/only-export-components': [
        'warn',
        { allowConstantExport: true },
      ],
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
          // `const { offset, limit, ...rest } = filters` to strip keys
          // is the idiom for query-key scoping; tsc allows it too.
          ignoreRestSiblings: true,
        },
      ],
    },
  },
  {
    // Test files lean on `any` for fixture shapes and mock return
    // values; the type-checker still runs on them via tsc.
    files: ['**/__tests__/**', '**/*.test.{ts,tsx}', 'src/test/**'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
    },
  },
);
