import js from '@eslint/js';
import tseslint from 'typescript-eslint';
export default tseslint.config(
  { ignores: ['dist/', 'node_modules/', 'playwright-report/', 'test-results/'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  { files: ['scripts/**/*.mjs', 'e2e/**/*.mjs'], languageOptions: { globals: { URL: 'readonly', fetch: 'readonly', console: 'readonly', process: 'readonly' } } },
  { rules: { '@typescript-eslint/no-non-null-assertion': 'off', '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }] } },
);
