import js from '@eslint/js';
import globals from 'globals';

export default [
  { ignores: ['node_modules/**', 'extension/rules.json'] },
  js.configs.recommended,
  {
    files: ['extension/**/*.js'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: { ...globals.browser, ...globals.serviceworker, chrome: 'readonly', LanguageModel: 'readonly', ai: 'readonly' },
    },
    rules: {
      'no-unused-vars': ['warn', { args: 'none', caughtErrors: 'none' }],
      'no-empty': ['warn', { allowEmptyCatch: true }],
      // The sanitisers deliberately strip control characters from page text.
      'no-control-regex': 'off',
    },
  },
  {
    // Page-level and classic scripts are not ES modules.
    files: ['extension/content.js', 'extension/injected.js', 'extension/behavior-probe.js', 'extension/report-collector.js', 'extension/video-player-module.js'],
    languageOptions: { sourceType: 'script' },
  },
  {
    files: ['tests/**/*.mjs', 'eslint.config.js'],
    languageOptions: { ecmaVersion: 2023, sourceType: 'module', globals: globals.node },
  },
];
