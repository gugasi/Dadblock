# Changelog

## Unreleased

Known cleanup, tracked honestly rather than hidden:

- Remove the leftover `console.log` calls (about 20).
- Delete four unused variables that ESLint reports (`lastUrlSPA`, `hasSupportedQuote`, `MAX_FINDING_CHARS`, `JUDGE_JUDGMENTS`).
- Split `background.js` and `content.js` (each about 4,000+ lines) into smaller modules.
- Widen the PII redactor beyond US-style formats and add tests for each new format.

## 1.1.0 (published on the Chrome Web Store)

- New: Dad's Report, a plain-English look at what each page is really doing.
- New: Shop Check and a one-tap domain age lookup.
- New: "Heads-up" notes (popup only) instead of scary banners.
- Better: fewer false alarms (login buttons, one-time codes you asked for, ordinary buttons).
- Better: sign-in and payment windows from trusted providers open properly; search results pages are no longer scanned.
- Better: online whiteboards, design tools and document editors keep working; private documents and boards are never scanned.
- Better: anything the extension cannot confirm now says "Page not verified".

The code in `extension/` at tag `v1.1.0` is exactly what was submitted to the Web Store.
