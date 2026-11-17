# Architecture

## Components

| File | Runs in | Job |
| --- | --- | --- |
| `background.js` | Service worker | Coordinates scans, caches results, manages ad-block rules and per-tab state |
| `content.js` | Page (isolated world) | Extracts the visible text, requests analysis, shows warning banners |
| `report-collector.js` | Page (isolated world) | Measures observable facts for Dad's Report (outside hosts, form targets) |
| `injected.js`, `behavior-probe.js` | Page (MAIN world) | Pop-under and click-trap blocking; counts permission requests the page makes |
| `offscreen.js` | Offscreen document | Hosts Chrome's Prompt API, which the service worker cannot reach |
| `modes/local/detector.js` | Service worker | Prompts and two-stage on-device detection |
| `modes/cloud/detector.js` | Service worker | Cloud analysis through the Worker, or direct with the user's own key |
| `utils/redactor.js` | Service worker | Removes personal details locally before anything is sent |
| `utils/audit-verdicts.js` | Shared | Validates model output and calibrates the verdict |
| `popup*.js`, `settings.js`, `onboarding.js` | Extension pages | The user interface |
| `rules.json` | declarativeNetRequest | Bundled ad and tracker rules (updatable data, never code) |

## Decisions worth explaining

**Offscreen document for on-device AI.** The Prompt API needs a document context, and an MV3 service worker is not one.
An offscreen document hosts it, is created only for the offline engine and shows no UI.

**MAIN-world scripts for pop-under blocking.** Pop-unders are opened by the page's own JavaScript, so the blocker has to
wrap `window.open` in the page's context. Real sign-in and payment windows need a recent user interaction and a
relevant flow, and known workspace sites are left alone so web apps keep working.

**Validate the model, do not trust it.** Model answers must match a strict schema. Every quoted piece of evidence must
appear in the text that was supplied, and the final severity is calibrated from the grounded findings rather than taken
from the model's own label. Anything that fails validation becomes "Page not verified" instead of a guess.

**Redact before the network.** In Hybrid Cloud mode, personal details are removed on the user's device first, and the
Worker never receives them.

**Rules as data.** Ad and tracker rules can be refreshed from a server without shipping a new extension, but they are
JSON data, never code, which keeps the extension free of remotely hosted code.

**Honest copy.** Reports are template-based: each sentence is tied to a measured fact, so the report cannot invent a
claim. Dadblock never labels a site "safe".

## Tests

- `tests/redactor.test.mjs`: every redaction type the store listing promises, plus a documented limitation.
- `tests/verdicts.test.mjs`: schema, grounding and calibration rules.
- `tests/package.test.mjs`: manifest validity, referenced files exist, permissions match the listing, every script parses, no secrets, rules file is valid.
- `tests/e2e/load-extension.py`: loads the unpacked extension in Chromium.
