// Dadblock Content Script
// Extracts visible page content, requests analysis, and displays protective UI.

// ==========================================
// SETTINGS AND SHARED STATE
// ==========================================

const SCAN_SETTING_KEYS = [
  'enableAutoScan',
  'autoScan',
  'bannerEnabled',
  'showBanner',
  'scanChanges',
  'selectedMode',
  'activeMode',
];

let scanSettingsLoaded = false;
let scanSettingsRevision = 0;
let scanSettingsValues = {};

let enableAutoScan = false;
let bannerEnabled = false;
let scanChanges = false;
let selectedScanMode = 'cloud';

let backgroundBannerEnabled = true;

let isUpdatingBanner = false;
let analysisInProgress = false;
let requestAnalysisPending = false;
let threatDetectedForPage = false;
let quotaBannerDismissed = false;

let lastAnalyzedContent = '';
let scanAttempts = 0;
let insufficientContentRetries = 0;
let transientScanRetries = 0;

const MAX_SCAN_ATTEMPTS = 3;
const MAX_INSUFFICIENT_CONTENT_RETRIES = 2;
const MAX_TRANSIENT_SCAN_RETRIES = 1;

let currentUrl = window.location.href;
let lastUrlSPA = currentUrl;

let analysisTimeout = null;
let mutationBurstStartedAt = 0;
const MUTATION_MAX_WAIT_MS = 4000;
let observer = null;
let activeScanContext = null;
let scanGeneration = 0;

const scheduledScanTimers = new Map();

let _cosmeticDisabledForThisPage = false;

// ==========================================
// SETTINGS HELPERS
// ==========================================

function resolveBooleanSetting(values, primaryKey, fallbackKey, defaultValue) {
  if (typeof values[primaryKey] === 'boolean') {
    return values[primaryKey];
  }

  if (fallbackKey && typeof values[fallbackKey] === 'boolean') {
    return values[fallbackKey];
  }

  return defaultValue;
}

function resolveScanMode(values) {
  const mode = values.selectedMode || values.activeMode;
  return mode === 'local' ? 'local' : 'cloud';
}

function requestedModeForResult(result) {
  if (
    result?.requestedMode === 'local' ||
    result?.requestedMode === 'cloud'
  ) {
    return result.requestedMode;
  }

  if (
    result?.mode === 'local' &&
    ['ERROR', 'RATE_LIMITED', 'QUOTA_EXCEEDED'].includes(result.fallbackFrom)
  ) {
    return 'cloud';
  }

  return result?.mode === 'local' || result?.mode === 'cloud'
    ? result.mode
    : null;
}

function resultMatchesSelectedMode(result) {
  if (!result || isEasterEggResult(result)) {
    return true;
  }

  const requestedMode = requestedModeForResult(result);

  return requestedMode
    ? requestedMode === selectedScanMode
    : result.conclusive !== true;
}

function getScanSettingsSnapshot() {
  return {
    ok: scanSettingsLoaded,
    enableAutoScan,
    bannerEnabled,
    scanChanges,
    selectedMode: selectedScanMode,
  };
}

function applyScanSettings(values) {
  const wasAutoScanEnabled = enableAutoScan;
  const wereChangesEnabled = scanChanges;
  const wasLoaded = scanSettingsLoaded;
  const previousMode = selectedScanMode;

  scanSettingsValues = { ...values };

  enableAutoScan = resolveBooleanSetting(
    scanSettingsValues,
    'enableAutoScan',
    'autoScan',
    true
  );

  bannerEnabled = resolveBooleanSetting(
    scanSettingsValues,
    'bannerEnabled',
    'showBanner',
    true
  );

  scanChanges = resolveBooleanSetting(
    scanSettingsValues,
    'scanChanges',
    null,
    true
  );

  selectedScanMode = resolveScanMode(scanSettingsValues);
  scanSettingsLoaded = true;

  if (wasLoaded && previousMode !== selectedScanMode) {
    resetForModeChange();
    refreshScanObserver();
  }

  if (!bannerEnabled) {
    clearDadblockUI();
  }

  if (wasAutoScanEnabled && !enableAutoScan) {
    cancelAutomaticScanning();
  } else if (wereChangesEnabled && !scanChanges) {
    if (observer) {
      observer.disconnect();
    }

    clearTimeout(analysisTimeout);
    analysisTimeout = null;
    mutationBurstStartedAt = 0;
  }

  return getScanSettingsSnapshot();
}

async function readScanSettings() {
  // A storage change during a read must not restore an older setting.
  for (let attempt = 0; attempt < 3; attempt++) {
    const revision = scanSettingsRevision;

    try {
      if (!chrome.runtime?.id) {
        throw new Error('Extension context invalidated');
      }

      const values = await chrome.storage.local.get(SCAN_SETTING_KEYS);

      if (revision !== scanSettingsRevision) {
        continue;
      }

      return applyScanSettings(values);
    } catch {
      scanSettingsLoaded = false;
      enableAutoScan = false;
      bannerEnabled = false;
      scanChanges = false;

      cancelAutomaticScanning();
      clearDadblockUI();

      return getScanSettingsSnapshot();
    }
  }

  scanSettingsLoaded = false;
  enableAutoScan = false;
  bannerEnabled = false;
  scanChanges = false;

  cancelAutomaticScanning();
  clearDadblockUI();

  return getScanSettingsSnapshot();
}

function bannersAllowed(analysisResult = null) {
  return (
    !pageDisposed &&
    scanSettingsLoaded &&
    bannerEnabled !== false &&
    backgroundBannerEnabled !== false &&
    analysisResult?.bannerEnabled !== false &&
    resultMatchesSelectedMode(analysisResult)
  );
}

function rememberBackgroundBannerSetting(response) {
  if (
    !response ||
    typeof response !== 'object' ||
    !resultMatchesSelectedMode(response)
  ) {
    return;
  }

  if (typeof response.bannerEnabled === 'boolean') {
    backgroundBannerEnabled = response.bannerEnabled;
  }

  if (!bannersAllowed(response)) {
    clearDadblockUI();
  }
}

function getResultJudgment(result) {
  return typeof result?.judgment === 'string'
    ? result.judgment.trim().toUpperCase()
    : '';
}

function isDangerResult(result) {
  const judgment = getResultJudgment(result);

  return (
    judgment === 'WARNING' ||
    judgment === 'SCAM' ||
    judgment === 'THREAT'
  );
}

function isEasterEggResult(result) {
  return getResultJudgment(result) === 'EASTER_EGG';
}

// ==========================================
// BANNER EVIDENCE
// ==========================================

const MAX_BANNER_EVIDENCE_ITEMS = 2;
const MAX_BANNER_EVIDENCE_CHARS = 240;
const MAX_BANNER_DAD_TIP_CHARS = 320;

function normalizeBannerEvidenceText(value, limit = MAX_BANNER_EVIDENCE_CHARS) {
  if (typeof value !== 'string') {
    return '';
  }

  return value
    .replace(
      /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g,
      ' '
    )
    .replace(/^\s*(?:[-*•]\s+|\d+[.)]\s+)/, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, limit);
}

function getBannerEvidence(analysisResult) {
  if (
    !isDangerResult(analysisResult) ||
    !Array.isArray(analysisResult.evidence)
  ) {
    return [];
  }

  const points = [];
  const seen = new Set();

  // Bound processing even if a malformed background payload has many items.
  for (const value of analysisResult.evidence.slice(0, 12)) {
    const text = normalizeBannerEvidenceText(value);
    const identity = text.toLowerCase();

    if (!text || seen.has(identity)) {
      continue;
    }

    seen.add(identity);
    points.push(text);

    if (points.length === MAX_BANNER_EVIDENCE_ITEMS) {
      break;
    }
  }

  return points;
}

function renderBannerEvidence(shadow, analysisResult) {
  const section = shadow.getElementById('db-evidence-section');
  const list = shadow.getElementById('db-evidence-list');

  if (!section || !list) {
    return;
  }

  section.hidden = true;
  list.replaceChildren();

  const points = getBannerEvidence(analysisResult);

  if (points.length === 0) {
    return;
  }

  const fragment = document.createDocumentFragment();

  for (const text of points) {
    const item = document.createElement('li');

    const icon = document.createElement('span');
    icon.className = 'db-evidence-icon';
    icon.setAttribute('aria-hidden', 'true');
    icon.textContent = '⚠';

    const label = document.createElement('span');
    label.className = 'db-evidence-text';

    // Evidence can contain page/model text. Never interpret it as markup.
    label.textContent = text;

    item.append(icon, label);
    fragment.append(item);
  }

  list.replaceChildren(fragment);
  section.hidden = false;
}

// Result origin is application metadata, never a claim inferred from
// page text. Keep it separate from the model's explanation.
function renderBannerResultSource(shadow, result) {
  const source = shadow.getElementById('db-result-source');

  if (!source) {
    return;
  }

  source.hidden = true;
  source.textContent = '';

  if (
    result?.schemaVersion !== 2 ||
    (
      result.conclusive !== true &&
      getResultJudgment(result) !== 'INCONCLUSIVE'
    )
  ) {
    return;
  }

  const engineMode = result.engineMode || result.mode;

  if (engineMode !== 'local' && engineMode !== 'cloud') {
    return;
  }

  const isFallback =
    requestedModeForResult(result) === 'cloud' &&
    engineMode === 'local';

  let label = engineMode === 'local'
    ? 'Result from Local AI'
    : 'Result from Cloud AI';

  if (isFallback) {
    label += ' · Cloud fallback';
  } else if (result.cached === true || result.cacheHit === true) {
    label += ' · Cached result';
  }

  source.textContent = label;
  source.hidden = false;
}

function renderBannerDadTip(shadow, result) {
  const box = shadow.getElementById('db-dad-tip');

  if (!box) {
    return;
  }

  box.hidden = true;
  box.textContent = '';

  if (!isDangerResult(result)) {
    return;
  }

  const tip = normalizeBannerEvidenceText(
    result.dadTip,
    MAX_BANNER_DAD_TIP_CHARS
  );

  if (!tip) {
    return;
  }

  box.textContent = 'Dad’s tip: ' + tip;
  box.hidden = false;
}

// ==========================================
// MAIN THREAD YIELDING
// ==========================================

const yieldToMain = () => {
  if (typeof globalThis.scheduler?.yield === 'function') {
    return globalThis.scheduler.yield();
  }

  return new Promise(resolve => {
    window.setTimeout(resolve, 0);
  });
};

// ==========================================
// DADBLOCK UI: CLOSED SHADOW DOM
// ==========================================

let secureShadowHost = null;
let secureShadowRoot = null;
let currentShadowId = null;
let uiRenderVersion = 0;
let modalReturnFocus = null;

function getSecureShadowRoot(analysisResult = null) {
  if (!bannersAllowed(analysisResult)) {
    return null;
  }

  if (secureShadowRoot && secureShadowHost?.isConnected) {
    return secureShadowRoot;
  }

  if (!document.documentElement) {
    return null;
  }

  currentShadowId = 'db-guard-' + Math.random().toString(36).substring(2, 15);

  secureShadowHost = document.createElement('div');
  secureShadowHost.id = currentShadowId;

  secureShadowHost.style.cssText =
    'position: fixed; top: 0; left: 0; width: 100%; ' +
    'z-index: 2147483647; pointer-events: none;';

  // The host remains part of the page DOM; its contents use a closed root.
  secureShadowRoot = secureShadowHost.attachShadow({ mode: 'closed' });

  document.documentElement.appendChild(secureShadowHost);

  return secureShadowRoot;
}

function clearDadblockUI() {
  uiRenderVersion++;

  if (secureShadowRoot) {
    secureShadowRoot.innerHTML = '';
  }

  isUpdatingBanner = false;

  const previousFocus = modalReturnFocus;
  modalReturnFocus = null;

  if (previousFocus?.isConnected && typeof previousFocus.focus === 'function') {
    try {
      previousFocus.focus({ preventScroll: true });
    } catch {
      // The previous focus target may have been removed or disabled.
    }
  }
}

async function prepareUIRender(analysisResult = null) {
  if (
    scanSettingsLoaded &&
    !resultMatchesSelectedMode(analysisResult)
  ) {
    return null;
  }

  if (analysisResult?.bannerEnabled === false) {
    clearDadblockUI();
    return null;
  }

  const renderVersion = ++uiRenderVersion;
  const renderGeneration = scanGeneration;
  const renderUrl = window.location.href;
  const settings = await readScanSettings();

  if (
    renderVersion !== uiRenderVersion ||
    renderGeneration !== scanGeneration ||
    pageDisposed ||
    renderUrl !== window.location.href ||
    !settings.ok ||
    !bannersAllowed(analysisResult)
  ) {
    return null;
  }

  return getSecureShadowRoot(analysisResult);
}

// ==========================================
// DISMISSAL ACTIONS
// ==========================================

async function handleDismissal(action) {
  clearDadblockUI();

  const url = window.location.href;
  const origin = window.location.origin;
  const partAfterOrigin = url.substring(origin.length);

  if (action === 'once') {
    return;
  }

  if (action === 'today') {
    const pattern = origin + partAfterOrigin.substring(0, 16);
    const data = await chrome.storage.local.get(['ignoreRules']);
    const ignoreRules = Array.isArray(data.ignoreRules) ? data.ignoreRules : [];

    if (!ignoreRules.some(rule =>
      rule?.type === 'url_temporary' &&
      rule.pattern === pattern &&
      rule.expiry > Date.now()
    )) {
      await chrome.storage.local.set({
        ignoreRules: [
          ...ignoreRules,
          {
            type: 'url_temporary',
            pattern,
            timestamp: Date.now(),
            expiry: Date.now() + 24 * 60 * 60 * 1000,
          },
        ],
      });
    }

    return;
  }

  if (action === 'page_forever') {
    const data = await chrome.storage.local.get(['ignoreRules']);
    const ignoreRules = Array.isArray(data.ignoreRules) ? data.ignoreRules : [];

    if (!ignoreRules.some(rule =>
      rule?.type === 'url' && rule.pattern === url
    )) {
      await chrome.storage.local.set({
        ignoreRules: [
          ...ignoreRules,
          {
            type: 'url',
            pattern: url,
            timestamp: Date.now(),
          },
        ],
      });
    }

    return;
  }

  if (action === 'site_forever') {
    const domain = window.location.hostname;

    _cosmeticDisabledForThisPage = true;
    threatDetectedForPage = true;
    cancelAutomaticScanning();

    const data = await chrome.storage.local.get([
      'ignoreRules',
      'adBlockDisabledDomains',
      'cosmeticDisabledDomains',
    ]);

    const ignoreRules = Array.isArray(data.ignoreRules)
      ? data.ignoreRules
      : [];

    const adBlockDisabledDomains = Array.isArray(data.adBlockDisabledDomains)
      ? data.adBlockDisabledDomains
      : [];

    const cosmeticDisabledDomains = Array.isArray(data.cosmeticDisabledDomains)
      ? data.cosmeticDisabledDomains
      : [];

    const newIgnoreRules = ignoreRules.some(rule =>
      rule?.type === 'domain' && rule.pattern === domain
    )
      ? ignoreRules
      : [
          ...ignoreRules,
          {
            type: 'domain',
            pattern: domain,
            timestamp: Date.now(),
          },
        ];

    await chrome.storage.local.set({
      ignoreRules: newIgnoreRules,

      adBlockDisabledDomains: adBlockDisabledDomains.includes(domain)
        ? adBlockDisabledDomains
        : [...adBlockDisabledDomains, domain],

      cosmeticDisabledDomains: cosmeticDisabledDomains.includes(domain)
        ? cosmeticDisabledDomains
        : [...cosmeticDisabledDomains, domain],
    });

    window.location.reload();
  }
}

// ==========================================
// DISMISSAL MODAL
// ==========================================

async function showDismissModal() {
  const shadow = await prepareUIRender();

  if (!shadow) {
    return false;
  }

  modalReturnFocus = document.activeElement;
  isUpdatingBanner = true;

  try {
    shadow.innerHTML = `
      <style>
        .db-modal-overlay {
          pointer-events: auto;
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: rgba(11, 15, 25, 0.8);
          backdrop-filter: blur(8px);
          -webkit-backdrop-filter: blur(8px);
          z-index: 2147483647;
          display: flex;
          align-items: center;
          justify-content: center;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          animation: db-fade-in 0.2s ease-out;
        }

        .db-modal-box {
          background: #1E293B;
          border: 1px solid #334155;
          border-radius: 16px;
          width: 400px;
          max-width: 90%;
          padding: 28px;
          box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5);
          animation: db-scale-up 0.3s cubic-bezier(0.16, 1, 0.3, 1);
        }

        .db-modal-title {
          margin: 0 0 8px;
          font-size: 18px;
          color: #F8FAFC;
          font-weight: 700;
          display: flex;
          align-items: center;
          gap: 8px;
        }

        .db-modal-title svg {
          color: #38BDF8;
          width: 20px;
          height: 20px;
        }

        .db-modal-desc {
          margin: 0 0 24px;
          font-size: 14px;
          color: #94A3B8;
          line-height: 1.5;
        }

        .db-dismiss-option {
          display: block;
          width: 100%;
          text-align: left;
          padding: 14px 16px;
          margin-bottom: 8px;
          background: #0F172A;
          border: 1px solid #334155;
          border-radius: 12px;
          font-size: 14px;
          color: #E2E8F0;
          cursor: pointer;
          transition: all 0.2s;
          font-weight: 500;
        }

        .db-dismiss-option:hover {
          background: rgba(56, 189, 248, 0.1);
          border-color: #38BDF8;
          color: #38BDF8;
          transform: translateY(-1px);
        }

        .db-cancel-btn {
          margin-top: 16px;
          width: 100%;
          padding: 12px;
          background: transparent;
          border: none;
          color: #64748B;
          font-size: 14px;
          cursor: pointer;
          font-weight: 600;
          transition: color 0.2s;
        }

        .db-cancel-btn:hover {
          color: #F8FAFC;
        }

        @keyframes db-fade-in {
          from { opacity: 0; }
          to { opacity: 1; }
        }

        @keyframes db-scale-up {
          from {
            opacity: 0;
            transform: scale(0.95) translateY(10px);
          }
          to {
            opacity: 1;
            transform: scale(1) translateY(0);
          }
        }
      </style>

      <div class="db-modal-overlay" id="db-modal-bg"
           role="dialog" aria-modal="true"
           aria-labelledby="db-modal-title-id">
        <div class="db-modal-box">
          <h3 class="db-modal-title" id="db-modal-title-id">
            <svg viewBox="0 0 24 24" fill="none"
                 stroke="currentColor" stroke-width="2"
                 stroke-linecap="round" stroke-linejoin="round"
                 aria-hidden="true" focusable="false">
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
              <line x1="12" y1="9" x2="12" y2="13"></line>
              <line x1="12" y1="17" x2="12.01" y2="17"></line>
            </svg>
            Tell Dad to ignore this
          </h3>

          <p class="db-modal-desc">
            Dad just wants to keep you safe! How long should he look the other way?
          </p>

          <button type="button" class="db-dismiss-option" data-action="once">
            Just this once, Dad.
          </button>

          <button type="button" class="db-dismiss-option" data-action="today">
            Leave me alone for today (24h).
          </button>

          <button type="button" class="db-dismiss-option" data-action="page_forever">
            I trust this specific page forever.
          </button>

          <button type="button" class="db-dismiss-option" data-action="site_forever">
            I trust this entire website forever.
          </button>

          <button type="button" class="db-cancel-btn" id="db-cancel-dismiss">
            Nevermind, Dad knows best.
          </button>
        </div>
      </div>
    `;

    const focusableElements = Array.from(
      shadow.querySelectorAll('.db-dismiss-option, .db-cancel-btn')
    );

    focusableElements[0]?.focus();

    shadow.getElementById('db-modal-bg').addEventListener('keydown', event => {
      if (event.key === 'Escape') {
        event.preventDefault();
        clearDadblockUI();
        return;
      }

      if (event.key !== 'Tab' || focusableElements.length === 0) {
        return;
      }

      const first = focusableElements[0];
      const last = focusableElements[focusableElements.length - 1];
      const activeElement = shadow.activeElement;

      if (event.shiftKey && activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    });

    shadow.querySelectorAll('.db-dismiss-option').forEach(button => {
      button.addEventListener('click', () => {
        handleDismissal(button.dataset.action).catch(() => {
          clearDadblockUI();
        });
      });
    });

    shadow.getElementById('db-cancel-dismiss').addEventListener(
      'click',
      clearDadblockUI
    );

    shadow.getElementById('db-modal-bg').addEventListener('click', event => {
      if (event.target === event.currentTarget) {
        clearDadblockUI();
      }
    });

    return true;
  } finally {
    isUpdatingBanner = false;
  }
}

// ==========================================
// WARNING AND THREAT BANNERS
// ==========================================

async function showWarningBanner(analysisResult, isStage1 = false) {
  if (!analysisResult || typeof analysisResult !== 'object') {
    return false;
  }

  if (
    scanSettingsLoaded &&
    !resultMatchesSelectedMode(analysisResult)
  ) {
    return false;
  }

  if (analysisResult.bannerEnabled === false) {
    clearDadblockUI();
    return false;
  }

  if (isStage1) {
    return false;
  }

  const isEasterEgg = isEasterEggResult(analysisResult);

  if (!isEasterEgg && !isDangerResult(analysisResult)) {
    return false;
  }

  // Whisper tier: streaming notes live in the popup only. They never
  // interrupt the page.
  if (!isEasterEgg && analysisResult.warningKind === 'streaming') {
    return false;
  }

  const shadow = await prepareUIRender(analysisResult);

  if (!shadow) {
    return false;
  }

  const isWarning = getResultJudgment(analysisResult) === 'WARNING';

  let themeGlow;
  let themeBorder;
  let themeBg;
  let themeIconColor;
  let titleText;
  let subText;
  let shieldSvg;

  if (isEasterEgg) {
    themeGlow = 'rgba(56, 189, 248, 0.4)';
    themeBorder = 'rgba(56, 189, 248, 0.3)';
    themeBg =
      'linear-gradient(135deg, rgba(29, 78, 216, 0.95), rgba(56, 189, 248, 0.95))';
    themeIconColor = '#FFFFFF';

    titleText = typeof analysisResult.title === 'string'
      ? analysisResult.title
      : "🏠 DAD'S HOUSE";

    subText = typeof analysisResult.analysis === 'string'
      ? analysisResult.analysis
      : 'Well would you look at that... you found the best website on the internet. Pull up a chair and stay a while, kiddo. ☕';

    shieldSvg = `
      <svg viewBox="0 0 100 100" width="24" height="24"
           fill="none" stroke="white" stroke-width="6"
           stroke-linecap="round" stroke-linejoin="round"
           aria-hidden="true" focusable="false">
        <path d="M 15 45 L 85 45" />
        <path d="M 22 45 Q 32 70 42 45 Z" fill="white" />
        <path d="M 58 45 Q 68 70 78 45 Z" fill="white" />
        <path d="M 38 75 Q 50 85 68 70" fill="none" />
      </svg>
    `;
  } else {
    themeGlow = isWarning
      ? 'rgba(245, 158, 11, 0.4)'
      : 'rgba(220, 38, 38, 0.4)';

    themeBorder = isWarning
      ? 'rgba(245, 158, 11, 0.3)'
      : 'rgba(220, 38, 38, 0.3)';

    themeBg = isWarning
      ? 'rgba(30, 20, 10, 0.85)'
      : 'rgba(30, 10, 10, 0.85)';

    themeIconColor = isWarning ? '#F59E0B' : '#EF4444';

    titleText = isWarning
      ? analysisResult.warningKind === 'streaming'
        ? 'Dad has a heads-up'
        : 'Dad recommends caution here.'
      : 'Possible scam detected.';

    subText = typeof analysisResult.analysis === 'string'
      ? analysisResult.analysis
      : isWarning
        ? 'Check the observed details before continuing.'
        : 'Read the evidence before sharing details or paying.';

    shieldSvg = `
      <svg width="24" height="24" viewBox="0 0 24 24"
           fill="none" stroke="${themeIconColor}" stroke-width="2"
           stroke-linecap="round" stroke-linejoin="round"
           aria-hidden="true" focusable="false">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        <line x1="12" y1="8" x2="12" y2="12" />
        <line x1="12" y1="16" x2="12.01" y2="16" />
      </svg>
    `;
  }

  isUpdatingBanner = true;

  try {
    shadow.innerHTML = `
      <style>
        [hidden] {
          display: none !important;
        }

        .db-glass-banner {
          box-sizing: border-box;
          pointer-events: auto;
          position: fixed;
          top: 16px;
          left: 50%;
          transform: translateX(-50%) translateY(-20px);
          opacity: 0;
          width: 90%;
          max-width: 600px;
          max-height: calc(100vh - 32px);
          overflow-y: auto;
          background: ${themeBg};
          backdrop-filter: blur(16px) saturate(180%);
          -webkit-backdrop-filter: blur(16px) saturate(180%);
          border: 1px solid ${themeBorder};
          border-radius: 16px;
          box-shadow: 0 20px 40px -10px rgba(0,0,0,0.5), 0 0 20px ${themeGlow};
          color: #F9FAFB;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
          padding: 16px 24px;
          display: flex;
          align-items: flex-start;
          gap: 16px;
          animation: db-slide-down 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }

        .db-icon-container {
          display: flex;
          align-items: center;
          justify-content: center;
          width: 40px;
          height: 40px;
          flex-shrink: 0;
          background: rgba(255,255,255,0.05);
          border-radius: 12px;
          border: 1px solid rgba(255,255,255,0.1);
        }

        .db-text-content {
          flex: 1;
          min-width: 0;
        }

        .db-title {
          font-size: 15px;
          font-weight: 600;
          margin-bottom: 4px;
          letter-spacing: -0.2px;
          overflow-wrap: anywhere;
        }

        .db-subtitle {
          font-size: 13px;
          color: ${isEasterEgg ? 'rgba(255,255,255,0.9)' : '#9CA3AF'};
          line-height: 1.4;
          overflow-wrap: anywhere;
        }

        .db-result-source {
          margin: 6px 0 0;
          font-size: 11px;
          color: #9CA3AF;
          line-height: 1.4;
          overflow-wrap: anywhere;
        }

        .db-dad-tip {
          margin: 10px 0 0;
          padding: 8px 10px;
          border: 1px solid ${themeBorder};
          border-radius: 8px;
          background: rgba(255,255,255,0.04);
          color: #E5E7EB;
          font-size: 12px;
          line-height: 1.45;
          overflow-wrap: anywhere;
        }

        .db-evidence-section {
          margin-top: 10px;
          padding-top: 9px;
          border-top: 1px solid ${themeBorder};
        }

        .db-evidence-heading {
          margin: 0 0 5px;
          color: ${themeIconColor};
          font-size: 11px;
          font-weight: 700;
          line-height: 1.4;
        }

        .db-evidence-list {
          margin: 0;
          padding: 0;
          list-style: none;
        }

        .db-evidence-list li {
          display: flex;
          align-items: flex-start;
          gap: 7px;
          margin: 0;
          padding: 4px 0;
          color: #E5E7EB;
          font-size: 12px;
          line-height: 1.45;
        }

        .db-evidence-icon {
          flex: 0 0 14px;
          width: 14px;
          color: ${themeIconColor};
          line-height: 1.45;
        }

        .db-evidence-text {
          min-width: 0;
          overflow-wrap: anywhere;
          white-space: pre-wrap;
        }

        .db-btn {
          flex-shrink: 0;
          background: rgba(255,255,255,0.1);
          border: 1px solid rgba(255,255,255,0.1);
          color: #E5E7EB;
          padding: 8px 16px;
          border-radius: 8px;
          font-size: 13px;
          font-weight: 500;
          cursor: pointer;
          transition: all 0.2s ease;
        }

        .db-btn:hover {
          background: rgba(255,255,255,0.2);
        }

        .db-btn:focus-visible {
          outline: 2px solid ${themeIconColor};
          outline-offset: 3px;
        }

        @media (max-width: 520px) {
          .db-glass-banner {
            padding: 14px 16px;
            gap: 12px;
            flex-wrap: wrap;
          }

          .db-text-content {
            flex: 1 1 calc(100% - 64px);
          }

          .db-btn {
            margin-left: auto;
          }
        }

        @media (prefers-reduced-motion: reduce) {
          .db-glass-banner {
            animation: none;
            transform: translateX(-50%);
            opacity: 1;
          }

          .db-btn {
            transition: none;
          }
        }

        @keyframes db-slide-down {
          to {
            transform: translateX(-50%) translateY(0);
            opacity: 1;
          }
        }
      </style>

      <div class="db-glass-banner" id="db-banner-main"
           role="status" aria-live="polite">
        <div class="db-icon-container">${shieldSvg}</div>

        <div class="db-text-content">
          <div class="db-title" id="db-title-text"></div>
          <div class="db-subtitle" id="db-subtitle-text"></div>
          <p class="db-result-source" id="db-result-source" hidden></p>

          <section class="db-evidence-section" id="db-evidence-section"
                   aria-labelledby="db-evidence-heading" hidden>
            <div class="db-evidence-heading" id="db-evidence-heading">
              Evidence &amp; Artifacts
            </div>
            <ul class="db-evidence-list" id="db-evidence-list" role="list"></ul>
          </section>

          <p class="db-dad-tip" id="db-dad-tip" hidden></p>
        </div>

        <button type="button" class="db-btn" id="db-ignore-btn">
          ${isEasterEgg ? 'Thanks, Dad ▼' : 'Ignore Dad ▼'}
        </button>
      </div>
    `;

    shadow.getElementById('db-title-text').textContent = titleText;
    shadow.getElementById('db-subtitle-text').textContent = subText;

    // Both direct analysis responses and background banner messages use
    // this renderer. No response-derived strings enter the HTML template.
    renderBannerEvidence(shadow, analysisResult);
    renderBannerResultSource(shadow, analysisResult);
    renderBannerDadTip(shadow, analysisResult);

    shadow.getElementById('db-evidence-heading').textContent =
      isWarning ? 'Observed details' : 'Evidence & Artifacts';

    shadow.getElementById('db-ignore-btn').addEventListener('click', event => {
      event.stopPropagation();

      if (isEasterEgg) {
        clearDadblockUI();
        return;
      }

      showDismissModal().catch(() => {
        clearDadblockUI();
      });
    });

    return true;
  } finally {
    isUpdatingBanner = false;
  }
}

async function updateWarningBanner(analysisResult) {
  if (
    scanSettingsLoaded &&
    !resultMatchesSelectedMode(analysisResult)
  ) {
    return false;
  }

  if (
    !analysisResult ||
    typeof analysisResult !== 'object' ||
    analysisResult.bannerEnabled === false ||
    !isDangerResult(analysisResult)
  ) {
    clearDadblockUI();
    return false;
  }

  return showWarningBanner(analysisResult, false);
}

// ==========================================
// QUOTA BANNER
// ==========================================

async function showQuotaExceededBanner(analysisResult) {
  if (
    quotaBannerDismissed ||
    getResultJudgment(analysisResult) !== 'QUOTA_EXCEEDED'
  ) {
    return false;
  }

  const shadow = await prepareUIRender(analysisResult);

  if (!shadow || quotaBannerDismissed) {
    return false;
  }

  const quota = analysisResult.quota &&
    typeof analysisResult.quota === 'object'
      ? analysisResult.quota
      : { current: '?', limit: '?' };

  const infoSvg = `
    <svg width="24" height="24" viewBox="0 0 24 24"
         fill="none" stroke="#FBBF24" stroke-width="2"
         stroke-linecap="round" stroke-linejoin="round"
         aria-hidden="true" focusable="false">
      <circle cx="12" cy="12" r="10"></circle>
      <line x1="12" y1="16" x2="12" y2="12"></line>
      <line x1="12" y1="8" x2="12.01" y2="8"></line>
    </svg>
  `;

  isUpdatingBanner = true;

  try {
    shadow.innerHTML = `
      <style>
        .db-glass-banner {
          pointer-events: auto;
          position: fixed;
          top: 16px;
          left: 50%;
          transform: translateX(-50%) translateY(-20px);
          opacity: 0;
          width: 90%;
          max-width: 600px;
          background: rgba(30, 20, 10, 0.85);
          backdrop-filter: blur(16px) saturate(180%);
          -webkit-backdrop-filter: blur(16px) saturate(180%);
          border: 1px solid rgba(245, 158, 11, 0.3);
          border-radius: 16px;
          box-shadow: 0 20px 40px -10px rgba(0,0,0,0.5), 0 0 20px rgba(245, 158, 11, 0.4);
          color: #F9FAFB;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          padding: 16px 24px;
          display: flex;
          align-items: center;
          gap: 16px;
          animation: db-slide-down 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }

        .db-icon-container {
          display: flex;
          align-items: center;
          justify-content: center;
          width: 40px;
          height: 40px;
          background: rgba(255,255,255,0.05);
          border-radius: 12px;
          border: 1px solid rgba(255,255,255,0.1);
        }

        .db-text-content {
          flex: 1;
        }

        .db-title {
          font-size: 15px;
          font-weight: 600;
          margin-bottom: 4px;
        }

        .db-subtitle {
          font-size: 13px;
          color: #9CA3AF;
          line-height: 1.4;
        }

        .db-close {
          font-size: 20px;
          color: #9CA3AF;
          cursor: pointer;
          background: none;
          border: none;
          padding: 4px 8px;
          transition: color 0.2s;
        }

        .db-close:hover {
          color: white;
        }

        @keyframes db-slide-down {
          to {
            transform: translateX(-50%) translateY(0);
            opacity: 1;
          }
        }
      </style>

      <div class="db-glass-banner" id="db-quota-banner"
           role="status" aria-live="polite">
        <div class="db-icon-container">${infoSvg}</div>

        <div class="db-text-content">
          <div class="db-title">Dad's Daily Allowance Reached</div>
          <div class="db-subtitle" id="db-quota-subtitle-text"></div>
        </div>

        <button type="button" class="db-close" id="db-close-quota"
                aria-label="Dismiss quota notice">×</button>
      </div>
    `;

    shadow.getElementById('db-quota-subtitle-text').textContent =
      `You've used ${quota.current ?? '?'} of ${quota.limit ?? '?'} free scans today. ` +
      'Time to do your chores and try again tomorrow.';

    shadow.getElementById('db-close-quota').addEventListener('click', () => {
      quotaBannerDismissed = true;
      clearDadblockUI();
    });

    return true;
  } finally {
    isUpdatingBanner = false;
  }
}

// ==========================================
// SCAN LIFECYCLE AND CANCELLATION
// ==========================================

const SCAN_TIMEOUT_MS = 70000;
const MAX_TEXT_CHARACTERS = 48000;
const MAX_LINK_SECTION_CHARACTERS = 16000;
const MAX_VISIBLE_LINKS = 80;
const MAX_DOCUMENT_NODES = 25000;

let pageDisposed = false;

class ScanCancelledError extends Error {
  constructor() {
    super('Scan cancelled');
    this.name = 'ScanCancelledError';
  }
}

function invalidateActiveScan() {
  scanGeneration++;

  const previousContext = activeScanContext;
  activeScanContext = null;

  if (previousContext) {
    previousContext.cancelled = true;
    previousContext.abortController.abort();
  }

  analysisInProgress = false;
  requestAnalysisPending = false;
}

function cancelScheduledScans(includeManual = false) {
  for (const [timer, trigger] of scheduledScanTimers) {
    if (includeManual || trigger !== 'manual') {
      clearTimeout(timer);
      scheduledScanTimers.delete(timer);
    }
  }

  clearTimeout(analysisTimeout);
  analysisTimeout = null;
}

function cancelAutomaticScanning() {
  cancelScheduledScans(false);

  if (activeScanContext && activeScanContext.trigger !== 'manual') {
    invalidateActiveScan();
  }

  if (observer) {
    observer.disconnect();
  }
}

// A mode switch invalidates old UI, fingerprints and in-flight work.
// It does not itself start another scan; normal navigation, enabled
// dynamic scanning, or Scan now can request the next result.
function resetForModeChange() {
  invalidateActiveScan();
  cancelScheduledScans(true);
  clearDadblockUI();

  if (observer) {
    observer.disconnect();
  }

  currentUrl = window.location.href;
  lastUrlSPA = currentUrl;

  scanAttempts = 0;
  insufficientContentRetries = 0;
  transientScanRetries = 0;
  lastAnalyzedContent = '';

  threatDetectedForPage = false;
  quotaBannerDismissed = false;
  backgroundBannerEnabled = true;
}

function synchronizeNavigationState() {
  const newUrl = window.location.href;

  if (newUrl === currentUrl) {
    return false;
  }

  invalidateActiveScan();
  cancelScheduledScans(true);
  clearDadblockUI();

  currentUrl = newUrl;
  lastUrlSPA = newUrl;

  scanAttempts = 0;
  insufficientContentRetries = 0;
  transientScanRetries = 0;
  lastAnalyzedContent = '';

  threatDetectedForPage = false;
  quotaBannerDismissed = false;
  backgroundBannerEnabled = true;

  return true;
}

function isScanContextCurrent(context) {
  if (
    !context ||
    pageDisposed ||
    context.cancelled ||
    context.abortController.signal.aborted ||
    context !== activeScanContext ||
    context.generation !== scanGeneration ||
    context.url !== window.location.href ||
    Date.now() >= context.deadline
  ) {
    return false;
  }

  if (!scanSettingsLoaded) {
    return false;
  }

  if (context.trigger !== 'manual') {
    if (!enableAutoScan) {
      return false;
    }

    if (context.fromMutation && !scanChanges) {
      return false;
    }
  }

  return true;
}

function assertScanContext(context) {
  if (!isScanContextCurrent(context)) {
    throw new ScanCancelledError();
  }
}

function schedulePageAnalysis(
  { trigger = 'auto', fromMutation = false } = {},
  delay = 0
) {
  if (pageDisposed) {
    return;
  }

  if (
    trigger !== 'manual' &&
    (
      !scanSettingsLoaded ||
      !enableAutoScan ||
      (fromMutation && !scanChanges)
    )
  ) {
    return;
  }

  if (trigger !== 'manual') {
    for (const [pendingTimer, pendingTrigger] of scheduledScanTimers) {
      if (pendingTrigger !== 'manual') {
        clearTimeout(pendingTimer);
        scheduledScanTimers.delete(pendingTimer);
      }
    }
  }

  const scheduledUrl = window.location.href;

  const timer = window.setTimeout(() => {
    scheduledScanTimers.delete(timer);

    if (pageDisposed || window.location.href !== scheduledUrl) {
      return;
    }

    if (
      trigger !== 'manual' &&
      (
        !scanSettingsLoaded ||
        !enableAutoScan ||
        (fromMutation && !scanChanges)
      )
    ) {
      return;
    }

    analyzePage({ trigger, fromMutation }).catch(() => {});
  }, delay);

  scheduledScanTimers.set(timer, trigger);
}

async function waitForDocumentBody(context) {
  assertScanContext(context);

  if (document.body) {
    return;
  }

  if (document.readyState !== 'loading') {
    throw new ScanCancelledError();
  }

  await new Promise(resolve => {
    const signal = context.abortController.signal;

    const finish = () => {
      document.removeEventListener('DOMContentLoaded', finish);
      signal.removeEventListener('abort', finish);
      resolve();
    };

    document.addEventListener('DOMContentLoaded', finish, { once: true });
    signal.addEventListener('abort', finish, { once: true });

    if (signal.aborted || document.body) {
      finish();
    }
  });

  assertScanContext(context);

  if (!document.body) {
    throw new ScanCancelledError();
  }
}

// ==========================================
// PAYMENT AND FORM PRIVACY
// ==========================================

const PAYMENT_PROVIDER_DOMAINS = [
  'stripe.com',
  'stripe.network',
  'paypal.com',
  'paypalobjects.com',
  'adyen.com',
  'adyenpayments.com',
  'braintreegateway.com',
  'braintreepayments.com',
];

const SENSITIVE_CONTROL_SELECTOR = [
  'input[type="password"]',
  '[autocomplete^="cc-" i]',
  'input[name*="credit_card" i]',
  'input[name*="creditcard" i]',
  'input[name*="card_number" i]',
  'input[name*="cardnumber" i]',
  'input[name*="card-number" i]',
  'input[name*="cvv" i]',
  'input[name*="cvc" i]',
  'input[id*="credit_card" i]',
  'input[id*="creditcard" i]',
  'input[id*="card_number" i]',
  'input[id*="cardnumber" i]',
  'input[id*="card-number" i]',
  'input[id*="cvv" i]',
  'input[id*="cvc" i]',
].join(', ');

// Form subtrees and editable regions are excluded. No control values are read.
const PRIVATE_REGION_SELECTOR = [
  'form',
  'input',
  'textarea',
  'select',
  'option',
  '[contenteditable]:not([contenteditable="false" i])',
  '[data-private]:not([data-private="false" i])',
  '[data-sensitive]:not([data-sensitive="false" i])',
  '[id^="db-guard-"]',
  '#dadblock-dismiss-modal',
  SENSITIVE_CONTROL_SELECTOR,
].join(', ');

const NONCONTENT_SELECTOR = [
  'script',
  'style',
  'noscript',
  'template',
  'svg',
  'canvas',
  'iframe',
].join(', ');

const EXTRACTION_EXCLUSION_SELECTOR =
  PRIVATE_REGION_SELECTOR + ', ' + NONCONTENT_SELECTOR;

function hostnameMatchesDomain(hostname, domain) {
  const normalized = String(hostname || '').toLowerCase();

  return normalized === domain || normalized.endsWith('.' + domain);
}

function isPaymentProviderHostname(hostname) {
  return PAYMENT_PROVIDER_DOMAINS.some(domain =>
    hostnameMatchesDomain(hostname, domain)
  );
}

function getNodeElement(node) {
  if (!node) {
    return null;
  }

  return node.nodeType === Node.ELEMENT_NODE
    ? node
    : node.parentElement;
}

function isPaymentIframe(iframe) {
  if (!iframe || iframe.tagName !== 'IFRAME') {
    return false;
  }

  try {
    const source = iframe.getAttribute('src');

    if (source) {
      const url = new URL(source, iframe.ownerDocument.baseURI);

      if (isPaymentProviderHostname(url.hostname)) {
        return true;
      }
    }
  } catch {
    // Continue with provider markers.
  }

  const markers = [
    iframe.getAttribute('name') || '',
    iframe.id || '',
    iframe.getAttribute('title') || '',
  ].join(' ');

  return /(?:__privateStripeFrame|stripe[-_\s]*(?:frame|payment|card)|paypal|adyen|braintree)/i
    .test(markers);
}

function isPaymentDocument(doc) {
  try {
    if (isPaymentProviderHostname(doc.location.hostname)) {
      return true;
    }
  } catch {
    return true;
  }

  try {
    const frame = doc.defaultView?.frameElement;

    if (frame && isPaymentIframe(frame)) {
      return true;
    }
  } catch {
    // Cross-origin parents are inaccessible; the document URL was checked.
  }

  return false;
}

function isProtectedElement(node) {
  const element = getNodeElement(node);

  if (!element) {
    return false;
  }

  try {
    return Boolean(element.closest(EXTRACTION_EXCLUSION_SELECTOR));
  } catch {
    return true;
  }
}

function isProtectedInteractiveElement(node) {
  const element = getNodeElement(node);

  if (!element) {
    return false;
  }

  try {
    return Boolean(element.closest(PRIVATE_REGION_SELECTOR)) ||
      isPaymentIframe(element);
  } catch {
    return true;
  }
}

function containsProtectedInteractiveContent(element) {
  if (!element || element.nodeType !== Node.ELEMENT_NODE) {
    return false;
  }

  if (isProtectedInteractiveElement(element)) {
    return true;
  }

  try {
    if (
      element.matches('[role="dialog"], [aria-modal="true"]') ||
      element.querySelector(
        PRIVATE_REGION_SELECTOR + ', [role="dialog"], [aria-modal="true"]'
      )
    ) {
      return true;
    }

    for (const iframe of element.querySelectorAll('iframe')) {
      if (isPaymentIframe(iframe)) {
        return true;
      }
    }
  } catch {
    return true;
  }

  return false;
}

function isOnlyProtectedSubtree(node, depth = 0) {
  if (!node) {
    return true;
  }

  if (isProtectedElement(node)) {
    return true;
  }

  if (node.nodeType === Node.TEXT_NODE) {
    return !node.textContent.trim();
  }

  if (node.nodeType !== Node.ELEMENT_NODE) {
    return true;
  }

  if (depth >= 6 || node.childNodes.length === 0) {
    return false;
  }

  return Array.from(node.childNodes).every(child =>
    isOnlyProtectedSubtree(child, depth + 1)
  );
}

function isRelevantPageMutation(mutation) {
  if (isProtectedElement(mutation.target)) {
    return false;
  }

  if (mutation.type === 'childList') {
    const changedNodes = [
      ...mutation.addedNodes,
      ...mutation.removedNodes,
    ];

    return changedNodes.some(node => !isOnlyProtectedSubtree(node));
  }

  if (mutation.type === 'attributes') {
    return !isOnlyProtectedSubtree(mutation.target);
  }

  return mutation.type === 'characterData';
}

// ==========================================
// URL SANITIZATION
// ==========================================

const TRACKING_PARAMETER_NAMES = new Set([
  'ref',
  'referrer',
  'referer',
  'ref_src',
  'ref_url',
  'gclid',
  'dclid',
  'fbclid',
  'msclkid',
  'twclid',
  'ttclid',
  'yclid',
  'igshid',
  'gbraid',
  'wbraid',
  'srsltid',
  'mc_cid',
  'mc_eid',
  '_ga',
  '_gl',
  '_gac',
  'vero_id',
  'vero_conv',
  'mkt_tok',
  'wickedid',
  'clickid',
  'click_id',
  'affiliate',
  'affiliate_id',
  'aff',
  'aff_id',
  'affid',
]);

const SAFE_QUERY_PARAMETER_NAMES = new Set([
  'page',
  'p',
  'limit',
  'offset',
  'lang',
  'locale',
  'category',
  'sort',
  'order',
  'view',
  'format',
  'type',
  'v',
  'video',
  'id',
]);

const DESTINATION_PARAMETER_NAMES = new Set([
  'url',
  'target',
  'dest',
  'destination',
  'redirect',
  'redirect_url',
  'redirect_uri',
  'next',
  'continue',
  'return_url',
]);

const SENSITIVE_PARAMETER_PATTERN =
  /(?:token|auth|authorization|session|secret|password|passwd|credential|signature|nonce|csrf|xsrf|api.?key|access.?key|client.?secret|email|phone|address|customer|account|payment|card|cvv|cvc)/i;

const SENSITIVE_PATH_MARKER_PATTERN =
  /^(?:token|auth|session|reset|reset-password|password-reset|verify|verification|activate|activation|invite|invitation|magic-link|checkout-session)$/i;

function decodeURLComponentSafely(value) {
  let decoded = String(value || '');

  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const next = decodeURIComponent(decoded);

      if (next === decoded) {
        break;
      }

      decoded = next;
    } catch {
      break;
    }
  }

  return decoded;
}

function looksOpaqueToken(value) {
  const decoded = decodeURLComponentSafely(value).trim();

  if (!decoded) {
    return false;
  }

  if (
    /^[a-f0-9]{16,}$/i.test(decoded) ||
    /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i
      .test(decoded) ||
    /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(decoded)
  ) {
    return true;
  }

  if (
    decoded.length >= 24 &&
    /^[A-Za-z0-9_+/=-]+$/.test(decoded) &&
    (
      (/[a-z]/.test(decoded) && /[A-Z]/.test(decoded)) ||
      (/[A-Za-z]/.test(decoded) && /\d/.test(decoded))
    )
  ) {
    return true;
  }

  return (
    decoded.length >= 16 &&
    /^[A-Za-z0-9_-]+$/.test(decoded) &&
    /[a-z]/.test(decoded) &&
    /[A-Z]/.test(decoded) &&
    /\d/.test(decoded)
  );
}

function looksSensitiveURLValue(value) {
  const decoded = decodeURLComponentSafely(value);

  return (
    looksOpaqueToken(decoded) ||
    /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(decoded) ||
    /^(?:\+?\d[\s().-]*){8,}$/.test(decoded)
  );
}

function sanitizeExtractedURL(rawURL, baseURL = document.baseURI, depth = 0) {
  if (
    typeof rawURL !== 'string' ||
    !rawURL.trim() ||
    rawURL.length > 8192 ||
    depth > 2
  ) {
    return '';
  }

  try {
    const url = new URL(rawURL, baseURL);

    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return '';
    }

    url.username = '';
    url.password = '';
    url.hash = '';

    const segments = url.pathname.split('/');
    let redactFollowingSegments = false;

    url.pathname = segments.map(segment => {
      const decoded = decodeURLComponentSafely(segment);

      if (!segment) {
        return segment;
      }

      if (redactFollowingSegments || looksSensitiveURLValue(decoded)) {
        return '[redacted]';
      }

      if (SENSITIVE_PATH_MARKER_PATTERN.test(decoded)) {
        redactFollowingSegments = true;
      }

      return segment;
    }).join('/');

    const sanitizedParameters = new URLSearchParams();

    for (const [key, value] of url.searchParams) {
      const normalizedKey = key.toLowerCase();

      if (
        normalizedKey.startsWith('utm_') ||
        TRACKING_PARAMETER_NAMES.has(normalizedKey) ||
        SENSITIVE_PARAMETER_PATTERN.test(normalizedKey)
      ) {
        continue;
      }

      if (DESTINATION_PARAMETER_NAMES.has(normalizedKey)) {
        const destination = sanitizeExtractedURL(
          value,
          url.origin,
          depth + 1
        );

        if (destination) {
          sanitizedParameters.append(key, destination);
        }

        continue;
      }

      if (
        !SAFE_QUERY_PARAMETER_NAMES.has(normalizedKey) ||
        value.length > 120 ||
        looksSensitiveURLValue(value)
      ) {
        continue;
      }

      sanitizedParameters.append(key, value);
    }

    url.search = sanitizedParameters.toString();

    const sanitized = url.href;
    return sanitized.length <= 2048 ? sanitized : '';
  } catch {
    return '';
  }
}

function sanitizeExtractedText(text, maxLength = Infinity) {
  if (typeof text !== 'string') {
    return '';
  }

  const sanitized = text
    .replace(/https?:\/\/[^\s<>"']+/gi, rawURL =>
      sanitizeExtractedURL(rawURL) || '[URL omitted]'
    )
    .replace(/[A-Za-z0-9_=-]{16,}/g, value =>
      looksOpaqueToken(value) ? '[token omitted]' : value
    )
    .replace(/\s+/g, ' ')
    .trim();

  return sanitized.slice(0, maxLength);
}

// ==========================================
// VISIBLE CONTENT EXTRACTION
// ==========================================

function isElementVisible(element) {
  if (
    !element ||
    !element.isConnected ||
    isProtectedElement(element)
  ) {
    return false;
  }

  const doc = element.ownerDocument;
  const view = doc.defaultView;

  if (!view) {
    return false;
  }

  try {
    for (
      let ancestor = element;
      ancestor;
      ancestor = ancestor.parentElement
    ) {
      if (ancestor.hidden) {
        return false;
      }

      const style = view.getComputedStyle(ancestor);

      if (
        style.display === 'none' ||
        style.visibility === 'hidden' ||
        style.visibility === 'collapse' ||
        style.opacity === '0'
      ) {
        return false;
      }

      if (ancestor === doc.body) {
        break;
      }
    }

    const rect = element.getBoundingClientRect();
    const height = view.innerHeight || doc.documentElement.clientHeight;
    const width = view.innerWidth || doc.documentElement.clientWidth;

    return (
      rect.width > 0 &&
      rect.height > 0 &&
      rect.bottom >= -height &&
      rect.top <= height * 2 &&
      rect.right >= 0 &&
      rect.left <= width
    );
  } catch {
    return false;
  }
}

function isIframeVisible(iframe) {
  if (!iframe?.isConnected || isPaymentIframe(iframe)) {
    return false;
  }

  const ancestor = iframe.parentElement;

  if (ancestor && isProtectedElement(ancestor)) {
    return false;
  }

  try {
    const view = iframe.ownerDocument.defaultView;
    const style = view.getComputedStyle(iframe);

    if (
      style.display === 'none' ||
      style.visibility === 'hidden' ||
      style.opacity === '0'
    ) {
      return false;
    }

    if (ancestor && !isElementVisible(ancestor)) {
      return false;
    }

    const rect = iframe.getBoundingClientRect();
    const height = view.innerHeight;
    const width = view.innerWidth;

    return (
      rect.width > 0 &&
      rect.height > 0 &&
      rect.bottom >= -height &&
      rect.top <= height * 2 &&
      rect.right >= 0 &&
      rect.left <= width
    );
  } catch {
    return false;
  }
}

async function extractDocumentTextAsync(doc, context, maxCharacters) {
  assertScanContext(context);

  if (!doc.body || isPaymentDocument(doc) || maxCharacters <= 0) {
    return '';
  }

  const walker = doc.createTreeWalker(
    doc.body,
    NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT,
    {
      acceptNode(node) {
        if (isProtectedElement(node)) {
          return NodeFilter.FILTER_REJECT;
        }

        return NodeFilter.FILTER_ACCEPT;
      },
    }
  );

  const pieces = [];
  let characters = 0;
  let operations = 0;
  let node;

  while ((node = walker.nextNode())) {
    operations++;

    if (operations > MAX_DOCUMENT_NODES) {
      break;
    }

    if (operations % 100 === 0) {
      await yieldToMain();
      assertScanContext(context);
    }

    if (node.nodeType !== Node.TEXT_NODE) {
      continue;
    }

    const parent = node.parentElement;

    if (!parent || !isElementVisible(parent)) {
      continue;
    }

    const remaining = maxCharacters - characters;

    if (remaining <= 0) {
      break;
    }

    const text = sanitizeExtractedText(node.textContent, remaining);

    if (!text) {
      continue;
    }

    pieces.push(text);
    characters += text.length + 1;
  }

  assertScanContext(context);

  return pieces.join(' ').slice(0, maxCharacters).trim();
}

async function extractVisibleContentAsync(context = activeScanContext) {
  if (!context) {
    return '';
  }

  assertScanContext(context);

  let fullText = await extractDocumentTextAsync(
    document,
    context,
    MAX_TEXT_CHARACTERS
  );

  assertScanContext(context);

  const iframes = Array.from(document.querySelectorAll('iframe'));

  for (const iframe of iframes) {
    assertScanContext(context);

    if (
      fullText.length >= MAX_TEXT_CHARACTERS ||
      isPaymentIframe(iframe) ||
      !isIframeVisible(iframe)
    ) {
      continue;
    }

    try {
      const iframeDoc = iframe.contentDocument;

      if (!iframeDoc?.body || isPaymentDocument(iframeDoc)) {
        continue;
      }

      const prefix = '\n\nIFRAME CONTENT:\n';
      const remaining =
        MAX_TEXT_CHARACTERS - fullText.length - prefix.length;

      if (remaining <= 0) {
        break;
      }

      const iframeText = await extractDocumentTextAsync(
        iframeDoc,
        context,
        remaining
      );

      if (iframeText) {
        fullText += prefix + iframeText;
      }
    } catch (error) {
      if (error instanceof ScanCancelledError) {
        throw error;
      }

      // Cross-origin or detached frames are ignored.
    }

    await yieldToMain();
    assertScanContext(context);
  }

  return fullText.slice(0, MAX_TEXT_CHARACTERS);
}

function readPublicLinkText(element) {
  const walker = element.ownerDocument.createTreeWalker(
    element,
    NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT,
    {
      acceptNode(node) {
        return isProtectedElement(node)
          ? NodeFilter.FILTER_REJECT
          : NodeFilter.FILTER_ACCEPT;
      },
    }
  );

  const pieces = [];
  let characters = 0;
  let operations = 0;
  let node;

  while ((node = walker.nextNode())) {
    if (++operations > 200 || characters >= 300) {
      break;
    }

    if (
      node.nodeType !== Node.TEXT_NODE ||
      !isElementVisible(node.parentElement)
    ) {
      continue;
    }

    const text = sanitizeExtractedText(
      node.textContent,
      300 - characters
    );

    if (text) {
      pieces.push(text);
      characters += text.length + 1;
    }
  }

  return pieces.join(' ').slice(0, 300);
}

async function extractVisibleLinksAsync(context = activeScanContext) {
  if (!context) {
    return [];
  }

  assertScanContext(context);

  const links = [];
  const seen = new Set();

  // onclick code is not inspected or executed to infer destinations.
  const elements = Array.from(
    document.querySelectorAll('a[href], button[onclick]')
  );

  for (let index = 0; index < elements.length; index += 50) {
    assertScanContext(context);

    for (const element of elements.slice(index, index + 50)) {
      if (
        links.length >= MAX_VISIBLE_LINKS ||
        isProtectedElement(element) ||
        !isElementVisible(element)
      ) {
        continue;
      }

      const isButton = (
        element.tagName === 'BUTTON' ||
        element.classList.contains('btn') ||
        element.classList.contains('button')
      );

      const rawHref = element.tagName === 'A'
        ? element.getAttribute('href') || ''
        : '';

      if (
        element.tagName === 'A' &&
        (!rawHref.trim() || rawHref.trim().startsWith('#'))
      ) {
        continue;
      }

      const url = rawHref
        ? sanitizeExtractedURL(rawHref, element.ownerDocument.baseURI)
        : '';

      if (rawHref && !url) {
        continue;
      }

      const text = readPublicLinkText(element);

      const ariaLabel = sanitizeExtractedText(
        element.getAttribute('aria-label') || '',
        200
      );

      const title = sanitizeExtractedText(
        element.getAttribute('title') || '',
        200
      );

      const identity = `${url}\n${text}\n${isButton}`;

      if (seen.has(identity)) {
        continue;
      }

      seen.add(identity);

      links.push({
        text,
        url,
        ariaLabel,
        title,
        isButton,
      });
    }

    if (links.length >= MAX_VISIBLE_LINKS) {
      break;
    }

    await yieldToMain();
    assertScanContext(context);
  }

  return links;
}

function buildAnalysisPayload(content, links) {
  const lines = [];
  let linkCharacters = 0;

  for (const link of links) {
    const linkType = link.isButton ? '[BUTTON]' : '[LINK]';

    const label = (link.text || link.ariaLabel || link.title || '')
      .replace(/[\r\n"]/g, ' ');

    const line = link.url
      ? `${linkType} "${label}" → ${link.url}\n`
      : `${linkType} "${label}"\n`;

    if (linkCharacters + line.length > MAX_LINK_SECTION_CHARACTERS) {
      break;
    }

    lines.push(line);
    linkCharacters += line.length;
  }

  if (lines.length === 0) {
    return content;
  }

  return (
    'LINKS FOUND ON PAGE:\n' +
    lines.join('') +
    '\nPAGE TEXT:\n' +
    content
  );
}

async function getContentFingerprint(url, content) {
  if (!globalThis.crypto?.subtle) {
    return '';
  }

  const input = new TextEncoder().encode(url + '\n' + content);
  const digest = await crypto.subtle.digest('SHA-256', input);

  return Array.from(new Uint8Array(digest), byte =>
    byte.toString(16).padStart(2, '0')
  ).join('');
}

// ==========================================
// BACKGROUND MESSAGING
// ==========================================

async function safeSendMessage(payload, context = null) {
  if (!chrome.runtime?.id) {
    return null;
  }

  if (context && !isScanContextCurrent(context)) {
    return null;
  }

  return new Promise(resolve => {
    let settled = false;
    let timeout = null;

    const signal = context?.abortController.signal;

    const finish = response => {
      if (settled) {
        return;
      }

      settled = true;
      clearTimeout(timeout);
      signal?.removeEventListener('abort', onAbort);
      resolve(response ?? null);
    };

    const onAbort = () => finish(null);

    if (signal?.aborted) {
      finish(null);
      return;
    }

    signal?.addEventListener('abort', onAbort, { once: true });

    const remaining = context
      ? Math.max(1, context.deadline - Date.now())
      : SCAN_TIMEOUT_MS;

    timeout = window.setTimeout(() => finish(null), remaining);

    try {
      Promise.resolve(chrome.runtime.sendMessage(payload)).then(
        finish,
        () => finish(null)
      );
    } catch {
      finish(null);
    }
  });
}

async function sendScanMessage(context, payload) {
  assertScanContext(context);

  const settings = await readScanSettings();

  if (
    !settings.ok ||
    (
      context.trigger !== 'manual' &&
      (
        !settings.enableAutoScan ||
        (context.fromMutation && !settings.scanChanges)
      )
    )
  ) {
    return null;
  }

  assertScanContext(context);

  return safeSendMessage({
    ...payload,
    pageUrl: context.url,
    trigger: context.trigger,
    manual: context.trigger === 'manual',
  }, context);
}

async function sendSkippedNotice(context, reason) {
  return sendScanMessage(context, {
    action: 'analyzeContent',
    content: '',
    skipped: true,
    reason,
  });
}

// ==========================================
// PAGE ANALYSIS
// ==========================================

function isPrivateHostname(hostname) {
  const host = String(hostname || '')
    .toLowerCase()
    .replace(/^\[|\]$/g, '');

  return (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host === '::1' ||
    host.startsWith('fe80:') ||
    /^(?:fc|fd)[a-f0-9]{2}:/i.test(host) ||
    /^(?:127\.|10\.|192\.168\.|169\.254\.|0\.)/.test(host) ||
    /^172\.(?:1[6-9]|2[0-9]|3[01])\./.test(host)
  );
}

// Private workspaces (documents, boards, designs) are never scanned:
// there is nothing to protect the user from, and their private content
// should not be read at all.
function isWorkspaceEditorURL(value) {
  try {
    const url = value instanceof URL ? value : new URL(value);
    const host = url.hostname.toLowerCase();
    const path = url.pathname.toLowerCase();
    const on = domain => host === domain || host.endsWith('.' + domain);

    if (host === 'docs.google.com') {
      return (
        /^\/(?:document|spreadsheets|presentation|drawings)\//.test(path) ||
        (path.startsWith('/forms/d/') && path.includes('/edit'))
      );
    }

    return (
      host === 'drive.google.com' ||
      host === 'calendar.google.com' ||
      host === 'app.slack.com' ||
      ['miro.com', 'figma.com', 'notion.so', 'lucid.app', 'lucidchart.com',
        'whimsical.com', 'excalidraw.com', 'tldraw.com', 'diagrams.net',
        'draw.io', 'mural.co', 'overleaf.com', 'airtable.com', 'trello.com',
        'asana.com', 'clickup.com', 'office.com', 'office365.com',
        'officeapps.live.com', 'onedrive.live.com', 'sharepoint.com',
        'github.dev'].some(on) ||
      (on('canva.com') && /^\/(?:design|folder|your-designs|projects)/.test(path))
    );
  } catch {
    return false;
  }
}

// Search results are lists of other sites' text, not a page to judge.
function isSearchResultsPage(url) {
  const host = url.hostname.toLowerCase();
  const path = url.pathname.toLowerCase();

  return (
    (/^(?:www\.)?google\.[a-z.]+$/.test(host) && path.startsWith('/search')) ||
    (/^(?:www\.)?bing\.com$/.test(host) && path.startsWith('/search')) ||
    (host === 'duckduckgo.com' && url.searchParams.has('q')) ||
    (host === 'search.brave.com' && path.startsWith('/search')) ||
    (host === 'search.yahoo.com' && path.startsWith('/search')) ||
    (/^(?:www\.)?ecosia\.org$/.test(host) && path.startsWith('/search')) ||
    (/^(?:www\.)?startpage\.com$/.test(host) && path.includes('search')) ||
    (/^yandex\.[a-z.]+$/.test(host) && path.startsWith('/search'))
  );
}

function isEmailInterfaceWithoutMessage(url) {
  if (url.hostname === 'mail.google.com') {
    const pathSegments = url.hash.slice(1).split('/');
    return pathSegments.length < 2 || !pathSegments[1];
  }

  if (
    url.hostname === 'outlook.live.com' ||
    url.hostname === 'outlook.office.com'
  ) {
    return !url.pathname.includes('/mail/id/');
  }

  return false;
}

async function showPageEasterEgg(context, url) {
  let storageKey;
  let result;

  if (
    url.hostname === 'dadblock.org' ||
    url.hostname === 'www.dadblock.org'
  ) {
    storageKey = 'dadblock_easter_egg_shown';
    result = { judgment: 'easter_egg' };
  } else if (
    url.hostname === 'buymeacoffee.com' &&
    url.pathname.replace(/\/$/, '') === '/dadblock'
  ) {
    storageKey = 'dadblock_coffee_egg_shown';

    result = {
      judgment: 'easter_egg',
      title: 'OH, HEY.',
      analysis:
        "You didn't have to click this far. Means a lot though thank you. " +
        '— Dad (P.S. I am more of a tea than coffee guy myself hehe.)',
    };
  } else {
    return false;
  }

  assertScanContext(context);

  let alreadyShown = false;

  try {
    alreadyShown = sessionStorage.getItem(storageKey) === 'true';
  } catch {
    // The greeting can work without session storage.
  }

  if (!alreadyShown) {
    const shown = await showWarningBanner(result);
    assertScanContext(context);

    if (shown) {
      try {
        sessionStorage.setItem(storageKey, 'true');
      } catch {
        // Session persistence is optional.
      }
    }
  }

  threatDetectedForPage = true;
  return true;
}

async function analyzePage(
  { trigger = 'auto', fromMutation = false } = {}
) {
  // The top document extracts eligible visible iframe content itself.
  // Individual frames must not compete for the top tab's analysis tracker.
  if (
    window.top !== window ||
    pageDisposed ||
    !chrome.runtime?.id
  ) {
    return;
  }

  synchronizeNavigationState();

  const manual = trigger === 'manual';

  if (
    activeScanContext ||
    analysisInProgress ||
    (!manual && threatDetectedForPage)
  ) {
    return;
  }

  const context = {
    trigger: manual ? 'manual' : 'auto',
    fromMutation: !manual && fromMutation,
    url: window.location.href,
    generation: ++scanGeneration,
    cancelled: false,
    abortController: new AbortController(),
    deadline: Date.now() + SCAN_TIMEOUT_MS,
    retryDelay: null,
  };

  activeScanContext = context;
  analysisInProgress = true;
  requestAnalysisPending = true;

  try {
    const settings = await readScanSettings();

    if (
      !settings.ok ||
      (
        !manual &&
        (
          !settings.enableAutoScan ||
          (fromMutation && !settings.scanChanges)
        )
      )
    ) {
      return;
    }

    assertScanContext(context);

    const url = new URL(context.url);

    if (
      (url.protocol !== 'http:' && url.protocol !== 'https:') ||
      isPrivateHostname(url.hostname)
    ) {
      await sendSkippedNotice(context, 'unsupported_page');
      return;
    }

    if (isSearchResultsPage(url)) {
      await sendSkippedNotice(context, 'search_results');
      return;
    }

    if (isWorkspaceEditorURL(url)) {
      await sendSkippedNotice(context, 'workspace_app');
      return;
    }

    if (isPaymentDocument(document)) {
      await sendSkippedNotice(context, 'sensitive_context');
      return;
    }

    if (!manual && scanAttempts >= MAX_SCAN_ATTEMPTS) {
      await sendSkippedNotice(context, 'max_scans_reached');
      return;
    }

    if (!manual && await showPageEasterEgg(context, url)) {
      return;
    }

    if (isEmailInterfaceWithoutMessage(url)) {
      await sendSkippedNotice(context, 'email_interface');
      return;
    }

    await waitForDocumentBody(context);
    assertScanContext(context);

    const content = await extractVisibleContentAsync(context);
    assertScanContext(context);

    if (!content || content.length < 50) {
      if (insufficientContentRetries < MAX_INSUFFICIENT_CONTENT_RETRIES) {
        insufficientContentRetries++;

        schedulePageAnalysis(
          {
            trigger: context.trigger,
            fromMutation: context.fromMutation,
          },
          insufficientContentRetries === 1 ? 500 : 1000
        );

        return;
      }

      await sendSkippedNotice(context, 'insufficient_content');
      return;
    }

    const links = await extractVisibleLinksAsync(context);
    assertScanContext(context);

    insufficientContentRetries = 0;

    const enhancedContent = buildAnalysisPayload(content, links);

    const fingerprint = await getContentFingerprint(
      context.url,
      enhancedContent
    );

    assertScanContext(context);

    if (
      !manual &&
      fingerprint &&
      fingerprint === lastAnalyzedContent
    ) {
      await sendSkippedNotice(context, 'content_unchanged');
      return;
    }

    scanAttempts++;

    const response = await sendScanMessage(context, {
      action: 'analyzeContent',
      content: enhancedContent,
    });

    if (!response) {
      if (
        !manual &&
        activeScanContext === context &&
        !context.cancelled &&
        !pageDisposed &&
        context.url === window.location.href &&
        transientScanRetries < MAX_TRANSIENT_SCAN_RETRIES &&
        scanAttempts < MAX_SCAN_ATTEMPTS
      ) {
        context.retryDelay = 1200;
      }

      return;
    }

    if (
      !isScanContextCurrent(context) ||
      typeof response !== 'object' ||
      !resultMatchesSelectedMode(response)
    ) {
      return;
    }

    rememberBackgroundBannerSetting(response);

    const judgment = getResultJudgment(response);

    // Remember conclusive results and genuine model abstentions.
    // Invalid evidence or a timeout must not make unchanged text ineligible.
    if (
      fingerprint &&
      response.schemaVersion === 2 &&
      (
        response.conclusive === true ||
        (
          judgment === 'INCONCLUSIVE' &&
          response.method === 'ai' &&
          (
            response.code === 'LOCAL_JUDGE_ABSTAINED' ||
            !response.code
          )
        )
      )
    ) {
      lastAnalyzedContent = fingerprint;
    }

    if (isDangerResult(response)) {
      threatDetectedForPage = true;

      if (fingerprint) {
        lastAnalyzedContent = fingerprint;
      }

      if (observer) {
        observer.disconnect();
      }

      if (bannersAllowed(response)) {
        // Pass the complete result, including evidence, to the banner.
        await showWarningBanner(
          response,
          response.stage === 'stage1'
        );
      }

      return;
    }

    if (judgment === 'QUOTA_EXCEEDED') {
      scanAttempts = MAX_SCAN_ATTEMPTS;

      if (observer) {
        observer.disconnect();
      }

      if (bannersAllowed(response)) {
        await showQuotaExceededBanner(response);
      }

      return;
    }

    const validatedSafe = (
      judgment === 'SAFE' &&
      response.schemaVersion === 2 &&
      response.conclusive === true &&
      response.safe === true &&
      response.isMalicious === false
    );

    const validatedInbox = (
      judgment === 'INBOX' &&
      response.schemaVersion === 2 &&
      response.conclusive === true
    );

    if (validatedSafe || validatedInbox) {
      if (fingerprint) {
        lastAnalyzedContent = fingerprint;
      }

      threatDetectedForPage = false;
      clearDadblockUI();
    }

    const retryableFailure = (
      response.code === 'LOCAL_JUDGE_INVALID_RESPONSE' ||
      response.code === 'ANALYSIS_TIMEOUT' ||
      response.code === 'ANALYSIS_EXCEPTION' ||
      response.code === 'HANDLER_FAILED' ||
      response.method === 'timeout' ||
      (
        response.mode === 'local' &&
        response.method === 'error' &&
        response.code !== 'LOCAL_AI_UNAVAILABLE' &&
        response.code !== 'SETTINGS_UNAVAILABLE'
      )
    );

    if (
      !manual &&
      retryableFailure &&
      transientScanRetries < MAX_TRANSIENT_SCAN_RETRIES &&
      scanAttempts < MAX_SCAN_ATTEMPTS
    ) {
      context.retryDelay = 1200;
    }

    if (scanAttempts >= MAX_SCAN_ATTEMPTS && observer) {
      observer.disconnect();
    }
  } catch (error) {
    if (!(error instanceof ScanCancelledError)) {
      // Leave the background's existing result untouched.
    }
  } finally {
    if (activeScanContext === context) {
      const retryDelay = context.retryDelay;

      const mayRetry = (
        retryDelay !== null &&
        !pageDisposed &&
        !context.cancelled &&
        context.url === window.location.href &&
        scanSettingsLoaded &&
        enableAutoScan &&
        !threatDetectedForPage &&
        transientScanRetries < MAX_TRANSIENT_SCAN_RETRIES &&
        scanAttempts < MAX_SCAN_ATTEMPTS
      );

      activeScanContext = null;
      analysisInProgress = false;
      requestAnalysisPending = false;

      context.cancelled = true;
      context.abortController.abort();

      refreshScanObserver();

      if (mayRetry) {
        transientScanRetries++;
        schedulePageAnalysis({ trigger: 'auto' }, retryDelay);
      }
    }
  }
}

// ==========================================
// AUTOMATIC SCAN OBSERVER
// ==========================================

function refreshScanObserver() {
  if (!observer) {
    observer = new MutationObserver(mutations => {
      if (
        pageDisposed ||
        !scanSettingsLoaded ||
        !enableAutoScan ||
        !scanChanges ||
        isUpdatingBanner
      ) {
        return;
      }

      if (synchronizeNavigationState()) {
        refreshScanObserver();
        schedulePageAnalysis({ trigger: 'auto' }, 500);
        return;
      }

      if (
        threatDetectedForPage ||
        analysisInProgress ||
        requestAnalysisPending ||
        scanAttempts >= MAX_SCAN_ATTEMPTS ||
        !mutations.some(isRelevantPageMutation)
      ) {
        return;
      }

      // Debounce with a maximum wait: busy pages (ad rotators,
      // carousels) must not postpone the scan forever.
      const burstNow = Date.now();

      // The maximum wait only guarantees that the FIRST scan happens.
      // Later re-scans of a busy page still wait for a quiet moment, so a
      // constantly changing page is not scanned over and over.
      if (
        scanAttempts === 0 &&
        analysisTimeout &&
        mutationBurstStartedAt &&
        burstNow - mutationBurstStartedAt >= MUTATION_MAX_WAIT_MS
      ) {
        return;
      }

      if (!mutationBurstStartedAt) {
        mutationBurstStartedAt = burstNow;
      }

      clearTimeout(analysisTimeout);

      analysisTimeout = window.setTimeout(() => {
        analysisTimeout = null;
        mutationBurstStartedAt = 0;

        if (
          !pageDisposed &&
          scanSettingsLoaded &&
          enableAutoScan &&
          scanChanges &&
          !analysisInProgress &&
          !requestAnalysisPending &&
          !threatDetectedForPage
        ) {
          analyzePage({
            trigger: 'auto',
            fromMutation: true,
          }).catch(() => {});
        }
      }, 2000);
    });
  }

  observer.disconnect();

  if (
    pageDisposed ||
    !document.body ||
    !scanSettingsLoaded ||
    !enableAutoScan ||
    !scanChanges ||
    threatDetectedForPage ||
    scanAttempts >= MAX_SCAN_ATTEMPTS ||
    isPaymentDocument(document)
  ) {
    return;
  }

  observer.observe(document.body, {
    childList: true,
    subtree: true,
    characterData: true,
    attributes: true,
    attributeFilter: [
      'class',
      'style',
      'hidden',
      'aria-hidden',
      'href',
    ],
  });
}

// ==========================================
// RUNTIME MESSAGE LISTENER
// ==========================================

chrome.runtime.onMessage.addListener(
  (request, sender, sendResponse) => {
    if (!request || typeof request !== 'object') {
      return false;
    }

    if (sender?.id && sender.id !== chrome.runtime.id) {
      return false;
    }

    if (request.action === 'ping') {
      sendResponse({
        alive: !pageDisposed,
        pageUrl: window.location.href,
      });
      return false;
    }

    if (
      typeof request.pageUrl === 'string' &&
      request.pageUrl !== window.location.href
    ) {
      sendResponse({
        acknowledged: false,
        reason: 'stale_route',
      });
      return false;
    }

    if (
      request.action === 'pageNavigation' ||
      request.action === 'resetThreatState'
    ) {
      const changed = synchronizeNavigationState();

      readScanSettings().then(settings => {
        if (
          pageDisposed ||
          !settings.ok ||
          !settings.enableAutoScan
        ) {
          sendResponse({
            success: true,
            acknowledged: false,
            changed,
            reason: 'auto_scan_disabled',
          });
          return;
        }

        refreshScanObserver();

        const alreadyHandled = (
          !changed &&
          (
            activeScanContext ||
            analysisInProgress ||
            requestAnalysisPending ||
            threatDetectedForPage ||
            lastAnalyzedContent
          )
        );

        if (!alreadyHandled) {
          schedulePageAnalysis({ trigger: 'auto' }, 300);
        }

        sendResponse({
          success: true,
          acknowledged: true,
          changed,
          reason: alreadyHandled ? 'already_current' : 'scheduled',
        });
      }).catch(() => {
        sendResponse({
          success: false,
          acknowledged: false,
          reason: 'settings_unavailable',
        });
      });

      return true;
    }

    if (request.action === 'requestAnalysis') {
      if (request.trigger === 'manual') {
        threatDetectedForPage = false;
        requestAnalysisPending = false;

        invalidateActiveScan();
        cancelScheduledScans(true);

        analysisInProgress = false;
        scanAttempts = 0;
        insufficientContentRetries = 0;
        transientScanRetries = 0;
        lastAnalyzedContent = '';
        quotaBannerDismissed = false;

        currentUrl = window.location.href;
        lastUrlSPA = currentUrl;

        clearDadblockUI();

        sendResponse({ acknowledged: true });

        analyzePage({ trigger: 'manual' }).catch(() => {});
        return false;
      }

      readScanSettings().then(settings => {
        synchronizeNavigationState();

        if (
          pageDisposed ||
          !settings.ok ||
          !settings.enableAutoScan
        ) {
          sendResponse({
            acknowledged: false,
            reason: 'auto_scan_disabled',
          });
          return;
        }

        if (threatDetectedForPage) {
          sendResponse({
            acknowledged: false,
            reason: 'threat_detected',
          });
          return;
        }

        if (
          requestAnalysisPending ||
          analysisInProgress ||
          activeScanContext
        ) {
          sendResponse({
            acknowledged: false,
            reason: 'already_pending',
          });
          return;
        }

        requestAnalysisPending = true;

        sendResponse({ acknowledged: true });
        analyzePage({ trigger: 'auto' }).catch(() => {});
      }).catch(() => {
        sendResponse({
          acknowledged: false,
          reason: 'settings_unavailable',
        });
      });

      return true;
    }

    if (request.action === 'removeThreatBanner') {
      clearDadblockUI();
      sendResponse({ success: true });
      return false;
    }

    if (
      request.action === 'showThreatBanner' ||
      request.action === 'updateThreatBanner'
    ) {
      // Preserve all result fields, including evidence and dadTip.
      const result = request.result &&
        typeof request.result === 'object'
          ? {
              ...request.result,
              ...(request.bannerEnabled === false
                ? { bannerEnabled: false }
                : {}),
            }
          : null;

      if (pageDisposed) {
        sendResponse({ success: false, shown: false });
        return false;
      }

      rememberBackgroundBannerSetting(result);

      const operation = request.action === 'showThreatBanner'
        ? showWarningBanner(result, request.isStage1 === true)
        : updateWarningBanner(result);

      Promise.resolve(operation).then(
        shown => sendResponse({
          success: true,
          shown: shown === true,
        }),
        () => sendResponse({
          success: false,
          shown: false,
        })
      );

      return true;
    }

    return false;
  }
);

// ==========================================
// SETTINGS CHANGES
// ==========================================

chrome.storage.onChanged.addListener((changes, namespace) => {
  if (namespace !== 'local' || pageDisposed) {
    return;
  }

  const changedScanKeys = SCAN_SETTING_KEYS.filter(key =>
    Object.prototype.hasOwnProperty.call(changes, key)
  );

  if (changedScanKeys.length > 0) {
    const wasLoaded = scanSettingsLoaded;
    const wasAutoScanEnabled = enableAutoScan;

    scanSettingsRevision++;

    const nextValues = { ...scanSettingsValues };

    for (const key of changedScanKeys) {
      const value = changes[key].newValue;

      if (value === undefined) {
        delete nextValues[key];
      } else {
        nextValues[key] = value;
      }
    }

    scanSettingsValues = nextValues;

    if (
      !wasLoaded &&
      (changes.selectedMode || changes.activeMode)
    ) {
      resetForModeChange();
    }

    if (wasLoaded) {
      applyScanSettings(nextValues);
    }

    if (
      changes.enableAutoScan?.newValue === false ||
      (
        typeof nextValues.enableAutoScan !== 'boolean' &&
        changes.autoScan?.newValue === false
      )
    ) {
      enableAutoScan = false;
      cancelAutomaticScanning();
    }

    if (
      changes.bannerEnabled?.newValue === false ||
      (
        typeof nextValues.bannerEnabled !== 'boolean' &&
        changes.showBanner?.newValue === false
      )
    ) {
      bannerEnabled = false;
      clearDadblockUI();
    }

    readScanSettings().then(settings => {
      if (pageDisposed) {
        return;
      }

      refreshScanObserver();

      if (
        settings.ok &&
        settings.enableAutoScan &&
        !wasAutoScanEnabled
      ) {
        scanAttempts = 0;
        insufficientContentRetries = 0;
        transientScanRetries = 0;
        lastAnalyzedContent = '';

        refreshScanObserver();
        schedulePageAnalysis({ trigger: 'auto' });
      }
    }).catch(() => {});
  }

  if (changes.cosmeticDisabledDomains) {
    cosmeticSettingsRevision++;

    const domains = Array.isArray(
      changes.cosmeticDisabledDomains.newValue
    )
      ? changes.cosmeticDisabledDomains.newValue
      : [];

    _cosmeticDisabledForThisPage =
      domains.includes(window.location.hostname);

    cosmeticSettingsReady = true;

    if (_cosmeticDisabledForThisPage) {
      stopCosmeticEngines();
    } else {
      startCosmeticEngines();
    }
  }
});

// ==========================================
// NAVIGATION AND SCAN BOOTSTRAP
// ==========================================

function handlePageNavigation() {
  if (pageDisposed || !synchronizeNavigationState()) {
    return;
  }

  refreshScanObserver();
  schedulePageAnalysis({ trigger: 'auto' }, 500);
}

// The background uses webNavigation for page-world History API changes.
// Native popstate/hashchange events remain useful for immediate local reset.

window.addEventListener('popstate', handlePageNavigation);
window.addEventListener('hashchange', handlePageNavigation);

function whenDocumentReady(callback) {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', callback, {
      once: true,
    });
  } else {
    callback();
  }
}

async function bootstrapPageScanning() {
  const settings = await readScanSettings();

  if (pageDisposed || !settings.ok) {
    return;
  }

  whenDocumentReady(() => {
    if (pageDisposed) {
      return;
    }

    refreshScanObserver();

    if (scanSettingsLoaded && enableAutoScan) {
      schedulePageAnalysis({ trigger: 'auto' });
    }
  });
}

// ==========================================
// DADBLOCK ADVANCED COSMETIC FILTERING
// ==========================================
// 1. Selector Engine
// 2. Attribute Sweep
// 3. Sponsored Walker
// 4. Sticky Bar Zapper
//
// Cosmetic filtering is independent of AI auto-scan.
// These engines never send extracted page content to the background.
// ==========================================

const _IS_YOUTUBE = hostnameMatchesDomain(
  window.location.hostname,
  'youtube.com'
);

let cosmeticSettingsReady = false;
let cosmeticSettingsRevision = 0;

let _cosmeticScheduled = false;
let cosmeticFirstAnimationFrame = null;
let cosmeticSecondAnimationFrame = null;
let overlayZapperInterval = null;

// ==========================================
// ENGINE 1: SELECTOR ENGINE
// ==========================================

const AD_SELECTORS = [
  // Google / DoubleClick / AdSense
  '.adsbygoogle',
  'ins.adsbygoogle',
  '[id^="google_ads_iframe_"]',
  '[id^="google_ads_frame"]',
  '[id*="gpt-ad-"]',
  '[id*="div-gpt-ad"]',
  '[data-google-av-cxn]',
  '[data-google-container-id]',
  '[data-ad-status="unfilled"]',
  '[data-ad-status="filled"]',
  'div[id^="aw0"]',

  // GPT / Header Bidding / Prebid
  '[data-dfp-ad]',
  '[data-dfp-slot]',
  '[data-prebid]',
  '[data-prebid-slot]',
  '[class*="prebid-ad"]',

  // Taboola
  '.taboola-container',
  '.taboola-widget',
  '[id^="taboola-"]',
  '[data-taboola-widget]',
  'div[class*="trc_related"]',

  // Outbrain
  '.outbrain-widget',
  '.OUTBRAIN',
  '[data-widget-id^="AR_"]',
  '[class*="ob-widget"]',

  // Criteo
  '[id^="criteo-"]',
  '[class*="criteo-ad"]',
  '[data-csa-c-type="ad"]',

  // Amazon Ads
  '[id^="amzn_assoc_ad"]',
  'span.a-sponsored-label',

  // Generic IAB / Standard patterns
  '.ad-banner',
  '.ad-container',
  '.ad-wrapper',
  '.ad-slot',
  '.ad-unit',
  '.ad-leaderboard',
  '.ad-rectangle',
  '.ad-skyscraper',
  '.ad-halfpage',
  '.ad-billboard',
  '.ad-box',
  '.ad-break',
  '[class*="adhesion-ad"]',
  '[class*="sponsor-label"]',
  '[id*="ad-container"]',
  '[id*="ad-slot"]',
  '[id*="ad-unit"]',
  '[id*="banner-ad"]',
  '[id*="leaderboard-ad"]',

  // Promoted / Sponsored content cards
  '.promoted-tweet',
  '[data-promoted="true"]',
  '[data-testid="placementTracking"]',
  '[class*="promoted-post"]',
  '[class*="sponsored-post"]',
  '[class*="native-ad"]',
  '[class*="native-advertisement"]',

  // Sticky / Adhesion units
  '[class*="sticky-ad"]',
  '[class*="bottom-ad"]',
  '[class*="top-ad-bar"]',
  '[id*="sticky-ad"]',

  // Push notification prompts
  '[class*="push-notification-prompt"]',
  '[id*="push-prompt"]',
  '[class*="notif-prompt"]',
  '[id*="onesignal"]',
  '[class*="onesignal"]',

  // Video player ad overlays
  '.jw-ad-container',
  '.jw-ima-ad-container',
  '.vjs-ad-container',
  '[class*="videojs-ad"]',
  '[class*="ima-ad-container"]',

  // News site and content-farm ad networks
  '.adsninja-ad',
  '[id^="nativo-"]',
  '[class*="nativo"]',
  '[class*="mgid-widget"]',
  '[id^="mgid-"]',
  '[class*="zergnet"]',
  '[id^="zergnet"]',
  '#carbonads',
  '.carbon-ads',

  // Streaming corner ads
  'a[href*="wcostream.com/ads/"]',
  'img[src*="/ads/"]',
];

// ==========================================
// ENGINE 2: ATTRIBUTE SWEEP
// ==========================================

const AD_DATA_ATTRIBUTES = [
  'data-ad',
  'data-ad-slot',
  'data-ad-unit',
  'data-ad-client',
  'data-ad-format',
  'data-advertisement',
  'data-ad-id',
  'data-ad-zone',
  'data-ad-type',
  'data-ad-network',
  'data-ad-label',
  'data-ad-refresh',
  'data-ad-height',
  'data-ad-width',
];

const AD_ARIA_LABELS = new Set([
  'advertisement',
  'ad',
  'sponsored',
  'sponsored content',
  'promoted',
  'promoted content',
]);

// ==========================================
// ENGINE 3: SPONSORED WALKER
// ==========================================

const SPONSORED_PATTERNS = [
  /^sponsored$/i,
  /^advertisement$/i,
  /^advertis(ing|ement)$/i,
  /^promoted$/i,
  /^promoted content$/i,
  /^paid content$/i,
  /^paid post$/i,
  /^paid partnership$/i,
  /^partner content$/i,
  /^brand content$/i,
];

const BLOCK_TAGS = new Set([
  'ARTICLE',
  'SECTION',
  'ASIDE',
  'LI',
  'DIV',
  'FIGURE',
]);

const SAFE_ANCESTORS = new Set([
  'BODY',
  'HTML',
  'MAIN',
  'HEADER',
  'FOOTER',
  'NAV',
]);

function hasExplicitAdMarker(element) {
  if (!element || element.nodeType !== Node.ELEMENT_NODE) {
    return false;
  }

  try {
    if (element.matches(AD_SELECTORS.join(', '))) {
      return true;
    }

    for (const attribute of AD_DATA_ATTRIBUTES) {
      const value = element.getAttribute(attribute);

      if (value !== null && value !== 'false' && value !== '0') {
        return true;
      }
    }

    return AD_ARIA_LABELS.has(
      (element.getAttribute('aria-label') || '').toLowerCase().trim()
    );
  } catch {
    return false;
  }
}

function findSponsoredContainer(textNode) {
  let node = textNode.parentElement;
  let depth = 0;
  let labelContainer = null;

  const labelText = (textNode.textContent || '').trim();

  while (node && depth < 8) {
    if (
      SAFE_ANCESTORS.has(node.tagName) ||
      containsProtectedInteractiveContent(node)
    ) {
      break;
    }

    if (BLOCK_TAGS.has(node.tagName)) {
      const rect = node.getBoundingClientRect();

      if (
        rect.height > 0 &&
        rect.width > 0 &&
        rect.height < 800 &&
        rect.width < 1400 &&
        hasExplicitAdMarker(node)
      ) {
        return node;
      }

      // A sponsored label alone does not justify removing a product grid,
      // carousel or an unrelated section containing the label.
      if (
        !labelContainer &&
        rect.height > 0 &&
        rect.height <= 80 &&
        (node.textContent || '').trim() === labelText &&
        node.childElementCount <= 3
      ) {
        labelContainer = node;
      }
    }

    node = node.parentElement;
    depth++;
  }

  return labelContainer;
}

// ==========================================
// ENGINE 4: STICKY BAR ZAPPER
// ==========================================

function isLikelyStickyAdBar(element, style, rect) {
  if (containsProtectedInteractiveContent(element)) {
    return false;
  }

  const viewportWidth =
    window.innerWidth || document.documentElement.clientWidth;

  const viewportHeight =
    window.innerHeight || document.documentElement.clientHeight;

  if (style.position !== 'fixed' && style.position !== 'sticky') {
    return false;
  }

  if (
    rect.width < viewportWidth * 0.5 ||
    rect.height <= 0 ||
    rect.height > 180
  ) {
    return false;
  }

  if (
    rect.top >= 150 &&
    rect.bottom <= viewportHeight - 150
  ) {
    return false;
  }

  const hasAdFrame = Array.from(
    element.querySelectorAll('iframe')
  ).some(iframe => {
    if (isPaymentIframe(iframe)) {
      return false;
    }

    if (/^(?:google_ads_iframe_|google_ads_frame|gpt[-_]|taboola[-_])/i
      .test(iframe.id || '')) {
      return true;
    }

    try {
      const url = new URL(
        iframe.getAttribute('src') || '',
        iframe.ownerDocument.baseURI
      );

      return [
        'doubleclick.net',
        'googlesyndication.com',
        'googleadservices.com',
        'taboola.com',
        'outbrain.com',
      ].some(domain => hostnameMatchesDomain(url.hostname, domain));
    } catch {
      return false;
    }
  });

  return hasExplicitAdMarker(element) || hasAdFrame;
}

// ==========================================
// SHARED COSMETIC HELPERS
// ==========================================

function cosmeticEnginesAllowed() {
  return (
    !pageDisposed &&
    cosmeticSettingsReady &&
    !_IS_YOUTUBE &&
    !_cosmeticDisabledForThisPage &&
    !isPaymentDocument(document)
  );
}

function hideElement(element) {
  if (
    !cosmeticEnginesAllowed() ||
    !element ||
    !element.style ||
    element.style.display === 'none' ||
    SAFE_ANCESTORS.has(element.tagName) ||
    element.matches(
      '[role="main"], [role="navigation"], [role="banner"], ' +
      '[role="contentinfo"], dialog, [aria-modal="true"], ' +
      '[id^="db-guard-"]'
    ) ||
    containsProtectedInteractiveContent(element)
  ) {
    return;
  }

  element.style.setProperty('display', 'none', 'important');
}

function scheduleCosmeticPass() {
  if (!cosmeticEnginesAllowed() || _cosmeticScheduled) {
    return;
  }

  _cosmeticScheduled = true;

  cosmeticFirstAnimationFrame = requestAnimationFrame(() => {
    cosmeticFirstAnimationFrame = null;

    cosmeticSecondAnimationFrame = requestAnimationFrame(() => {
      cosmeticSecondAnimationFrame = null;
      _cosmeticScheduled = false;

      if (cosmeticEnginesAllowed()) {
        runCosmeticEngines();
      }
    });
  });
}

// ==========================================
// FOUR-ENGINE ORCHESTRATOR
// ==========================================

function runCosmeticEngines() {
  if (!cosmeticEnginesAllowed() || !document.body) {
    return;
  }

  restoreOverlayPointerEvents();

  // Engine 1: Selector sweep.
  try {
    document.querySelectorAll(
      AD_SELECTORS.join(', ')
    ).forEach(hideElement);
  } catch {
    // A malformed selector must not stop the other engines.
  }

  // Engine 2: Attribute sweep.
  for (const attribute of AD_DATA_ATTRIBUTES) {
    document.querySelectorAll(`[${attribute}]`).forEach(element => {
      const value = element.getAttribute(attribute);

      if (value !== null && value !== 'false' && value !== '0') {
        hideElement(element);
      }
    });
  }

  document.querySelectorAll('[aria-label]').forEach(element => {
    if (isProtectedInteractiveElement(element)) {
      return;
    }

    const label = (element.getAttribute('aria-label') || '')
      .toLowerCase()
      .trim();

    if (AD_ARIA_LABELS.has(label)) {
      hideElement(element);
    }
  });

  // Engine 3: Sponsored-text walker.
  const walker = document.createTreeWalker(
    document.body,
    NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT,
    {
      acceptNode(node) {
        if (isProtectedElement(node)) {
          return NodeFilter.FILTER_REJECT;
        }

        if (node.nodeType === Node.ELEMENT_NODE) {
          return NodeFilter.FILTER_SKIP;
        }

        const text = node.textContent.trim();

        if (text.length === 0 || text.length > 60) {
          return NodeFilter.FILTER_REJECT;
        }

        return NodeFilter.FILTER_ACCEPT;
      },
    }
  );

  let textNode;

  while ((textNode = walker.nextNode())) {
    const text = textNode.textContent.trim();

    if (SPONSORED_PATTERNS.some(pattern => pattern.test(text))) {
      const container = findSponsoredContainer(textNode);

      if (container) {
        hideElement(container);
      }
    }
  }

  // Engine 4: Sticky bar zapper.
  const stickyQuery = [
    'div[style*="position:fixed"]',
    'div[style*="position: fixed"]',
    'div[style*="position:sticky"]',
    'div[style*="position: sticky"]',
  ].join(', ');

  document.querySelectorAll(stickyQuery).forEach(element => {
    try {
      if (containsProtectedInteractiveContent(element)) {
        return;
      }

      const style = window.getComputedStyle(element);

      if (style.display === 'none') {
        return;
      }

      const rect = element.getBoundingClientRect();

      if (isLikelyStickyAdBar(element, style, rect)) {
        hideElement(element);
      }
    } catch {
      // Detached elements are ignored.
    }
  });
}

// ==========================================
// COSMETIC OBSERVER
// ==========================================

const cosmeticObserverConfig = {
  childList: true,
  subtree: true,
  attributes: true,
  attributeFilter: [
    'class',
    'style',
    'data-ad-status',
    'id',
    'aria-label',
  ],
};

const cosmeticObserver = new MutationObserver(mutations => {
  if (!cosmeticEnginesAllowed()) {
    return;
  }

  for (const mutation of mutations) {
    if (
      (
        mutation.type === 'attributes' ||
        (
          mutation.type === 'childList' &&
          mutation.addedNodes.length > 0
        )
      ) &&
      isRelevantPageMutation(mutation)
    ) {
      scheduleCosmeticPass();
      return;
    }
  }
});

// ==========================================
// INVISIBLE OVERLAY ZAPPER
// ==========================================

const ZAPPER_EXCLUDE_TAGS = new Set([
  'VIDEO',
  'CANVAS',
  'INPUT',
  'BUTTON',
  'SELECT',
  'TEXTAREA',
  'IMG',
]);

const overlayPointerOverrides = new Map();

function restoreOverlayPointerEvents(restoreAll = false) {
  for (const [element, previous] of overlayPointerOverrides) {
    try {
      if (!restoreAll && element.isConnected) {
        const style = window.getComputedStyle(element);
        const rect = element.getBoundingClientRect();

        if (isInvisibleTrap(element, style, rect)) {
          continue;
        }
      }

      if (
        element.style.getPropertyValue('pointer-events') === 'none' &&
        element.style.getPropertyPriority('pointer-events') === 'important'
      ) {
        if (previous.value) {
          element.style.setProperty(
            'pointer-events',
            previous.value,
            previous.priority
          );
        } else {
          element.style.removeProperty('pointer-events');
        }
      }
    } catch {
      // Detached elements need no further intervention.
    }

    overlayPointerOverrides.delete(element);
  }
}

function disableOverlayInterception(element) {
  if (!overlayPointerOverrides.has(element)) {
    overlayPointerOverrides.set(element, {
      value: element.style.getPropertyValue('pointer-events'),
      priority: element.style.getPropertyPriority('pointer-events'),
    });
  }

  element.style.setProperty('pointer-events', 'none', 'important');
}

function isInvisibleTrap(element, style, rect) {
  if (
    !element?.isConnected ||
    SAFE_ANCESTORS.has(element.tagName) ||
    containsProtectedInteractiveContent(element) ||
    element.closest(
      'dialog, [aria-modal="true"], [aria-busy="true"], ' +
      '[role="progressbar"], [id^="db-guard-"], ' +
      '.jwplayer, .plyr, .video-js, .html5-video-player, [data-player]'
    )
  ) {
    return false;
  }

  if (style.position !== 'fixed' && style.position !== 'absolute') {
    return false;
  }

  // Real content stays intact even when its container is transparent.
  if (
    (element.textContent || '').trim() ||
    element.querySelector(
      'img, svg, canvas, video, audio, iframe, form, input, button, ' +
      'select, textarea, a[href], [contenteditable], dialog, ' +
      '[role="button"], [role="link"], [role="dialog"], ' +
      '[aria-modal="true"], [aria-busy="true"], [role="progressbar"]'
    ) ||
    (style.backgroundImage && style.backgroundImage !== 'none')
  ) {
    return false;
  }

  const metadata = [
    element.getAttribute('id') || '',
    element.getAttribute('class') || '',
  ].join(' ');

  if (
    /(?:^|[\s_-])(?:backdrop|scrim|modal|dialog)(?:$|[\s_-])/i
      .test(metadata) &&
    Array.from(document.querySelectorAll(
      'dialog[open], [role="dialog"], [aria-modal="true"]'
    )).some(dialog => {
      const dialogStyle = window.getComputedStyle(dialog);
      const dialogRect = dialog.getBoundingClientRect();

      return (
        dialogStyle.display !== 'none' &&
        dialogStyle.visibility !== 'hidden' &&
        dialogStyle.opacity !== '0' &&
        dialogRect.width > 0 &&
        dialogRect.height > 0
      );
    })
  ) {
    return false;
  }

  const viewportWidth =
    window.innerWidth || document.documentElement.clientWidth;

  const viewportHeight =
    window.innerHeight || document.documentElement.clientHeight;

  if (viewportWidth <= 0 || viewportHeight <= 0) {
    return false;
  }

  const visibleWidth = Math.max(
    0,
    Math.min(rect.right, viewportWidth) - Math.max(rect.left, 0)
  );

  const visibleHeight = Math.max(
    0,
    Math.min(rect.bottom, viewportHeight) - Math.max(rect.top, 0)
  );

  if (
    visibleWidth < viewportWidth * 0.8 ||
    visibleHeight < viewportHeight * 0.8
  ) {
    return false;
  }

  const opacity = Number.parseFloat(style.opacity);

  return (
    (Number.isFinite(opacity) && opacity <= 0.05) ||
    style.backgroundColor === 'transparent' ||
    /rgba\([^)]*,\s*0(?:\.0+)?\s*\)/i.test(style.backgroundColor)
  );
}

function zapInvisibleOverlays() {
  if (!cosmeticEnginesAllowed() || !document.body) {
    return;
  }

  restoreOverlayPointerEvents();

  document.querySelectorAll(
    'div, a, span, section, aside'
  ).forEach(element => {
    try {
      if (
        ZAPPER_EXCLUDE_TAGS.has(element.tagName) ||
        containsProtectedInteractiveContent(element)
      ) {
        return;
      }

      const style = window.getComputedStyle(element);

      if (
        style.display === 'none' ||
        style.visibility === 'hidden' ||
        style.pointerEvents === 'none'
      ) {
        return;
      }

      const rect = element.getBoundingClientRect();

      if (rect.width === 0 || rect.height === 0) {
        return;
      }

      if (isInvisibleTrap(element, style, rect)) {
        disableOverlayInterception(element);
      }
    } catch {
      // Detached elements are ignored.
    }
  });
}

// ==========================================
// COSMETIC SETTINGS AND BOOTSTRAP
// ==========================================

async function checkCosmeticDisabled() {
  for (let attempt = 0; attempt < 3; attempt++) {
    const revision = cosmeticSettingsRevision;

    try {
      const data = await chrome.storage.local.get([
        'cosmeticDisabledDomains',
      ]);

      if (revision !== cosmeticSettingsRevision) {
        continue;
      }

      const domains = Array.isArray(data.cosmeticDisabledDomains)
        ? data.cosmeticDisabledDomains
        : [];

      _cosmeticDisabledForThisPage =
        domains.includes(window.location.hostname);

      cosmeticSettingsReady = true;
      return;
    } catch {
      _cosmeticDisabledForThisPage = true;
      cosmeticSettingsReady = false;
      stopCosmeticEngines();
      return;
    }
  }

  _cosmeticDisabledForThisPage = true;
  cosmeticSettingsReady = false;
  stopCosmeticEngines();
}

function stopCosmeticEngines() {
  cosmeticObserver.disconnect();
  restoreOverlayPointerEvents(true);

  if (cosmeticFirstAnimationFrame !== null) {
    cancelAnimationFrame(cosmeticFirstAnimationFrame);
    cosmeticFirstAnimationFrame = null;
  }

  if (cosmeticSecondAnimationFrame !== null) {
    cancelAnimationFrame(cosmeticSecondAnimationFrame);
    cosmeticSecondAnimationFrame = null;
  }

  _cosmeticScheduled = false;

  if (overlayZapperInterval !== null) {
    clearInterval(overlayZapperInterval);
    overlayZapperInterval = null;
  }
}

function startCosmeticEngines() {
  if (!cosmeticEnginesAllowed()) {
    stopCosmeticEngines();
    return;
  }

  whenDocumentReady(() => {
    if (!cosmeticEnginesAllowed() || !document.body) {
      return;
    }

    runCosmeticEngines();

    cosmeticObserver.disconnect();
    cosmeticObserver.observe(
      document.body,
      cosmeticObserverConfig
    );

    zapInvisibleOverlays();

    if (overlayZapperInterval === null) {
      overlayZapperInterval = window.setInterval(
        zapInvisibleOverlays,
        1500
      );
    }
  });
}

async function bootstrapCosmeticEngines() {
  await checkCosmeticDisabled();

  if (!pageDisposed) {
    startCosmeticEngines();
  }
}

// ==========================================
// PAGE LIFECYCLE
// ==========================================

window.addEventListener('pagehide', event => {
  if (!event.isTrusted) {
    return;
  }

  pageDisposed = true;

  invalidateActiveScan();
  cancelScheduledScans(true);

  if (observer) {
    observer.disconnect();
  }

  stopCosmeticEngines();
  clearDadblockUI();
});

window.addEventListener('pageshow', event => {
  if (!event.isTrusted || (!event.persisted && !pageDisposed)) {
    return;
  }

  pageDisposed = false;

  scanSettingsLoaded = false;
  cosmeticSettingsReady = false;

  currentUrl = window.location.href;
  lastUrlSPA = currentUrl;

  scanAttempts = 0;
  insufficientContentRetries = 0;
  transientScanRetries = 0;
  lastAnalyzedContent = '';

  threatDetectedForPage = false;
  requestAnalysisPending = false;
  analysisInProgress = false;
  quotaBannerDismissed = false;
  backgroundBannerEnabled = true;

  bootstrapPageScanning().catch(() => {});
  bootstrapCosmeticEngines().catch(() => {});
});

// Settings resolve before the first automatic extraction or UI injection.
bootstrapPageScanning().catch(() => {});

// Cosmetic filtering retains its independent per-domain setting.
bootstrapCosmeticEngines().catch(() => {});
