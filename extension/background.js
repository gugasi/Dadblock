// Dadblock Background Service Worker
// Coordinates on-device/cloud scans, document ownership,
// and authenticated ad-block rules.

import {
  initializeLocalMode,
  analyzeLocal,
  getLocalAvailability,
  shutdownLocalMode,
  buildLocalUnavailableResult,
} from './modes/local/detector.js';

import {
  initializeCloudMode,
  analyzeCloud,
} from './modes/cloud/detector.js';

import {
  AUDIT_POLICY_REVISION,
} from './utils/audit-explanations.js';

console.log('[Dadblock] Background script starting...');

let currentSessions = null;
let activeMode = 'cloud';
let isAiAvailable = false;
let aiInitPromise = null;
let aiAvailabilityStatus = 'initializing';
let modeSwitchInFlight = null;

const DETECTION_CACHE = new Map();
const ACTIVE_ANALYSES = new Map();
const TAB_SCAN_EPOCHS = new Map();
const TAB_DOCUMENTS = new Map();
const TAB_STORAGE_QUEUES = new Map();
const SCANNING_ANIMATIONS = new Map();

// ============================================================
// SETTINGS
// ============================================================

// Read settings before each decision. Storage failures pause
// automatic work instead of silently enabling it.
const DEFAULT_SETTINGS = Object.freeze({
  enableAutoScan: true,
  bannerEnabled: true,
  selectedMode: 'cloud',
});

async function getSettings() {
  try {
    const settings = await chrome.storage.local.get([
      'enableAutoScan',
      'autoScan',
      'bannerEnabled',
      'showBanner',
      'selectedMode',
      'activeMode',
    ]);

    let mode = settings.selectedMode || settings.activeMode;

    if (mode !== 'local' && mode !== 'cloud') {
      mode = DEFAULT_SETTINGS.selectedMode;
    }

    return {
      ok: true,
      enableAutoScan:
        typeof settings.enableAutoScan === 'boolean'
          ? settings.enableAutoScan
          : settings.autoScan !== false,
      bannerEnabled:
        typeof settings.bannerEnabled === 'boolean'
          ? settings.bannerEnabled
          : settings.showBanner !== false,
      selectedMode: mode,
    };
  } catch (error) {
    console.warn(
      '[Dadblock] Could not read settings; automatic scanning paused:',
      error && error.name
    );

    return {
      ok: false,
      enableAutoScan: false,
      bannerEnabled: true,
      selectedMode: DEFAULT_SETTINGS.selectedMode,
    };
  }
}

// ============================================================
// MANUAL SCAN INTENT
// ============================================================

const MANUAL_SCAN_TABS = new Map();
const MANUAL_SCAN_TTL_MS = 30000;

function markManualScan(tabId) {
  if (Number.isInteger(tabId)) {
    MANUAL_SCAN_TABS.set(
      tabId,
      Date.now() + MANUAL_SCAN_TTL_MS
    );
  }
}

function consumeManualScan(tabId) {
  const expiry = MANUAL_SCAN_TABS.get(tabId);

  if (expiry === undefined) {
    return false;
  }

  MANUAL_SCAN_TABS.delete(tabId);

  return Date.now() <= expiry;
}

// ============================================================
// VERDICT NORMALIZATION
// ============================================================

// SAFE becomes green only when it is a validated v2 result.
// Errors, skipped scans, unavailable AI, and inconclusive results
// never become SAFE.
//
// Preserve the full detector object. In particular, evidence,
// dadTip, isStorefront, and validation metadata must pass through.
const KNOWN_JUDGMENTS = new Set([
  'SAFE',
  'SCAM',
  'WARNING',
  'THREAT',
  'INBOX',
  'INCONCLUSIVE',
  'SKIPPED',
  'IGNORED',
  'RATE_LIMITED',
  'QUOTA_EXCEEDED',
  'ERROR',
  'AI_UNAVAILABLE',
  'CONFIGURATION_ERROR',
]);

const DANGER_JUDGMENTS = new Set([
  'SCAM',
  'WARNING',
  'THREAT',
]);

function normalizeResult(result) {
  const raw =
    result && typeof result === 'object'
      ? result
      : {};

  let judgment =
    typeof raw.judgment === 'string'
      ? raw.judgment.trim().toUpperCase()
      : '';

  if (!KNOWN_JUDGMENTS.has(judgment)) {
    judgment = 'UNVERIFIED';
  }

  let signal = 'neutral';

  if (DANGER_JUDGMENTS.has(judgment)) {
    signal = 'danger';
  } else if (
    judgment === 'SAFE' &&
    raw.schemaVersion === 2 &&
    raw.conclusive === true &&
    raw.safe === true &&
    raw.isMalicious === false
  ) {
    signal = 'safe';
  }

  const inboxVerdict =
    judgment === 'INBOX' &&
    raw.schemaVersion === 2 &&
    raw.conclusive === true;

  return {
    ...raw,
    judgment,
    signal,
    conclusive:
      signal !== 'neutral' || inboxVerdict,
    safe: signal === 'safe',
    isMalicious:
      signal === 'danger'
        ? true
        : signal === 'safe' || inboxVerdict
          ? false
          : null,
    isWarning: judgment === 'WARNING',
  };
}

// ============================================================
// OFFSCREEN DOCUMENT MANAGEMENT
// ============================================================

const OFFSCREEN_DOCUMENT_PATH = 'offscreen.html';

const OFFSCREEN_REASON = 'WORKERS';

const OFFSCREEN_JUSTIFICATION =
  'Hosts the on-device Prompt API (LanguageModel), ' +
  'which is not exposed to extension service workers, ' +
  'to classify page text locally.';

const OFFSCREEN_IDLE_CLOSE_MS = 10 * 60 * 1000;
const LOCAL_RETRY_INTERVAL_MS = 60 * 1000;

let lastLocalUseAt = 0;
let lastLocalRetryAt = 0;
let offscreenCreating = null;
let offscreenLifecycle = Promise.resolve();

// Serialize create/close operations so they cannot interleave.
function withOffscreenLock(task) {
  const run = offscreenLifecycle.then(task, task);

  offscreenLifecycle = run.then(
    () => undefined,
    () => undefined
  );

  return run;
}

async function hasOffscreenDocument() {
  const offscreenUrl = chrome.runtime.getURL(
    OFFSCREEN_DOCUMENT_PATH
  );

  if (
    typeof chrome.runtime.getContexts === 'function'
  ) {
    const contexts = await chrome.runtime.getContexts({
      contextTypes: ['OFFSCREEN_DOCUMENT'],
      documentUrls: [offscreenUrl],
    });

    return contexts.length > 0;
  }

  if (
    chrome.offscreen &&
    typeof chrome.offscreen.hasDocument === 'function'
  ) {
    return chrome.offscreen.hasDocument();
  }

  const matched = await self.clients.matchAll();

  return matched.some(
    client => client.url === offscreenUrl
  );
}

// Idempotent, serialized, and safe when the detector concurrently
// ensures that its own offscreen document exists.
function setupOffscreenDocument() {
  return withOffscreenLock(async () => {
    try {
      if (
        !chrome.offscreen ||
        typeof chrome.offscreen.createDocument !== 'function'
      ) {
        return false;
      }

      if (await hasOffscreenDocument()) {
        return true;
      }

      if (!offscreenCreating) {
        offscreenCreating = chrome.offscreen
          .createDocument({
            url: OFFSCREEN_DOCUMENT_PATH,
            reasons: [OFFSCREEN_REASON],
            justification: OFFSCREEN_JUSTIFICATION,
          })
          .catch(async error => {
            if (await hasOffscreenDocument()) {
              return;
            }

            throw error;
          })
          .finally(() => {
            offscreenCreating = null;
          });
      }

      await offscreenCreating;

      return true;
    } catch (error) {
      console.warn(
        '[Dadblock] Could not create the offscreen document:',
        error && error.name
      );

      return false;
    }
  });
}

// Shut down detector sessions before closing the document.
function closeOffscreenDocument() {
  return withOffscreenLock(async () => {
    try {
      if (
        !chrome.offscreen ||
        typeof chrome.offscreen.closeDocument !== 'function'
      ) {
        return false;
      }

      if (!(await hasOffscreenDocument())) {
        return false;
      }

      await shutdownLocalMode();

      if (await hasOffscreenDocument()) {
        await chrome.offscreen.closeDocument();
      }

      return true;
    } catch (error) {
      console.warn(
        '[Dadblock] Could not close the offscreen document:',
        error && error.name
      );

      return false;
    }
  });
}

// ============================================================
// RULE SIGNATURE VERIFICATION
// ============================================================

const DADBLOCK_PUBLIC_KEY_JWK = {
  key_ops: ['verify'],
  ext: true,
  kty: 'EC',
  x: 'y8j_RBDejVVLkTAmjPOahB-P0P4ykf6t0Ab2gdGggZk',
  y: 'FzJLIQ6muBA6y_m312BWSIIISTJoBYqeJdb8RNZPcuI',
  crv: 'P-256',
};

const MAX_RULES_AGE_MS =
  7 * 24 * 60 * 60 * 1000;

// Verify the exact signed payload string. Do not reconstruct the
// JSON before signature verification.
async function verifyAndParseRulesPayload(
  payload,
  signatureB64
) {
  try {
    const key = await crypto.subtle.importKey(
      'jwk',
      DADBLOCK_PUBLIC_KEY_JWK,
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      false,
      ['verify']
    );

    const signatureBytes = Uint8Array.from(
      atob(signatureB64),
      character => character.charCodeAt(0)
    );

    const dataBytes = new TextEncoder().encode(
      payload
    );

    const isValid = await crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: 'SHA-256',
      },
      key,
      signatureBytes,
      dataBytes
    );

    if (!isValid) {
      return null;
    }

    const { rules, issuedAt } = JSON.parse(payload);

    if (
      !Array.isArray(rules) ||
      typeof issuedAt !== 'number' ||
      !Number.isFinite(issuedAt)
    ) {
      console.error(
        '[Dadblock] Signed payload has an unexpected shape; refusing.'
      );

      return null;
    }

    const age = Date.now() - issuedAt;

    if (age > MAX_RULES_AGE_MS) {
      console.error(
        `[Dadblock] Signed rules are ` +
        `${Math.round(age / 3600000)}h old; ` +
        'refusing stale payload.'
      );

      return null;
    }

    if (age < -60000) {
      console.error(
        '[Dadblock] Signed rules have a future timestamp; refusing.'
      );

      return null;
    }

    return {
      rules,
      issuedAt,
    };
  } catch (error) {
    console.error(
      '[Dadblock] Cryptography error during verification:',
      error && error.name
    );

    return null;
  }
}

// ============================================================
// DETECTION CACHE
// ============================================================

async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(
    typeof text === 'string' ? text : ''
  );

  const digest = await crypto.subtle.digest(
    'SHA-256',
    bytes
  );

  return Array.from(
    new Uint8Array(digest),
    byte => byte.toString(16).padStart(2, '0')
  ).join('');
}

// Hash both the whole URL and the whole supplied page text.
// Never place raw page text or URL query parameters in key names.
//
// Keep the tab prefix for existing cache cleanup behavior.
async function getCacheKey(
  url,
  content,
  tabId,
  mode = activeMode
) {
  const [urlHash, contentHash] = await Promise.all([
    sha256Hex(url),
    sha256Hex(content),
  ]);

  return (
    `tab${tabId}:audit-v4:${AUDIT_POLICY_REVISION}:` +
    `${urlHash}:${contentHash}:${mode}`
  );
}

// ============================================================
// AI INITIALIZATION AND MODE SWITCHING
// ============================================================

async function initializeAI(modeOverride = null) {
  try {
    const stored =
      modeOverride === 'local' || modeOverride === 'cloud'
        ? { selectedMode: modeOverride }
        : await chrome.storage.local.get([
            'selectedMode',
            'activeMode',
          ]);

    let savedMode =
      stored.selectedMode || stored.activeMode;

    if (savedMode === 'compatibility') {
      savedMode = 'cloud';

      await chrome.storage.local.set({
        selectedMode: 'cloud',
        activeMode: 'cloud',
      });
    }

    activeMode =
      savedMode === 'local' ? 'local' : 'cloud';

    console.log(
      `[Dadblock] Initializing AI in ${activeMode} mode...`
    );

    if (activeMode === 'cloud') {
      currentSessions = await initializeCloudMode();

      isAiAvailable =
        currentSessions.availability === 'readily';
    } else {
      await setupOffscreenDocument();

      currentSessions = await initializeLocalMode();

      isAiAvailable =
        !!currentSessions.analyzerSession &&
        !!currentSessions.judgeSession;
    }

    aiAvailabilityStatus =
      currentSessions.availability || 'error';

    if (isAiAvailable) {
      console.log(
        `[Dadblock] ${activeMode} mode initialized successfully and ready`
      );
    } else if (
      aiAvailabilityStatus === 'configure-required'
    ) {
      console.warn(
        '[Dadblock] Cloud mode requires configuration'
      );
    } else {
      console.warn(
        `[Dadblock] Failed to initialize ${activeMode} mode`
      );
    }
  } catch (error) {
    console.error(
      '[Dadblock] Failed to initialize AI:',
      error && error.name
    );

    isAiAvailable = false;
    aiAvailabilityStatus = 'error';
  }
}

// Engine identity describes the completed scan, independently of the
// mode currently selected in Settings.
function requestedModeForResult(result) {
  if (
    result?.requestedMode === 'local' ||
    result?.requestedMode === 'cloud'
  ) {
    return result.requestedMode;
  }

  if (
    result?.mode === 'local' &&
    [
      'ERROR',
      'RATE_LIMITED',
      'QUOTA_EXCEEDED',
    ].includes(result.fallbackFrom)
  ) {
    return 'cloud';
  }

  return result?.mode === 'local' ||
    result?.mode === 'cloud'
    ? result.mode
    : null;
}

function resultMatchesAudit(result, mode) {
  return (
    result?.auditRevision === AUDIT_POLICY_REVISION &&
    requestedModeForResult(result) === mode
  );
}

// Invalidate completed results as well as active model jobs.
// Mode selection itself does not request another automatic scan.
function invalidateModeState() {
  const tabIds = new Set([
    ...TAB_DOCUMENTS.keys(),
    ...ACTIVE_ANALYSES.keys(),
  ]);

  for (const tabId of tabIds) {
    cancelAnalysisForTab(tabId);
    MANUAL_SCAN_TABS.delete(tabId);

    const state = TAB_DOCUMENTS.get(tabId);

    if (state) {
      state.hasAnalysis = false;
      state.finished = true;
      state.readinessAttempts = 0;
      state.notifying = null;
    }

    updateBadge(tabId, null, {
      judgment: 'UNVERIFIED',
    });
  }

  DETECTION_CACHE.clear();
}

// Inspect only Dadblock result/cache keys. Re-read them inside the
// tab's storage queue so a delayed removal cannot erase a fresh scan.
async function clearStoredModeResults(mode, invalidatedAt) {
  const all = await chrome.storage.local.get(null);
  const keysByTab = new Map();

  for (const key of Object.keys(all)) {
    const match =
      key.match(/^detection_(\d+)$/) ||
      key.match(/^tab(\d+):/);

    if (!match) {
      continue;
    }

    const tabId = Number(match[1]);

    if (!Number.isSafeInteger(tabId)) {
      continue;
    }

    if (!keysByTab.has(tabId)) {
      keysByTab.set(tabId, []);
    }

    keysByTab.get(tabId).push(key);
  }

  await Promise.all(
    Array.from(keysByTab, ([tabId, keys]) =>
      queueTabStorage(tabId, async () => {
        const current = await chrome.storage.local.get(keys);
        const remove = keys.filter(key => {
          const entry = current[key];

          if (!entry) {
            return false;
          }

          return (
            !resultMatchesAudit(entry.result, mode) ||
            !Number.isFinite(entry.timestamp) ||
            entry.timestamp <= invalidatedAt
          );
        });

        if (remove.length) {
          await chrome.storage.local.remove(remove);
        }
      })
    )
  );
}

// Serialize mode transitions with any existing initialization.
// Publish the initialization barrier before awaiting storage or
// offscreen work, so new scans cannot use the previous sessions.
function switchMode(newMode) {
  if (newMode !== 'local' && newMode !== 'cloud') {
    return Promise.reject(
      new Error(`Unknown mode: ${newMode}`)
    );
  }

  if (modeSwitchInFlight?.mode === newMode) {
    return modeSwitchInFlight.promise;
  }

  console.log(
    `[Dadblock] Switching to ${newMode} mode...`
  );

  const previousInitialization = aiInitPromise;
  const invalidatedAt = Date.now();

  invalidateModeState();
  isAiAvailable = false;
  aiAvailabilityStatus = 'initializing';

  const transition = (async () => {
    if (previousInitialization) {
      try {
        await previousInitialization;
      } catch {
        // A failed previous initialization must not prevent recovery.
      }
    }

    currentSessions = null;
    activeMode = newMode;
    isAiAvailable = false;
    aiAvailabilityStatus = 'initializing';

    await chrome.storage.local.set({
      selectedMode: newMode,
      activeMode: newMode,
    });

    try {
      await clearStoredModeResults(newMode, invalidatedAt);
    } catch (error) {
      // Status/cache reads also reject stale mode/revision results.
      console.warn(
        '[Dadblock] Could not clear old mode results:',
        error && error.name
      );
    }

    if (newMode === 'cloud') {
      await closeOffscreenDocument();
    }

    await initializeAI(newMode);

    return true;
  })();

  const pending = {
    mode: newMode,
    promise: transition,
  };

  modeSwitchInFlight = pending;
  aiInitPromise = transition;

  transition.finally(() => {
    if (modeSwitchInFlight === pending) {
      modeSwitchInFlight = null;
    }
  }).catch(() => {});

  return transition;
}

// ============================================================
// AI ANALYSIS
// ============================================================

// Automatic scans never call a detector while auto-scan is off.
// Local mode never sends page content to a network detector.
async function analyzeContent(
  content,
  url = 'unknown',
  stage = 'stage1',
  abortSignal = null,
  options = {}
) {
  const trigger =
    options && options.trigger === 'manual'
      ? 'manual'
      : 'auto';

  const contentLength =
    typeof content === 'string'
      ? content.length
      : 0;

  const make = (
    judgment,
    analysis,
    extra = {}
  ) => normalizeResult({
    judgment,
    analysis,
    method: 'error',
    mode: activeMode,
    contentLength,
    ...extra,
  });

  if (
    typeof content !== 'string' ||
    !content.trim()
  ) {
    return make(
      'SKIPPED',
      'No readable content to scan.',
      {
        method: 'skipped',
        code: 'NO_CONTENT',
      }
    );
  }

  if (abortSignal?.aborted) {
    return make(
      'ERROR',
      'This scan was cancelled.',
      {
        code: 'ABORTED',
      }
    );
  }

  const settings = await getSettings();

  if (!settings.ok) {
    return make(
      'ERROR',
      "Dadblock couldn't read its settings, so this page was NOT checked.",
      {
        code: 'SETTINGS_UNAVAILABLE',
      }
    );
  }

  if (
    trigger === 'auto' &&
    !settings.enableAutoScan
  ) {
    return make(
      'SKIPPED',
      'Auto-scan is turned off. Use "Scan now" to check this page.',
      {
        method: 'skipped',
        code: 'AUTO_SCAN_DISABLED',
      }
    );
  }

  // A cold start may still be creating the on-device sessions.
  // Await that initialization rather than reporting unavailable
  // while initialization is still in flight.
  if (aiInitPromise) {
    try {
      await aiInitPromise;
    } catch {
      // initializeAI records its own availability failure.
    }
  }

  // A scan cancelled during initialization must not switch the browser
  // back to the mode that was selected when that old scan started.
  if (abortSignal?.aborted) {
    return make(
      'ERROR',
      'This scan was cancelled.',
      { code: 'ABORTED' }
    );
  }

  const initializedSettings = await getSettings();

  if (
    !initializedSettings.ok ||
    initializedSettings.selectedMode !== settings.selectedMode
  ) {
    return make(
      'ERROR',
      'The scanning settings changed. Scan this page again.',
      {
        code: initializedSettings.ok
          ? 'MODE_CHANGED'
          : 'SETTINGS_UNAVAILABLE',
      }
    );
  }

  if (settings.selectedMode !== activeMode) {
    try {
      await switchMode(settings.selectedMode);
    } catch (error) {
      console.error(
        '[Dadblock] Mode switch failed:',
        error && error.name
      );
    }
  }

  // A previously downloading model may now be usable.
  if (
    activeMode === 'local' &&
    !isAiAvailable &&
    Date.now() - lastLocalRetryAt >
      LOCAL_RETRY_INTERVAL_MS
  ) {
    lastLocalRetryAt = Date.now();
    aiInitPromise = initializeAI();

    try {
      await aiInitPromise;
    } catch {
      // initializeAI records its own failure.
    }
  }

  // Settings or cancellation may have changed while session
  // creation was awaited.
  const latestSettings = await getSettings();

  if (abortSignal?.aborted) {
    return make(
      'ERROR',
      'This scan was cancelled.',
      {
        code: 'ABORTED',
      }
    );
  }

  if (!latestSettings.ok) {
    return make(
      'ERROR',
      "Dadblock couldn't read its settings, so this page was NOT checked.",
      {
        code: 'SETTINGS_UNAVAILABLE',
      }
    );
  }

  if (
    trigger === 'auto' &&
    !latestSettings.enableAutoScan
  ) {
    return make(
      'SKIPPED',
      'Automatic scanning is paused.',
      {
        method: 'skipped',
        code: 'AUTO_SCAN_DISABLED',
      }
    );
  }

  if (
    latestSettings.selectedMode !==
      settings.selectedMode ||
    activeMode !== settings.selectedMode
  ) {
    return make(
      'ERROR',
      'The scanning mode changed. Scan this page again.',
      {
        code: 'MODE_CHANGED',
      }
    );
  }

  try {
    console.log(
      `[Dadblock] Running analysis in ${activeMode} mode ` +
      `(stage: ${stage}, trigger: ${trigger})`
    );

    if (activeMode === 'cloud') {
      if (
        aiAvailabilityStatus === 'configure-required'
      ) {
        return make(
          'CONFIGURATION_ERROR',
          'Cloud Mode requires configuration. Please set API URL in extension settings.',
          {
            mode: 'cloud',
          }
        );
      }

      if (!isAiAvailable) {
        console.error(
          '[Dadblock] Cloud mode not available; cannot analyze'
        );

        return make(
          'ERROR',
          'AI detection unavailable, so this page was NOT checked. Please check settings.',
          {
            code: 'AI_UNAVAILABLE',
          }
        );
      }

      const cloudResult = normalizeResult(
        await analyzeCloud(
          currentSessions,
          content,
          url,
          stage,
          abortSignal,
          { trigger }
        )
      );

      // On-device fallback is allowed only when the cloud engine
      // explicitly marks a quota/outage failure as eligible.
      if (
        cloudResult.fallbackEligible === true &&
        !(abortSignal && abortSignal.aborted)
      ) {
        const fallback = await tryLocalFallback(
          content,
          url,
          abortSignal,
          cloudResult
        );

        if (fallback) {
          return fallback;
        }
      }

      return cloudResult;
    }

    if (
      !isAiAvailable ||
      !currentSessions ||
      !currentSessions.analyzerSession ||
      !currentSessions.judgeSession
    ) {
      console.warn(
        '[Dadblock] Local AI unavailable; returning an unverified result'
      );

      return normalizeResult({
        ...buildLocalUnavailableResult(
          aiAvailabilityStatus,
          contentLength
        ),
        judgment: 'AI_UNAVAILABLE',
        mode: 'local',
      });
    }

    lastLocalUseAt = Date.now();

    return normalizeResult(
      await analyzeLocal(
        currentSessions.analyzerSession,
        currentSessions.judgeSession,
        content,
        url,
        {
          signal: abortSignal || undefined,
        }
      )
    );
  } catch (error) {
    console.error(
      '[Dadblock] Analysis error:',
      error && error.name
    );

    // Do not forward internal exception messages to the UI.
    return make(
      'ERROR',
      'The scan failed, so this page was NOT checked.',
      {
        code: 'ANALYSIS_EXCEPTION',
      }
    );
  }
}

// Cloud quota/outage -> on-device fallback.
// Keep the original cloud result if local inference cannot
// produce a conclusive result.
async function tryLocalFallback(
  content,
  url,
  abortSignal,
  cloudResult
) {
  try {
    if (!(await setupOffscreenDocument())) {
      return null;
    }

    if (
      (await getLocalAvailability()) !== 'readily'
    ) {
      return null;
    }

    if (abortSignal?.aborted) {
      return null;
    }

    const localSessions = await initializeLocalMode();

    if (
      !localSessions.analyzerSession ||
      !localSessions.judgeSession
    ) {
      return null;
    }

    if (abortSignal?.aborted) {
      return null;
    }

    console.log(
      '[Dadblock Fallback] Cloud limit or error hit. Falling back to Local AI...'
    );

    lastLocalUseAt = Date.now();

    const localResult = normalizeResult(
      await analyzeLocal(
        localSessions.analyzerSession,
        localSessions.judgeSession,
        content,
        url,
        {
          signal: abortSignal || undefined,
        }
      )
    );

    if (localResult.conclusive) {
      console.log(
        '[Dadblock Fallback] Local AI successfully analyzed page!'
      );

      return {
        ...localResult,
        requestedMode: 'cloud',
        engineMode: 'local',
        fallbackFrom: cloudResult.judgment,
      };
    }
  } catch (fallbackError) {
    console.error(
      '[Dadblock Fallback] Local AI fallback failed:',
      fallbackError && fallbackError.name
    );
  }

  return null;
}

// ============================================================
// IGNORE RULES
// ============================================================

async function shouldIgnoreUrl(url) {
  try {
    if (
      url.includes('chrome-extension://') &&
      (
        url.includes('/settings.html') ||
        url.includes('/popup.html')
      )
    ) {
      console.log(
        '[Dadblock] Ignoring extension internal page'
      );

      return true;
    }

    const { ignoreRules = [] } =
      await chrome.storage.local.get([
        'ignoreRules',
      ]);

    for (const rule of ignoreRules) {
      if (
        rule.expiry &&
        Date.now() > rule.expiry
      ) {
        continue;
      }

      if (
        rule.type === 'url' &&
        url === rule.pattern
      ) {
        console.log(
          '[Dadblock] Ignoring an exact URL match.'
        );

        return true;
      }

      if (
        rule.type === 'url_prefix' &&
        url.startsWith(rule.pattern)
      ) {
        console.log(
          '[Dadblock] Ignoring a URL prefix match.'
        );

        return true;
      }

      if (
        rule.type === 'url_temporary' &&
        url.startsWith(rule.pattern)
      ) {
        console.log(
          '[Dadblock] Ignoring a temporary URL match.'
        );

        return true;
      }

      if (
        rule.type === 'domain' ||
        rule.type === 'domain_temporary'
      ) {
        const parsedUrl = new URL(url);

        if (parsedUrl.hostname === rule.pattern) {
          console.log(
            '[Dadblock] Ignoring domain:',
            rule.pattern
          );

          return true;
        }
      }
    }

    return false;
  } catch (error) {
    console.error(
      '[Dadblock] Error checking ignore rules:',
      error && error.name
    );

    return false;
  }
}

// ============================================================
// EXTENSION MESSAGES
// ============================================================

chrome.runtime.onMessage.addListener(
  (request, sender, sendResponse) => {
    if (
      !request ||
      typeof request !== 'object' ||
      !sender ||
      sender.id !== chrome.runtime.id
    ) {
      console.warn(
        '[Dadblock Security] Rejected an unauthorized or malformed message.'
      );

      return false;
    }

    if (request.type === 'CONTENT_SCRIPT_READY') {
      const tabId = sender.tab?.id;

      if (
        Number.isInteger(tabId) &&
        sender.frameId === 0
      ) {
        sendResponse({
          status: 'acknowledged',
        });
      } else {
        sendResponse({
          status: 'ignored',
        });
      }

      return false;
    }

    if (request.action === 'setMode') {
      if (
        request.mode !== 'local' &&
        request.mode !== 'cloud'
      ) {
        sendResponse({
          success: false,
          error: 'Unknown mode',
          mode: activeMode,
        });

        return false;
      }

      switchMode(request.mode)
        .then(() => sendResponse({
          success: true,
          mode: activeMode,
        }))
        .catch(() => sendResponse({
          success: false,
          mode: activeMode,
        }));

      return true;
    }

    if (request.action === 'getMode') {
      sendResponse({
        mode: activeMode,
      });

      return false;
    }

    if (request.action === 'manualScan') {
      const manualTabId =
        Number.isInteger(request.tabId)
          ? request.tabId
          : sender.tab && sender.tab.id;

      if (!Number.isInteger(manualTabId)) {
        sendResponse({
          success: false,
          error: 'No tab',
        });

        return false;
      }

      requestManualAnalysis(manualTabId)
        .then(success => sendResponse({
          success,
        }))
        .catch(() => sendResponse({
          success: false,
          error: 'Content script not reachable',
        }));

      return true;
    }

    if (request.action === 'analyzeContent') {
      return handleAnalyzeContentMessage(
        request,
        sender,
        sendResponse
      );
    }

    if (request.action === 'getStatus') {
      const statusTabId =
        Number.isInteger(request.tabId)
          ? request.tabId
          : sender.tab && sender.tab.id;

      const unverified = () => ({
        result: normalizeResult({
          judgment: 'UNVERIFIED',
          analysis: 'No scan performed yet',
        }),
      });

      if (!Number.isInteger(statusTabId)) {
        sendResponse(unverified());

        return false;
      }

      getCurrentDetection(statusTabId)
        .then(detection => sendResponse(
          detection
            ? {
                ...detection,
                result: normalizeResult(
                  detection.result
                ),
              }
            : unverified()
        ))
        .catch(() => sendResponse(unverified()));

      return true;
    }

    if (
      request.action === 'checkAiAvailability'
    ) {
      sendResponse({
        available: isAiAvailable,
        status: aiAvailabilityStatus,
        mode: activeMode,
      });

      return false;
    }

    if (request.action === 'clearTabCache') {
      const tabId = request.tabId;

      if (!Number.isInteger(tabId)) {
        sendResponse({
          success: false,
          error: 'No tab',
        });

        return false;
      }

      clearTabCacheAndScan(tabId)
        .then(success => sendResponse({
          success,
        }))
        .catch(() => sendResponse({
          success: false,
        }));

      return true;
    }

    return false;
  }
);

async function requestManualAnalysis(tabId) {
  const live = await readActiveDocument(tabId);

  if (
    !live ||
    !isSupportedScanURL(live.url)
  ) {
    return false;
  }

  const state = adoptTabDocument(
    tabId,
    live.documentId,
    live.url
  );

  cancelAnalysisForTab(tabId);

  const epoch =
    TAB_SCAN_EPOCHS.get(tabId) || 0;

  markManualScan(tabId);

  await queueTabStorage(tabId, async () => {
    if (TAB_DOCUMENTS.get(tabId) === state) {
      await chrome.storage.local.remove([
        `detection_${tabId}`,
      ]);
    }
  });

  if (!isRouteCurrent(tabId, state, epoch)) {
    return false;
  }

  startScanningAnimation(tabId);

  try {
    const reply = await chrome.tabs.sendMessage(
      tabId,
      {
        action: 'requestAnalysis',
        trigger: 'manual',
        pageUrl: live.url,
      },
      {
        documentId: live.documentId,
      }
    );

    if (!isRouteCurrent(tabId, state, epoch)) {
      return false;
    }

    if (reply?.acknowledged === true) {
      return true;
    }

    throw new Error(
      'Content script did not acknowledge'
    );
  } catch {
    if (isRouteCurrent(tabId, state, epoch)) {
      MANUAL_SCAN_TABS.delete(tabId);
      stopScanningAnimation(tabId);

      updateBadge(tabId, null, {
        judgment: 'SKIPPED',
        method: 'skipped',
      });
    }

    return false;
  }
}

async function clearTabCacheAndScan(tabId) {
  cancelAnalysisForTab(tabId);
  MANUAL_SCAN_TABS.delete(tabId);

  for (const key of Array.from(DETECTION_CACHE.keys())) {
    if (key.startsWith(`tab${tabId}:`)) {
      DETECTION_CACHE.delete(key);
    }
  }

  await queueTabStorage(tabId, async () => {
    const items = await chrome.storage.local.get(null);

    const keys = Object.keys(items).filter(key =>
      key === `detection_${tabId}` ||
      key.startsWith(`tab${tabId}:`)
    );

    if (keys.length) {
      await chrome.storage.local.remove(keys);
    }
  });

  // popup.js sends manualScan after this response.
  return true;
}

async function getCurrentDetection(tabId) {
  const live = await readActiveDocument(tabId);

  if (!live) {
    return null;
  }

  const data = await chrome.storage.local.get([
    `detection_${tabId}`,
  ]);

  const detection = data[`detection_${tabId}`];

  if (
    !detection ||
    detection.url !== live.url ||
    detection.documentId !== live.documentId
  ) {
    return null;
  }

  const current = await readActiveDocument(tabId);
  const settings = await getSettings();

  return (
    settings.ok &&
    resultMatchesAudit(detection.result, settings.selectedMode) &&
    current?.documentId === live.documentId &&
    current.url === live.url
  )
    ? detection
    : null;
}

// ============================================================
// SERIALIZED POPUP STATE AND RESULT PUBLICATION
// ============================================================

// Serialize writes/removals for a tab. A delayed old write must
// not land after the new document's result or reset.
function queueTabStorage(tabId, task) {
  const previous =
    TAB_STORAGE_QUEUES.get(tabId) ||
    Promise.resolve();

  const run = previous
    .catch(() => {})
    .then(task);

  TAB_STORAGE_QUEUES.set(tabId, run);

  run.finally(() => {
    if (TAB_STORAGE_QUEUES.get(tabId) === run) {
      TAB_STORAGE_QUEUES.delete(tabId);
    }
  }).catch(() => {});

  return run;
}

function isRouteCurrent(tabId, state, epoch) {
  return (
    TAB_DOCUMENTS.get(tabId) === state &&
    (TAB_SCAN_EPOCHS.get(tabId) || 0) === epoch
  );
}

async function publishResult(
  tabId,
  tabUrl,
  rawResult,
  ownership = {}
) {
  const normalized = normalizeResult(rawResult);
  const result = normalized.conclusive
    ? normalized
    : {
        ...normalized,
        auditRevision: AUDIT_POLICY_REVISION,
        requestedMode:
          requestedModeForResult(normalized) || activeMode,
        engineMode:
          normalized.mode === 'local' || normalized.mode === 'cloud'
            ? normalized.mode
            : activeMode,
      };

  const state =
    ownership.state ||
    TAB_DOCUMENTS.get(tabId);

  const epoch =
    ownership.epoch ??
    (TAB_SCAN_EPOCHS.get(tabId) || 0);

  const owns = () => (
    !!state &&
    state.url === tabUrl &&
    isRouteCurrent(tabId, state, epoch)
  );

  if (!owns()) {
    return null;
  }

  let published = false;
  let publishedResult = result;

  await queueTabStorage(tabId, async () => {
    if (!owns()) {
      return;
    }

    if (state.documentId) {
      const live = await readActiveDocument(
        tabId
      );

      if (
        !owns() ||
        live?.documentId !== state.documentId ||
        live.url !== tabUrl
      ) {
        return;
      }
    }

    // A later rescan of the same page that could not reach a verdict
    // must not erase an earlier verified SAFE result.
    let toStore = result;

    try {
      const priorKey = `detection_${tabId}`;
      const prior = (await chrome.storage.local.get(priorKey))[priorKey];

      if (
        prior &&
        prior.url === tabUrl &&
        prior.documentId === state.documentId &&
        prior.result &&
        prior.result.judgment === 'SAFE' &&
        result.judgment === 'INCONCLUSIVE'
      ) {
        toStore = normalizeResult(prior.result);
      }
    } catch {
      toStore = result;
    }

    // Store the complete normalized detector result.
    // Do not rebuild it with a field whitelist.
    await chrome.storage.local.set({
      [`detection_${tabId}`]: {
        result: toStore,
        url: tabUrl,
        documentId: state.documentId,
        timestamp: Date.now(),
      },
    });

    if (!owns()) {
      return;
    }

    published = true;

    if (
      result.code !== 'CONTENT_NOT_RECEIVED'
    ) {
      state.finished = true;
    }

    stopScanningAnimation(tabId);
    updateBadge(tabId, null, toStore);
    publishedResult = toStore;
  });

  return published ? publishedResult : null;
}

// ============================================================
// CONTENT ANALYSIS MESSAGE HANDLING
// ============================================================

function handleAnalyzeContentMessage(
  request,
  sender,
  sendResponse
) {
  if (
    !sender ||
    sender.id !== chrome.runtime.id ||
    !Number.isInteger(sender.tab?.id) ||
    (
      Number.isInteger(sender.frameId) &&
      sender.frameId !== 0
    )
  ) {
    sendResponse(undefined);

    return false;
  }

  const tabId = sender.tab.id;

  let responded = false;

  const respond = payload => {
    if (responded) {
      return;
    }

    responded = true;

    try {
      sendResponse(payload);
    } catch {
      // The originating document may have closed.
    }
  };

  processAnalyzeContent(
    request,
    sender,
    tabId,
    respond
  ).catch(error => {
    console.warn(
      '[Dadblock] Analysis handler failed:',
      error?.name || 'Error'
    );

    // Do not overwrite a newer document's state when an
    // unexpected handler failure has no verified ownership.
    respond(normalizeResult({
      judgment: 'ERROR',
      analysis:
        'The scan failed, so this page was NOT checked.',
      method: 'error',
      code: 'HANDLER_FAILED',
      mode: activeMode,
    }));
  });

  return true;
}

async function processAnalyzeContent(
  request,
  sender,
  tabId,
  respond
) {
  const url =
    typeof request.pageUrl === 'string'
      ? request.pageUrl
      : sender.url ||
        sender.tab.url ||
        'unknown';

  // MessageSender.url may describe the document's initial URL
  // after pushState. Use browser-owned document identity and
  // the current main-frame URL instead.
  const documentId = sender.documentId;

  if (
    typeof documentId !== 'string' ||
    (
      sender.documentLifecycle &&
      sender.documentLifecycle !== 'active'
    )
  ) {
    respond(undefined);

    return;
  }

  const liveDocument =
    await readActiveDocument(tabId);

  if (
    !liveDocument ||
    liveDocument.documentId !== documentId ||
    liveDocument.url !== url
  ) {
    respond(undefined);

    return;
  }

  const documentState = adoptTabDocument(
    tabId,
    documentId,
    url
  );

  const content =
    typeof request.content === 'string'
      ? request.content
      : '';

  const manual =
    !request.skipped &&
    (
      consumeManualScan(tabId) ||
      request.trigger === 'manual' ||
      request.manual === true
    );

  const epoch =
    TAB_SCAN_EPOCHS.get(tabId) || 0;

  let tracker = null;

  const isCurrent = () => (
    isRouteCurrent(
      tabId,
      documentState,
      epoch
    ) &&
    (
      !tracker ||
      (
        ACTIVE_ANALYSES.get(tabId) === tracker &&
        !tracker.cancelled
      )
    )
  );

  async function getLiveTab(
    verifyDocument = false
  ) {
    if (!isCurrent()) {
      return null;
    }

    try {
      const live = await readActiveDocument(
        tabId
      );

      if (
        !isCurrent() ||
        live?.documentId !== documentId ||
        live.url !== url
      ) {
        return null;
      }

      const tab = {
        ...live.tab,
        url: live.url,
      };

      if (verifyDocument) {
        const reply = await chrome.tabs.sendMessage(
          tabId,
          {
            action: 'ping',
            pageUrl: url,
          },
          {
            documentId,
          }
        );

        if (
          !reply?.alive ||
          reply.pageUrl !== url ||
          !isCurrent()
        ) {
          return null;
        }
      }

      return tab;
    } catch {
      return null;
    }
  }

  const settings = await getSettings();

  if (!(await getLiveTab())) {
    respond(undefined);

    return;
  }

  const respondResult = result => {
    respond({
      ...result,
      bannerEnabled: settings.bannerEnabled,
    });
  };

  if (request.skipped) {
    const pending = ACTIVE_ANALYSES.get(tabId);

    // A skip notification must not cancel another real scan.
    if (
      pending?.abortController &&
      !pending.cancelled
    ) {
      respond(undefined);

      return;
    }

    const data = await chrome.storage.local.get([
      `detection_${tabId}`,
    ]);

    if (
      !isCurrent() ||
      ACTIVE_ANALYSES.get(tabId) !== pending
    ) {
      respond(undefined);

      return;
    }

    if (pending) {
      clearTimeout(pending.timeout);
      clearTimeout(pending.contentTimeout);
      clearTimeout(pending.requestTimeout);

      ACTIVE_ANALYSES.delete(tabId);
    }

    stopScanningAnimation(tabId);

    const existing =
      data[`detection_${tabId}`];

    // Preserve a completed result from this exact document
    // and route, including a completed INCONCLUSIVE.
    if (
      existing?.url === url &&
      existing.documentId === documentId &&
      existing.result &&
      resultMatchesAudit(existing.result, settings.selectedMode) &&
      existing.result.judgment !== 'SKIPPED'
    ) {
      const preserved = normalizeResult(
        existing.result
      );

      updateBadge(tabId, null, preserved);
      respondResult(preserved);

      return;
    }

    const messages = {
      content_unchanged:
        'The supplied content has not changed since the previous scan.',
      max_scans_reached:
        'This page reached its automatic scan limit. Use Scan now to retry.',
      insufficient_content:
        'Not enough readable content to scan, so this page was NOT checked.',
      email_interface:
        'Open an individual message to scan its content.',
      sensitive_context:
        'This payment context is excluded from page extraction.',
      unsupported_page:
        'This page is outside the supported scanning scope.',
      search_results:
        'Search results are not scanned. Open a result and Dad will check that page.',
      workspace_app:
        'Dad does not read your private documents, boards or designs, so this page is not scanned.',
    };

    const skippedResult = await publishResult(
      tabId,
      url,
      {
        judgment: 'SKIPPED',
        analysis:
          messages[request.reason] ||
          'Page scanning was skipped.',
        method: 'skipped',
        mode: settings.selectedMode,
        reason: request.reason,
        contentLength: 0,
      },
      {
        state: documentState,
        epoch,
      }
    );

    respondResult(
      skippedResult ||
      normalizeResult({
        judgment: 'UNVERIFIED',
      })
    );

    return;
  }

  if (!settings.ok) {
    respondResult(normalizeResult({
      judgment: 'ERROR',
      analysis:
        'Dadblock could not read its settings.',
      method: 'error',
      code: 'SETTINGS_UNAVAILABLE',
    }));

    return;
  }

  const ignored = await shouldIgnoreUrl(url);

  if (!(await getLiveTab())) {
    respond(undefined);

    return;
  }

  // Identical automatic requests share work.
  // Changed automatic input waits for current inference instead
  // of repeatedly aborting and restarting the local model.
  //
  // Manual scans, genuine navigation, and mode changes may
  // supersede previous work.
  for (;;) {
    const previous =
      ACTIVE_ANALYSES.get(tabId);

    const sameDocument =
      previous &&
      previous.url === url &&
      previous.epoch === epoch &&
      previous.documentId === documentId &&
      previous.mode === settings.selectedMode;

    if (
      !manual &&
      !ignored &&
      sameDocument &&
      previous.completion &&
      !previous.cancelled
    ) {
      const sameInput =
        previous.requestContent === content;

      const shared =
        await previous.completion;

      if (!(await getLiveTab())) {
        respond(undefined);

        return;
      }

      if (sameInput && shared) {
        respondResult(shared);

        return;
      }

      continue;
    }

    if (previous) {
      previous.cancelled = true;

      clearTimeout(previous.timeout);
      clearTimeout(previous.contentTimeout);
      clearTimeout(previous.requestTimeout);

      previous.abortController?.abort();
    }

    break;
  }

  let settleCompletion;

  const completion = new Promise(resolve => {
    settleCompletion = resolve;
  });

  tracker = {
    url,
    epoch,
    documentId,
    mode: settings.selectedMode,
    manual,
    requestContent: content,
    completion,
    cancelled: false,
    timedOut: false,
    timeout: null,
    contentTimeout: null,
    startTime: Date.now(),
    abortController: new AbortController(),
  };

  ACTIVE_ANALYSES.set(tabId, tracker);
  documentState.hasAnalysis = true;

  let completedResult = null;
  let cacheKey = null;

  async function finish(
    rawResult,
    cacheResult = false
  ) {
    const tab = await getLiveTab(true);
    const freshSettings = await getSettings();

    if (
      !tab ||
      !isCurrent() ||
      !freshSettings.ok ||
      freshSettings.selectedMode !== tracker.mode
    ) {
      respond(undefined);

      return;
    }

    let finalResult = normalizeResult(
      rawResult
    );

    if (
      !manual &&
      !freshSettings.enableAutoScan
    ) {
      cacheResult = false;

      finalResult = normalizeResult({
        judgment: 'SKIPPED',
        analysis:
          'Auto-scan is turned off. Use Scan now to check this page.',
        method: 'skipped',
        code: 'AUTO_SCAN_DISABLED',
        mode: tracker.mode,
        contentLength: content.length,
      });
    }

    // Never stamp an older detector verdict as a current-policy audit.
    if (
      finalResult.conclusive &&
      finalResult.auditRevision !== AUDIT_POLICY_REVISION
    ) {
      cacheResult = false;

      finalResult = normalizeResult({
        judgment: 'INCONCLUSIVE',
        analysis:
          'This result used an older audit policy. Use Scan now after updating the extension.',
        method: 'unverified',
        code: 'OUTDATED_AUDIT',
        schemaVersion: 2,
        mode: finalResult.mode || tracker.mode,
        conclusive: false,
        contentLength: content.length,
      });
    }

    const engineMode =
      finalResult.mode === 'local' || finalResult.mode === 'cloud'
        ? finalResult.mode
        : tracker.mode;

    finalResult = {
      ...finalResult,
      auditRevision: AUDIT_POLICY_REVISION,
      requestedMode: tracker.mode,
      engineMode,
    };

    if (
      cacheResult &&
      cacheKey &&
      finalResult.schemaVersion === 2 &&
      finalResult.conclusive
    ) {
      DETECTION_CACHE.set(
        cacheKey,
        finalResult
      );

      chrome.storage.local.set({
        [cacheKey]: {
          result: finalResult,
          timestamp: Date.now(),
        },
      }).catch(() => {});
    }

    completedResult = await publishResult(
      tabId,
      tab.url,
      finalResult,
      {
        state: documentState,
        epoch,
      }
    );

    if (
      !completedResult ||
      !isCurrent()
    ) {
      respond(undefined);

      return;
    }

    respond({
      ...completedResult,
      bannerEnabled:
        freshSettings.bannerEnabled,
    });
  }

  try {
    if (ignored) {
      await finish({
        judgment: 'IGNORED',
        analysis:
          'This page is ignored and will not be scanned.',
        method: 'ignored',
        mode: tracker.mode,
        contentLength: content.length,
      });

      return;
    }

    if (
      !manual &&
      !settings.enableAutoScan
    ) {
      await finish({
        judgment: 'SKIPPED',
        analysis:
          'Auto-scan is turned off. Use Scan now to check this page.',
        method: 'skipped',
        code: 'AUTO_SCAN_DISABLED',
        mode: tracker.mode,
        contentLength: content.length,
      });

      return;
    }

    startScanningAnimation(tabId);

    tracker.timeout = setTimeout(() => {
      if (!isCurrent()) {
        return;
      }

      tracker.timedOut = true;
      tracker.abortController.abort();
    }, 60000);

    cacheKey = await getCacheKey(
      url,
      content,
      tabId,
      tracker.mode
    );

    if (!isCurrent()) {
      respond(undefined);

      return;
    }

    // Manual scans always run fresh inference.
    if (!manual) {
      let cached = DETECTION_CACHE.get(
        cacheKey
      );

      if (!cached) {
        const stored =
          await chrome.storage.local.get([
            cacheKey,
          ]);

        const entry = stored[cacheKey];

        const age =
          Date.now() -
          Number(entry?.timestamp);

        if (
          entry?.result &&
          Number.isFinite(age) &&
          age >= 0 &&
          age < 86400000
        ) {
          cached = entry.result;
        }
      }

      if (!isCurrent()) {
        respond(undefined);

        return;
      }

      if (
        !tracker.timedOut &&
        cached?.schemaVersion === 2 &&
        resultMatchesAudit(cached, tracker.mode) &&
        normalizeResult(cached).conclusive
      ) {
        await finish({
          ...cached,
          cacheHit: true,
        });

        return;
      }
    }

    let result;

    if (!tracker.timedOut) {
      result = await analyzeContent(
        content,
        url,
        'full',
        tracker.abortController.signal,
        {
          trigger:
            manual ? 'manual' : 'auto',
        }
      );
    }

    if (!isCurrent()) {
      respond(undefined);

      return;
    }

    if (tracker.timedOut) {
      await finish({
        judgment: 'ERROR',
        analysis:
          'The scan took too long, so this page was NOT checked.',
        method: 'timeout',
        code: 'ANALYSIS_TIMEOUT',
        mode: tracker.mode,
        contentLength: content.length,
      });

      return;
    }

    await finish(result, true);
  } catch (error) {
    if (isCurrent()) {
      await finish({
        judgment: 'ERROR',
        analysis:
          'The scan failed, so this page was NOT checked.',
        method: 'error',
        code:
          tracker.timedOut
            ? 'ANALYSIS_TIMEOUT'
            : 'ANALYSIS_EXCEPTION',
        mode: tracker.mode,
        contentLength: content.length,
      });
    } else {
      respond(undefined);
    }
  } finally {
    clearTimeout(tracker.timeout);
    clearTimeout(tracker.contentTimeout);

    if (
      ACTIVE_ANALYSES.get(tabId) === tracker
    ) {
      ACTIVE_ANALYSES.delete(tabId);
      stopScanningAnimation(tabId);
    }

    tracker.requestContent = null;
    settleCompletion(completedResult);
  }
}

// ============================================================
// BADGE AND ICON STATE
// ============================================================

function iconNameFor(normalized) {
  if (
    normalized.judgment === 'WARNING' &&
    normalized.signal === 'danger'
  ) {
    return 'warn';
  }

  if (normalized.signal === 'safe') {
    return 'safe';
  }

  if (normalized.signal === 'danger') {
    return 'danger';
  }

  if (
    normalized.judgment === 'INBOX' ||
    normalized.judgment === 'SKIPPED' ||
    normalized.judgment === 'IGNORED'
  ) {
    return 'skipped';
  }

  return 'neutral';
}

function iconPaths(name) {
  const paths = {};

  for (const size of [16, 32, 48, 128]) {
    paths[size] =
      `icons/icon-dad-${name}-${size}.png`;
  }

  return paths;
}

function updateBadge(
  tabId,
  isMalicious,
  result = null
) {
  const normalized = normalizeResult(
    result || {
      judgment:
        isMalicious === true
          ? 'SCAM'
          : 'UNVERIFIED',
    }
  );

  chrome.action.setBadgeText(
    {
      text: '',
      tabId,
    },
    () => {
      if (chrome.runtime.lastError) {
        // Ignore tab closure.
      }
    }
  );

  chrome.action.setIcon(
    {
      tabId,
      path: iconPaths(
        iconNameFor(normalized)
      ),
    },
    () => {
      if (chrome.runtime.lastError) {
        // Ignore tab closure.
      }
    }
  );
}

// ============================================================
// PERIODIC CLEANUP
// ============================================================

chrome.alarms.create(
  'dadblock-cleanup',
  {
    periodInMinutes: 5,
  }
);

chrome.alarms.onAlarm.addListener(
  async alarm => {
    if (
      alarm.name !== 'dadblock-cleanup'
    ) {
      return;
    }

    if (DETECTION_CACHE.size > 100) {
      DETECTION_CACHE.clear();
    }

    if (
      activeMode === 'cloud' &&
      Date.now() - lastLocalUseAt >
        OFFSCREEN_IDLE_CLOSE_MS
    ) {
      await closeOffscreenDocument();
    }

    const allStorage =
      await chrome.storage.local.get(null);

    const now = Date.now();
    const keysToRemove = [];

    for (
      const [key, value] of
      Object.entries(allStorage)
    ) {
      if (
        (
          key.startsWith('detection_') ||
          key.startsWith('tab')
        ) &&
        value?.timestamp &&
        now - value.timestamp > 3600000
      ) {
        keysToRemove.push(key);
      }
    }

    if (keysToRemove.length > 0) {
      await chrome.storage.local.remove(
        keysToRemove
      );

      console.log(
        `[Dadblock] Cleaned up ` +
        `${keysToRemove.length} old results`
      );
    }

    const { ignoreRules = [] } =
      await chrome.storage.local.get([
        'ignoreRules',
      ]);

    const validRules = ignoreRules.filter(
      rule =>
        !rule.expiry ||
        rule.expiry > now
    );

    if (
      validRules.length !==
      ignoreRules.length
    ) {
      await chrome.storage.local.set({
        ignoreRules: validRules,
      });
    }
  }
);

// ============================================================
// DOCUMENT OWNERSHIP AND NAVIGATION
// ============================================================

// frameId 0 persists across navigation. documentId distinguishes
// the current document from an old document at the same URL.
async function readActiveDocument(tabId) {
  if (
    !Number.isInteger(tabId) ||
    !chrome.webNavigation?.getFrame
  ) {
    return null;
  }

  try {
    const [tab, frame] = await Promise.all([
      chrome.tabs.get(tabId),
      chrome.webNavigation.getFrame({
        tabId,
        frameId: 0,
      }),
    ]);

    if (
      !frame ||
      frame.errorOccurred ||
      typeof frame.documentId !== 'string' ||
      (
        frame.documentLifecycle &&
        frame.documentLifecycle !== 'active'
      ) ||
      typeof frame.url !== 'string' ||
      tab.url !== frame.url
    ) {
      return null;
    }

    return {
      tab,
      documentId: frame.documentId,
      url: frame.url,
    };
  } catch {
    return null;
  }
}

// Search results are lists of other sites' text, not a page to judge.
// Dad checks the page you open instead.
function isSearchResultsURL(value) {
  try {
    const url = new URL(value);
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
  } catch {
    return false;
  }
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

function isSupportedScanURL(value) {
  try {
    const url = new URL(value);

    if (isSearchResultsURL(value) || isWorkspaceEditorURL(url)) {
      return false;
    }

    if (
      url.protocol !== 'http:' &&
      url.protocol !== 'https:'
    ) {
      return false;
    }

    const host =
      url.hostname.toLowerCase();

    const excluded = [
      'youtube.com',
      'youtube-nocookie.com',
      'googlevideo.com',
      'ytimg.com',
      'chromewebstore.google.com',
    ];

    if (
      excluded.some(domain =>
        host === domain ||
        host.endsWith('.' + domain)
      )
    ) {
      return false;
    }

    return !(
      host === 'chrome.google.com' &&
      url.pathname.startsWith('/webstore')
    );
  } catch {
    return false;
  }
}

// Duplicate loading events never reset an epoch.
// Only a different document or a different route does.
function adoptTabDocument(
  tabId,
  documentId,
  url
) {
  const previous =
    TAB_DOCUMENTS.get(tabId);

  if (
    previous?.documentId === documentId &&
    previous.url === url
  ) {
    return previous;
  }

  cancelAnalysisForTab(tabId);
  MANUAL_SCAN_TABS.delete(tabId);

  const state = {
    documentId,
    url,
    hasAnalysis: false,
    finished: false,
    readinessAttempts: 0,
    notifying: null,
  };

  TAB_DOCUMENTS.set(tabId, state);

  queueTabStorage(tabId, async () => {
    if (
      TAB_DOCUMENTS.get(tabId) === state
    ) {
      await chrome.storage.local.remove([
        `detection_${tabId}`,
      ]);
    }
  }).catch(() => {});

  updateBadge(tabId, null, {
    judgment: 'UNVERIFIED',
  });

  return state;
}

function cancelAnalysisForTab(tabId) {
  TAB_SCAN_EPOCHS.set(
    tabId,
    (TAB_SCAN_EPOCHS.get(tabId) || 0) + 1
  );

  const analysis =
    ACTIVE_ANALYSES.get(tabId);

  if (analysis) {
    analysis.cancelled = true;

    clearTimeout(analysis.timeout);
    clearTimeout(analysis.contentTimeout);
    clearTimeout(analysis.requestTimeout);

    analysis.abortController?.abort();

    ACTIVE_ANALYSES.delete(tabId);
  }

  stopScanningAnimation(tabId);
}

function cleanupClosedTab(tabId) {
  // Abort the model job, not just its bookkeeping entry.
  cancelAnalysisForTab(tabId);

  MANUAL_SCAN_TABS.delete(tabId);
  TAB_DOCUMENTS.delete(tabId);
  TAB_SCAN_EPOCHS.delete(tabId);

  for (
    const key of Array.from(DETECTION_CACHE.keys())
  ) {
    if (key.startsWith(`tab${tabId}:`)) {
      DETECTION_CACHE.delete(key);
    }
  }

  queueTabStorage(tabId, async () => {
    const all =
      await chrome.storage.local.get(null);

    const keys = Object.keys(all).filter(
      key =>
        key === `detection_${tabId}` ||
        key.startsWith(`tab${tabId}:`)
    );

    if (keys.length) {
      await chrome.storage.local.remove(keys);
    }
  }).catch(() => {});
}

chrome.tabs.onRemoved.addListener(
  tabId => {
    console.log(
      `[Dadblock] Tab ${tabId} closed, cleaning up state`
    );

    cleanupClosedTab(tabId);
  }
);

chrome.tabs.onReplaced.addListener(
  (addedTabId, removedTabId) => {
    cleanupClosedTab(removedTabId);

    handleNativeNavigation({
      tabId: addedTabId,
      frameId: 0,
    }).catch(() => {});
  }
);

async function notifyScanDocument(
  tabId,
  state,
  epoch
) {
  if (
    !isRouteCurrent(tabId, state, epoch)
  ) {
    return false;
  }

  if (state.notifying) {
    return state.notifying;
  }

  const pending = (async () => {
    const settings = await getSettings();
    const live = await readActiveDocument(
      tabId
    );

    if (
      !settings.ok ||
      !settings.enableAutoScan ||
      !isRouteCurrent(tabId, state, epoch) ||
      live?.documentId !== state.documentId ||
      live.url !== state.url
    ) {
      return false;
    }

    if (
      ACTIVE_ANALYSES.get(tabId)?.abortController
    ) {
      return true;
    }

    try {
      const reply = await chrome.tabs.sendMessage(
        tabId,
        {
          action: 'pageNavigation',
          trigger: 'auto',
          pageUrl: state.url,
        },
        {
          documentId: state.documentId,
        }
      );

      return (
        isRouteCurrent(tabId, state, epoch) &&
        reply?.acknowledged === true
      );
    } catch {
      // The document_end content script may not yet exist
      // when onCommitted first fires.
      return false;
    }
  })();

  state.notifying = pending;

  try {
    return await pending;
  } finally {
    if (state.notifying === pending) {
      state.notifying = null;
    }
  }
}

async function beginPageScanWatch(
  tabId,
  tabUrl,
  documentId
) {
  const state =
    TAB_DOCUMENTS.get(tabId);

  const epoch =
    TAB_SCAN_EPOCHS.get(tabId) || 0;

  if (
    !state ||
    state.url !== tabUrl ||
    state.documentId !== documentId ||
    state.hasAnalysis ||
    state.finished ||
    state.readinessAttempts >= 3
  ) {
    return;
  }

  const settings = await getSettings();
  const live = await readActiveDocument(
    tabId
  );

  if (
    !isRouteCurrent(tabId, state, epoch) ||
    live?.documentId !== documentId ||
    live.url !== tabUrl ||
    ACTIVE_ANALYSES.has(tabId)
  ) {
    return;
  }

  if (
    !settings.ok ||
    !settings.enableAutoScan ||
    !isSupportedScanURL(tabUrl)
  ) {
    state.finished = true;

    await publishResult(
      tabId,
      tabUrl,
      {
        judgment: 'SKIPPED',
        analysis:
          !settings.ok
            ? 'Dadblock could not read its settings.'
            : !settings.enableAutoScan
              ? 'Auto-scan is turned off. Use Scan now to check this page.'
              : isSearchResultsURL(tabUrl)
                ? 'Search results are not scanned. Open a result and Dad will check that page.'
                : isWorkspaceEditorURL(tabUrl)
                  ? 'Dad does not read your private documents, boards or designs, so this page is not scanned.'
                  : 'This page is outside the supported scanning scope.',
        method: 'skipped',
        code:
          !settings.ok
            ? 'SETTINGS_UNAVAILABLE'
            : !settings.enableAutoScan
              ? 'AUTO_SCAN_DISABLED'
              : 'UNSUPPORTED_PAGE',
        mode: settings.selectedMode,
        contentLength: 0,
      },
      {
        state,
        epoch,
      }
    );

    return;
  }

  state.readinessAttempts++;

  const watcher = {
    url: tabUrl,
    documentId,
    epoch,
    manual: false,
    cancelled: false,
    timeout: null,
    contentTimeout: null,
    requestTimeout: null,
    abortController: null,
    startTime: Date.now(),
  };

  const ownsWatch = () => (
    isRouteCurrent(tabId, state, epoch) &&
    ACTIVE_ANALYSES.get(tabId) === watcher &&
    !watcher.cancelled
  );

  ACTIVE_ANALYSES.set(tabId, watcher);
  startScanningAnimation(tabId);

  watcher.contentTimeout = setTimeout(
    async () => {
      if (!ownsWatch()) {
        return;
      }

      const current =
        await readActiveDocument(tabId);

      if (
        !ownsWatch() ||
        current?.documentId !== documentId ||
        current.url !== tabUrl
      ) {
        return;
      }

      ACTIVE_ANALYSES.delete(tabId);
      stopScanningAnimation(tabId);

      await publishResult(
        tabId,
        tabUrl,
        {
          judgment: 'SKIPPED',
          analysis:
            'Could not obtain readable content from this page. Use Scan now to retry.',
          method: 'skipped',
          code: 'CONTENT_NOT_RECEIVED',
          mode: settings.selectedMode,
        },
        {
          state,
          epoch,
        }
      ).catch(() => {});
    },
    12000
  );

  watcher.requestTimeout = setTimeout(
    () => {
      if (ownsWatch()) {
        notifyScanDocument(
          tabId,
          state,
          epoch
        ).catch(() => {});
      }
    },
    300
  );
}

// Verify the current browser document before handling an event.
// Subframe navigation and pop-under tabs cannot cancel another
// tab's scan.
async function handleNativeNavigation(
  details
) {
  if (
    details.frameId !== 0 ||
    (
      details.documentLifecycle &&
      details.documentLifecycle !== 'active'
    )
  ) {
    return;
  }

  const live = await readActiveDocument(
    details.tabId
  );

  if (
    !live ||
    (
      details.documentId &&
      details.documentId !== live.documentId
    ) ||
    (
      details.url &&
      details.url !== live.url
    )
  ) {
    return;
  }

  const state = adoptTabDocument(
    details.tabId,
    live.documentId,
    live.url
  );

  const epoch =
    TAB_SCAN_EPOCHS.get(details.tabId) || 0;

  await beginPageScanWatch(
    details.tabId,
    live.url,
    live.documentId
  );

  // DOMContentLoaded/onCompleted retry delivery without
  // cancelling or resetting an existing scan.
  if (
    isRouteCurrent(
      details.tabId,
      state,
      epoch
    ) &&
    !state.hasAnalysis &&
    !state.finished &&
    ACTIVE_ANALYSES.has(details.tabId)
  ) {
    await notifyScanDocument(
      details.tabId,
      state,
      epoch
    );
  }
}

if (chrome.webNavigation?.onCommitted) {
  for (
    const event of [
      chrome.webNavigation.onCommitted,
      chrome.webNavigation.onHistoryStateUpdated,
      chrome.webNavigation.onReferenceFragmentUpdated,
      chrome.webNavigation.onDOMContentLoaded,
      chrome.webNavigation.onCompleted,
    ]
  ) {
    event.addListener(details => {
      handleNativeNavigation(details)
        .catch(error => {
          console.warn(
            '[Dadblock] Navigation coordination failed:',
            error?.name || 'Error'
          );
        });
    });
  }
} else {
  console.error(
    '[Dadblock] Missing webNavigation permission. Use the Part 1 manifest.'
  );
}

// Browser URL updates provide an additional verified delivery
// opportunity. HTTP loading events alone never cancel work.
chrome.tabs.onUpdated.addListener(
  (tabId, changeInfo, tab) => {
    if (
      !tab.url ||
      (
        changeInfo.status !== 'loading' &&
        changeInfo.status !== 'complete' &&
        !changeInfo.url
      )
    ) {
      return;
    }

    let protocol;

    try {
      protocol = new URL(tab.url).protocol;
    } catch {
      return;
    }

    if (
      protocol === 'http:' ||
      protocol === 'https:'
    ) {
      if (
        changeInfo.url ||
        changeInfo.status === 'complete'
      ) {
        handleNativeNavigation({
          tabId,
          frameId: 0,
        }).catch(() => {});
      }

      return;
    }

    const state = adoptTabDocument(
      tabId,
      null,
      tab.url
    );

    state.finished = true;

    const epoch =
      TAB_SCAN_EPOCHS.get(tabId) || 0;

    if (
      tab.url.startsWith('chrome://newtab') ||
      tab.url.startsWith('edge://newtab') ||
      tab.url === 'about:blank'
    ) {
      updateBadge(tabId, null, {
        judgment: 'UNVERIFIED',
      });

      return;
    }

    publishResult(
      tabId,
      tab.url,
      {
        judgment: 'SKIPPED',
        method: 'skipped',
        analysis:
          'System pages and extension pages are not scanned.',
      },
      {
        state,
        epoch,
      }
    ).catch(() => {});
  }
);

// ============================================================
// SCANNING ANIMATION
// ============================================================

function startScanningAnimation(tabId) {
  stopScanningAnimation(tabId);

  let frame = 0;

  const totalFrames = 8;

  const animationInterval = setInterval(
    () => {
      const canvas = new OffscreenCanvas(
        128,
        128
      );

      const context = canvas.getContext(
        '2d'
      );

      context.clearRect(0, 0, 128, 128);

      const angle =
        (frame / totalFrames) *
        Math.PI *
        2;

      const radius = 15;

      const centerX =
        64 + Math.cos(angle) * radius;

      const centerY =
        64 + Math.sin(angle) * radius;

      context.beginPath();
      context.arc(
        centerX,
        centerY,
        30,
        0,
        Math.PI * 2
      );
      context.strokeStyle = '#3B82F6';
      context.lineWidth = 8;
      context.stroke();

      context.beginPath();
      context.arc(
        centerX,
        centerY,
        22,
        0,
        Math.PI * 2
      );
      context.strokeStyle = '#60A5FA';
      context.lineWidth = 4;
      context.stroke();

      const handleAngle =
        angle + Math.PI * 0.75;

      const handleLength = 30;

      const handleX =
        centerX +
        Math.cos(handleAngle) *
        handleLength;

      const handleY =
        centerY +
        Math.sin(handleAngle) *
        handleLength;

      context.beginPath();

      context.moveTo(
        centerX +
          Math.cos(handleAngle) * 25,
        centerY +
          Math.sin(handleAngle) * 25
      );

      context.lineTo(
        handleX,
        handleY
      );

      context.strokeStyle = '#3B82F6';
      context.lineWidth = 8;
      context.lineCap = 'round';
      context.stroke();

      const imageData =
        context.getImageData(
          0,
          0,
          128,
          128
        );

      chrome.action.setIcon(
        {
          tabId,
          imageData,
        },
        () => {
          if (chrome.runtime.lastError) {
            // Ignore tab closure.
          }
        }
      );

      frame =
        (frame + 1) % totalFrames;
    },
    150
  );

  SCANNING_ANIMATIONS.set(
    tabId,
    animationInterval
  );
}

function stopScanningAnimation(tabId) {
  const animationInterval =
    SCANNING_ANIMATIONS.get(tabId);

  if (animationInterval) {
    clearInterval(animationInterval);

    SCANNING_ANIMATIONS.delete(tabId);
  }
}

// ============================================================
// STARTUP AI AND UNINSTALL FEEDBACK
// ============================================================

chrome.runtime.setUninstallURL(
  'https://dadblock.org/goodbye.html'
);

aiInitPromise = initializeAI();

// ============================================================
// AD-BLOCKING ARCHITECTURE
// ============================================================

const SYNC_ALARM_NAME =
  'dadblock-sync-dynamic-rules';

const REMOTE_RULES_ENDPOINT =
  'https://dadblock-api.dadblock-api.workers.dev/dynamic-rules.json';

// Session rules are rebuilt from stored pause preferences
// because Chrome does not persist them across browser restarts.
async function syncAdBlockAllowlist() {
  try {
    const {
      adBlockDisabledDomains = [],
    } = await chrome.storage.local.get([
      'adBlockDisabledDomains',
    ]);

    const existing =
      await chrome.declarativeNetRequest
        .getSessionRules();

    const removeRuleIds = existing.map(
      rule => rule.id
    );

    const addRules =
      adBlockDisabledDomains.map(
        (domain, index) => ({
          id: index + 1,
          priority: 1000,
          action: {
            type: 'allowAllRequests',
          },
          condition: {
            urlFilter: `||${domain}^`,
            resourceTypes: [
              'main_frame',
              'sub_frame',
            ],
          },
        })
      );

    await chrome.declarativeNetRequest
      .updateSessionRules({
        removeRuleIds,
        addRules,
      });

    console.log(
      '[Dadblock] Ad-block session allowlist synced: ' +
      `${addRules.length} domain(s) paused.`
    );
  } catch (error) {
    console.error(
      '[Dadblock] Failed to sync ad-block allowlist:',
      error && error.name
    );
  }
}

// Turning off auto-scan does not cancel an explicit manual scan.
function cancelAutomaticAnalyses() {
  for (
    const tabId of Array.from(ACTIVE_ANALYSES.keys())
  ) {
    if (
      ACTIVE_ANALYSES.get(tabId)?.manual === true
    ) {
      continue;
    }

    cancelAnalysisForTab(tabId);

    updateBadge(tabId, null, {
      judgment: 'SKIPPED',
      method: 'skipped',
    });
  }
}

async function removeBannersEverywhere() {
  try {
    const tabs = await chrome.tabs.query({
      url: [
        'http://*/*',
        'https://*/*',
      ],
    });

    for (const tab of tabs) {
      chrome.tabs.sendMessage(
        tab.id,
        {
          action: 'removeThreatBanner',
        }
      ).catch(() => {});
    }
  } catch (error) {
    console.warn(
      '[Dadblock] Could not clear banners:',
      error && error.name
    );
  }
}

chrome.storage.onChanged.addListener(
  (changes, namespace) => {
    if (namespace !== 'local') {
      return;
    }

    if (
      changes.adBlockDisabledDomains
    ) {
      syncAdBlockAllowlist();
    }

    const modeChange =
      changes.selectedMode ||
      changes.activeMode;

    if (modeChange) {
      const requested =
        modeChange.newValue;

      if (
        (
          requested === 'local' ||
          requested === 'cloud'
        ) &&
        requested !== activeMode
      ) {
        switchMode(requested)
          .catch(error => {
            console.error(
              '[Dadblock] Mode switch failed:',
              error && error.name
            );
          });
      }
    }

    if (
      changes.enableAutoScan ||
      changes.autoScan
    ) {
      getSettings()
        .then(settings => {
          if (
            !settings.ok ||
            !settings.enableAutoScan
          ) {
            cancelAutomaticAnalyses();
          }
        })
        .catch(() => {
          cancelAutomaticAnalyses();
        });
    }

    if (
      changes.bannerEnabled ||
      changes.showBanner
    ) {
      getSettings()
        .then(settings => {
          if (
            !settings.ok ||
            !settings.bannerEnabled
          ) {
            removeBannersEverywhere();
          }
        })
        .catch(() => {});
    }
  }
);

chrome.runtime.onStartup.addListener(
  () => {
    syncAdBlockAllowlist();
    synchronizeDynamicRules();
    ensureRegisteredScripts();
  }
);

// ============================================================
// INSTALLATION AND UPDATES
// ============================================================

chrome.runtime.onInstalled.addListener(
  async details => {
    if (details.reason === 'install') {
      chrome.tabs.create({
        url: chrome.runtime.getURL(
          'onboarding.html'
        ),
      });

      // Prefer local only when this browser's on-device model
      // is already usable. A downloading or unavailable model
      // defaults to cloud so a new installation can scan.
      try {
        const capability =
          await getLocalAvailability();

        const readyNow =
          capability === 'readily';

        const defaultMode =
          readyNow ? 'local' : 'cloud';

        await switchMode(defaultMode);

        console.log(
          '[Dadblock] Fresh install; on-device AI capability: ' +
          `${capability}. Defaulting to ${defaultMode} mode.`
        );

        // A model download requiring user activation must
        // be initiated through the settings UI.
      } catch (error) {
        console.error(
          '[Dadblock] Capability check failed; defaulting to cloud mode:',
          error && error.name
        );

        await chrome.storage.local.set({
          selectedMode: 'cloud',
          activeMode: 'cloud',
        });
      }
    }

    chrome.alarms.create(
      SYNC_ALARM_NAME,
      {
        periodInMinutes: 1440,
      }
    );

    synchronizeDynamicRules();
    syncAdBlockAllowlist();

    await ensureRegisteredScripts();
  }
);

// ============================================================
// PERSISTED CONTENT SCRIPT REGISTRATION
// ============================================================

// Reconcile only Dadblock-owned scripts. Updating registrations
// avoids a protection gap caused by unregistering everything.
let scriptRegistrationInFlight = null;

function ensureRegisteredScripts() {
  if (scriptRegistrationInFlight) {
    return scriptRegistrationInFlight;
  }

  scriptRegistrationInFlight =
    reconcileRegisteredScripts()
      .finally(() => {
        scriptRegistrationInFlight = null;
      });

  return scriptRegistrationInFlight;
}

async function reconcileRegisteredScripts() {
  const desired = [
    {
      id: 'dadblock-video-optimizer',
      js: [
        'video-player-module.js',
      ],
      matches: [
        '*://*.youtube.com/*',
        '*://*.twitch.tv/*',
      ],
      runAt: 'document_start',

      // This supplied module uses authenticated chrome.storage
      // settings, so it must run in ISOLATED.
      world: 'ISOLATED',
      allFrames: false,
      matchOriginAsFallback: false,
      persistAcrossSessions: true,
    },
    {
      id: 'dadblock-behavioral-security',
      js: [
        'injected.js',
      ],
      matches: [
        '*://*/*',
      ],
      excludeMatches: [
        '*://*.youtube.com/*',
        '*://*.googlevideo.com/*',
        '*://*.google.com/*',
      ],
      runAt: 'document_start',

      // window.open interception must execute in the page's
      // MAIN world, including related blank/blob frames.
      world: 'MAIN',
      allFrames: true,
      matchOriginAsFallback: true,
      persistAcrossSessions: true,
    },
    {
      id: 'dadblock-behavior-probe',
      js: [
        'behavior-probe.js',
      ],
      matches: [
        '*://*/*',
      ],
      excludeMatches: [
        '*://*.youtube.com/*',
        '*://*.googlevideo.com/*',
        '*://*.google.com/*',
      ],
      runAt: 'document_start',

      // Records sensitive-feature calls (notifications, location,
      // clipboard, camera) for Dad's report. Top frame only.
      world: 'MAIN',
      allFrames: false,
      matchOriginAsFallback: false,
      persistAcrossSessions: true,
    },
  ];

  try {
    let existing =
      await chrome.scripting
        .getRegisteredContentScripts();

    // Registered scripts can keep serving an older copy of their file
    // after an update. Re-registering whenever the build changes
    // guarantees the newest popup blocker and probe are the ones that run.
    try {
      const manifest = chrome.runtime.getManifest();
      const build = String(manifest.version_name || manifest.version);
      const stored =
        (await chrome.storage.local.get('dadblockScriptBuild'))
          .dadblockScriptBuild;

      if (stored !== build) {
        const ours = new Set(desired.map(script => script.id));
        const present = existing
          .filter(script => ours.has(script.id))
          .map(script => script.id);

        if (present.length) {
          await chrome.scripting.unregisterContentScripts({ ids: present });
        }

        existing = existing.filter(script => !ours.has(script.id));

        await chrome.storage.local.set({ dadblockScriptBuild: build });
      }
    } catch {
      // Falls back to the normal reconcile below.
    }

    const byId = new Map(
      existing.map(script => [
        script.id,
        script,
      ])
    );

    const additions = [];
    const updates = [];

    for (const script of desired) {
      const current = byId.get(
        script.id
      );

      if (!current) {
        additions.push(script);

        continue;
      }

      const differs =
        Object.keys(script).some(
          key =>
            JSON.stringify(current[key]) !==
            JSON.stringify(script[key])
        );

      if (differs) {
        updates.push(script);
      }
    }

    if (updates.length) {
      await chrome.scripting
        .updateContentScripts(updates);
    }

    if (additions.length) {
      await chrome.scripting
        .registerContentScripts(additions);
    }

    console.log(
      '[Dadblock] Extension scripts registered successfully.'
    );
  } catch (error) {
    console.error(
      '[Dadblock] Failed to register scripts:',
      error?.name || 'Error'
    );
  }
}

// ============================================================
// AUTHENTICATED DYNAMIC RULE SYNC
// ============================================================

chrome.alarms.onAlarm.addListener(
  alarm => {
    if (
      alarm.name === SYNC_ALARM_NAME
    ) {
      synchronizeDynamicRules();
    }
  }
);

function hasUsableAdRules(rules) {
  if (
    !Array.isArray(rules) ||
    rules.length === 0 ||
    rules.length > 30000
  ) {
    return false;
  }

  const ids = new Set();

  for (const rule of rules) {
    if (
      !rule ||
      typeof rule !== 'object' ||
      Array.isArray(rule) ||
      !Number.isSafeInteger(rule.id) ||
      rule.id <= 0 ||
      ids.has(rule.id) ||
      !rule.action ||
      typeof rule.action !== 'object' ||
      Array.isArray(rule.action) ||
      typeof rule.action.type !== 'string' ||
      !rule.action.type.trim() ||
      !rule.condition ||
      typeof rule.condition !== 'object' ||
      Array.isArray(rule.condition)
    ) {
      return false;
    }

    if (
      rule.priority !== undefined &&
      (
        !Number.isSafeInteger(rule.priority) ||
        rule.priority < 1
      )
    ) {
      return false;
    }

    ids.add(rule.id);
  }

  return true;
}

let dynamicRulesSyncInFlight = null;

async function restoreBundledRulesIfEmpty() {
  const existing =
    await chrome.declarativeNetRequest
      .getDynamicRules();

  if (existing.length !== 0) {
    return;
  }

  const response = await fetch(
    chrome.runtime.getURL('rules.json'),
    {
      cache: 'no-store',
    }
  );

  if (!response.ok) {
    throw new Error(
      'Bundled rules could not be read'
    );
  }

  const bundledRules =
    await response.json();

  if (!hasUsableAdRules(bundledRules)) {
    throw new Error(
      'Bundled rules are empty or malformed'
    );
  }

  // Recheck after asynchronous file loading.
  const current =
    await chrome.declarativeNetRequest
      .getDynamicRules();

  if (current.length !== 0) {
    return;
  }

  await chrome.declarativeNetRequest
    .updateDynamicRules({
      removeRuleIds: [],
      addRules: bundledRules,
    });

  console.log(
    `[Dadblock] Restored ${bundledRules.length} bundled dynamic rules.`
  );
}

function synchronizeDynamicRules() {
  if (dynamicRulesSyncInFlight) {
    return dynamicRulesSyncInFlight;
  }

  dynamicRulesSyncInFlight =
    performDynamicRulesSync()
      .finally(() => {
        dynamicRulesSyncInFlight = null;
      });

  return dynamicRulesSyncInFlight;
}

async function performDynamicRulesSync() {
  // Recover installations whose dynamic rules were previously
  // wiped by an empty remote response.
  //
  // Static rules remain configured independently in manifest.json.
  try {
    await restoreBundledRulesIfEmpty();
  } catch (error) {
    console.warn(
      '[Dadblock] Bundled rule recovery failed:',
      error && error.name
        ? error.name
        : 'Error'
    );
  }

  const controller =
    new AbortController();

  const timeout = setTimeout(
    () => {
      controller.abort();
    },
    15000
  );

  try {
    const response = await fetch(
      REMOTE_RULES_ENDPOINT,
      {
        cache: 'no-store',
        credentials: 'omit',
        signal: controller.signal,
      }
    );

    if (!response.ok) {
      console.warn(
        `[Dadblock] Rules sync skipped: HTTP ${response.status}; ` +
        'installed rules retained.'
      );

      return;
    }

    const envelope = await response.json();

    if (
      !envelope ||
      typeof envelope !== 'object' ||
      Array.isArray(envelope) ||
      typeof envelope.payload !== 'string' ||
      typeof envelope.signature !== 'string' ||
      !envelope.signature
    ) {
      console.warn(
        '[Dadblock] Rules sync rejected: missing authenticated payload.'
      );

      return;
    }

    const verified =
      await verifyAndParseRulesPayload(
        envelope.payload,
        envelope.signature
      );

    if (!verified) {
      console.warn(
        '[Dadblock] Rules sync rejected: signature or freshness check failed.'
      );

      return;
    }

    // A valid signature does not make an empty ruleset safe
    // to install. Keep the existing protection.
    if (
      !hasUsableAdRules(verified.rules)
    ) {
      console.warn(
        '[Dadblock] Rules sync rejected: empty or malformed rules; ' +
        'installed rules retained.'
      );

      return;
    }

    const existing =
      await chrome.declarativeNetRequest
        .getDynamicRules();

    // Chrome validates the complete incoming ruleset in one
    // atomic operation. A rejection retains existing rules.
    await chrome.declarativeNetRequest
      .updateDynamicRules({
        removeRuleIds: existing.map(
          rule => rule.id
        ),
        addRules: verified.rules,
      });

    console.log(
      `[Dadblock] Synced ${verified.rules.length} authenticated dynamic rules.`
    );
  } catch (error) {
    console.warn(
      '[Dadblock] Rules sync failed; installed rules retained:',
      error && error.name
        ? error.name
        : 'Error'
    );
  } finally {
    clearTimeout(timeout);
  }
}

// Cold service-worker starts repair persisted registrations
// after all registration state has been initialized.
ensureRegisteredScripts();
syncAdBlockAllowlist();
