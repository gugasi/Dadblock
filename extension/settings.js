// settings.js
// Canonical settings take precedence. User changes write canonical and
// legacy keys together so older extension pages remain compatible.

(() => {
  'use strict';

  const STORAGE_KEYS = [
    'enableAutoScan',
    'autoScan',
    'bannerEnabled',
    'showBanner',
    'scanChanges',
    'selectedMode',
    'activeMode',
    'customApiKey',
    'ignoreRules',
    'adBlockDisabledDomains',
    'cosmeticDisabledDomains',
  ];

  const TOGGLE_SETTINGS = [
    {
      id: 'enableAutoScan',
      canonical: 'enableAutoScan',
      legacy: 'autoScan',
    },
    {
      id: 'bannerEnabled',
      canonical: 'bannerEnabled',
      legacy: 'showBanner',
    },
    {
      id: 'scanChanges',
      canonical: 'scanChanges',
      legacy: null,
    },
  ];

  const SVG_MOON =
    '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>';

  const SVG_SUN =
    '<circle cx="12" cy="12" r="5"></circle>' +
    '<line x1="12" y1="1" x2="12" y2="3"></line>' +
    '<line x1="12" y1="21" x2="12" y2="23"></line>' +
    '<line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>' +
    '<line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>' +
    '<line x1="1" y1="12" x2="3" y2="12"></line>' +
    '<line x1="21" y1="12" x2="23" y2="12"></line>' +
    '<line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>' +
    '<line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>';

  const RULE_TYPE_LABELS = {
    domain: 'Domain',
    url: 'Page',
    domain_temporary: '24h Domain',
    url_temporary: '24h Page',
  };

  let theme = 'light';

  try {
    theme = localStorage.getItem('dadblock-theme') === 'dark'
      ? 'dark'
      : 'light';
  } catch {
    // Theme persistence is optional.
  }

  applyTheme(theme);

  let ui = null;
  let storage = null;
  let snapshot = {};
  let settingsLoaded = false;
  let storageRevision = 0;
  let readPromise = null;
  let mutationQueue = Promise.resolve();
  let messageTimeout = null;

  let pendingMode = null;
  let rulesMutationPending = false;
  let apiKeyDirty = false;

  const pendingControls = new Set();
  const pendingToggles = new Map();

  function applyTheme(value) {
    theme = value === 'dark' ? 'dark' : 'light';

    if (theme === 'dark') {
      document.documentElement.setAttribute('data-theme', 'dark');
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
  }

  function updateThemeUI() {
    if (!ui) return;

    // These SVG fragments are static extension-owned strings.
    ui.themeIcon.innerHTML = theme === 'dark' ? SVG_SUN : SVG_MOON;
    ui.themeText.textContent = theme === 'dark'
      ? 'Light Mode'
      : 'Dark Mode';

    ui.themeToggle.setAttribute(
      'aria-label',
      theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'
    );
  }

  function readSetting(canonical, legacy, fallback) {
    const value = snapshot[canonical] !== undefined
      ? snapshot[canonical]
      : legacy
        ? snapshot[legacy]
        : undefined;

    return value === undefined ? fallback : value;
  }

  function readBooleanSetting(canonical, legacy) {
    const value = readSetting(canonical, legacy, true);
    return typeof value === 'boolean' ? value : true;
  }

  function readSelectedMode() {
    const value = readSetting('selectedMode', 'activeMode', 'cloud');
    return value === 'local' || value === 'cloud' ? value : 'cloud';
  }

  function asArray(value) {
    return Array.isArray(value) ? value : [];
  }

  function isValidRule(rule) {
    return (
      rule &&
      typeof rule === 'object' &&
      typeof rule.type === 'string' &&
      typeof rule.pattern === 'string' &&
      rule.pattern.length > 0
    );
  }

  function isActiveRule(rule) {
    if (!isValidRule(rule)) return false;

    if (rule.expiry === undefined || rule.expiry === null) {
      return true;
    }

    const expiry = Number(rule.expiry);
    return Number.isFinite(expiry) && expiry > Date.now();
  }

  function sameRule(first, second) {
    return (
      first?.type === second?.type &&
      first?.pattern === second?.pattern &&
      first?.timestamp === second?.timestamp &&
      first?.expiry === second?.expiry
    );
  }

  function showMessage(text, isError = false) {
    if (!ui) return;

    clearTimeout(messageTimeout);

    ui.statusMessage.textContent = text;
    ui.statusMessage.classList.toggle('error', isError);
    ui.statusMessage.classList.add('show');

    messageTimeout = window.setTimeout(() => {
      ui.statusMessage.classList.remove('show');
    }, isError ? 7000 : 3000);
  }

  function updateModeUI() {
    const selected = pendingMode || readSelectedMode();

    for (const [mode, button] of [
      ['local', ui.modeLocal],
      ['cloud', ui.modeCloud],
    ]) {
      const active = settingsLoaded && selected === mode;

      button.classList.toggle('active', active);
      button.setAttribute('aria-pressed', String(active));

      button.disabled = (
        !settingsLoaded ||
        pendingControls.has('modeLocal') ||
        pendingControls.has('modeCloud')
      );
    }

    if (!settingsLoaded) {
      ui.modeStatus.textContent = 'Settings are not loaded.';
    } else if (pendingMode) {
      ui.modeStatus.textContent = 'Saving engine selection…';
    } else {
      ui.modeStatus.textContent =
        `Selected: ${selected === 'local' ? 'Local' : 'Cloud'} Engine`;
    }
  }

  function renderSettings() {
    if (!ui) return;

    for (const config of TOGGLE_SETTINGS) {
      const input = ui[config.id];

      input.checked = pendingToggles.has(config.canonical)
        ? pendingToggles.get(config.canonical)
        : settingsLoaded &&
          readBooleanSetting(config.canonical, config.legacy);

      input.disabled = (
        !settingsLoaded ||
        pendingControls.has(config.id)
      );
    }

    updateModeUI();

    ui.customApiKey.disabled = (
      !settingsLoaded ||
      pendingControls.has('saveKeyBtn')
    );

    ui.saveKeyBtn.disabled = (
      !settingsLoaded ||
      pendingControls.has('saveKeyBtn')
    );

    if (!apiKeyDirty && !pendingControls.has('saveKeyBtn')) {
      ui.customApiKey.value = typeof snapshot.customApiKey === 'string'
        ? snapshot.customApiKey
        : '';
    }

    renderIgnoreRules();
    renderCosmeticOnlyDomains();
  }

  async function refreshSettings() {
    if (readPromise) return readPromise;

    readPromise = (async () => {
      for (let attempt = 0; attempt < 4; attempt++) {
        const revision = storageRevision;
        const values = await storage.local.get(STORAGE_KEYS);

        // A storage event during this read may have supplied newer values.
        if (revision !== storageRevision) continue;

        snapshot = values;
        settingsLoaded = true;
        renderSettings();
        return;
      }

      throw new Error('Settings changed during loading');
    })().catch(error => {
      settingsLoaded = false;
      renderSettings();
      throw error;
    }).finally(() => {
      readPromise = null;
    });

    return readPromise;
  }

  function enqueueMutation(operation) {
    const pending = mutationQueue.then(operation, operation);

    mutationQueue = pending.catch(() => {});
    return pending;
  }

  async function runChange(operation, successMessage) {
    try {
      await enqueueMutation(operation);
    } catch {
      try {
        await refreshSettings();
      } catch {
        // Keep controls disabled when authoritative state is unavailable.
      }

      showMessage(
        'Could not save this change. Please try again.',
        true
      );
      return false;
    }

    try {
      await refreshSettings();
      showMessage(successMessage);
    } catch {
      showMessage(
        'Your change was saved, but settings could not refresh. ' +
        'Reload this page.',
        true
      );
    }

    return true;
  }

  async function saveToggle(config, value) {
    if (!settingsLoaded || pendingControls.has(config.id)) return;

    pendingControls.add(config.id);
    pendingToggles.set(config.canonical, value);
    renderSettings();

    const update = { [config.canonical]: value };

    if (config.legacy) {
      update[config.legacy] = value;
    }

    try {
      await runChange(
        () => storage.local.set(update),
        "Settings saved! Dad's taking notes."
      );
    } finally {
      pendingControls.delete(config.id);
      pendingToggles.delete(config.canonical);
      renderSettings();
    }
  }

  async function setMode(mode) {
    if (
      !settingsLoaded ||
      (mode !== 'local' && mode !== 'cloud') ||
      pendingControls.has('modeLocal') ||
      pendingControls.has('modeCloud')
    ) {
      return;
    }

    pendingMode = mode;
    pendingControls.add('modeLocal');
    pendingControls.add('modeCloud');
    renderSettings();

    try {
      await runChange(
        () => storage.local.set({
          selectedMode: mode,
          activeMode: mode,
        }),
        `${mode === 'local' ? 'Local' : 'Cloud'} Engine selected.`
      );

      // The background's storage listener applies the engine switch.
      // No additional runtime message or duplicate initialization is needed.
    } finally {
      pendingMode = null;
      pendingControls.delete('modeLocal');
      pendingControls.delete('modeCloud');
      renderSettings();
    }
  }

  async function saveCustomApiKey(event) {
    event.preventDefault();

    if (
      !settingsLoaded ||
      pendingControls.has('saveKeyBtn')
    ) {
      return;
    }

    const key = ui.customApiKey.value.trim();

    pendingControls.add('saveKeyBtn');
    renderSettings();

    try {
      const saved = await runChange(
        () => storage.local.set({ customApiKey: key }),
        key
          ? 'Custom API key saved.'
          : 'Custom API key removed. The shared cloud engine will be used.'
      );

      if (saved) {
        apiKeyDirty = false;
        ui.customApiKey.value = key;
      }
    } finally {
      pendingControls.delete('saveKeyBtn');
      renderSettings();
    }
  }

  function renderEmptyState(container, message) {
    const element = document.createElement('div');
    element.className = 'empty-state';
    element.textContent = message;
    container.replaceChildren(element);
  }

  function createListItem(pattern, label, buttonText, onClick) {
    const item = document.createElement('div');
    item.className = 'ignore-item';

    const information = document.createElement('div');
    information.className = 'ignore-details';

    const patternElement = document.createElement('span');
    patternElement.className = 'ignore-url';
    patternElement.textContent = pattern;

    const typeElement = document.createElement('span');
    typeElement.className = 'ignore-type';
    typeElement.textContent = label;

    information.append(patternElement, typeElement);

    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'remove-btn';
    button.textContent = buttonText;
    button.disabled = !settingsLoaded || rulesMutationPending;
    button.setAttribute('aria-label', `${buttonText}: ${pattern}`);

    button.addEventListener('click', onClick);

    item.append(information, button);

    return { item, information };
  }

  function renderIgnoreRules() {
    const container = ui.ignoreList;

    if (!settingsLoaded) {
      renderEmptyState(container, 'Load settings to view ignored sites.');
      return;
    }

    const rules = asArray(snapshot.ignoreRules).filter(isActiveRule);

    if (rules.length === 0) {
      renderEmptyState(
        container,
        'No ignored pages or sites.'
      );
      return;
    }

    const fragment = document.createDocumentFragment();

    for (const rule of rules) {
      const { item, information } = createListItem(
        rule.pattern,
        RULE_TYPE_LABELS[rule.type] || rule.type,
        'Un-ignore',
        () => {
          removeIgnoreRule(rule).catch(() => {});
        }
      );

      if (
        (rule.type === 'domain_temporary' ||
          rule.type === 'url_temporary') &&
        Number.isFinite(Number(rule.expiry))
      ) {
        const minutes = Math.max(
          1,
          Math.ceil((Number(rule.expiry) - Date.now()) / 60000)
        );

        const expiry = document.createElement('span');
        expiry.className = 'ignore-expiry';
        expiry.textContent =
          `Expires in ${Math.floor(minutes / 60)}h ${minutes % 60}m`;

        information.append(expiry);
      }

      fragment.append(item);
    }

    // Stored patterns and rule types are rendered only as text.
    container.replaceChildren(fragment);
  }

  async function removeIgnoreRule(rule) {
    if (!settingsLoaded || rulesMutationPending) return;

    rulesMutationPending = true;
    renderSettings();

    try {
      await runChange(async () => {
        const values = await storage.local.get([
          'ignoreRules',
          'adBlockDisabledDomains',
          'cosmeticDisabledDomains',
        ]);

        const currentRules = asArray(values.ignoreRules);
        const index = currentRules.findIndex(candidate =>
          sameRule(candidate, rule)
        );

        // Identify the rule itself, not a stale rendered array index.
        if (index === -1) return;

        const remainingRules = currentRules.filter(
          (_, currentIndex) => currentIndex !== index
        );

        const update = { ignoreRules: remainingRules };

        const anotherDomainRule = remainingRules.some(candidate =>
          isActiveRule(candidate) &&
          candidate.type === 'domain' &&
          candidate.pattern === rule.pattern
        );

        if (rule.type === 'domain' && !anotherDomainRule) {
          update.adBlockDisabledDomains =
            asArray(values.adBlockDisabledDomains).filter(
              domain => domain !== rule.pattern
            );

          update.cosmeticDisabledDomains =
            asArray(values.cosmeticDisabledDomains).filter(
              domain => domain !== rule.pattern
            );
        }

        // Resume associated domain pauses in the same storage write.
        await storage.local.set(update);
      }, 'Ignore rule removed.');
    } finally {
      rulesMutationPending = false;
      renderSettings();
    }
  }

  function renderCosmeticOnlyDomains() {
    const container = ui.cosmeticOnlyList;

    if (!settingsLoaded) {
      renderEmptyState(container, 'Load settings to view cosmetic pauses.');
      return;
    }

    const ignoredDomains = new Set(
      asArray(snapshot.ignoreRules)
        .filter(rule => isActiveRule(rule) && rule.type === 'domain')
        .map(rule => rule.pattern)
    );

    const domains = [...new Set(
      asArray(snapshot.cosmeticDisabledDomains).filter(
        domain =>
          typeof domain === 'string' &&
          domain.length > 0 &&
          !ignoredDomains.has(domain)
      )
    )];

    if (domains.length === 0) {
      renderEmptyState(
        container,
        'No standalone cosmetic-ad-hiding pauses.'
      );
      return;
    }

    const fragment = document.createDocumentFragment();

    for (const domain of domains) {
      const { item } = createListItem(
        domain,
        'Cosmetic only',
        'Re-enable',
        () => {
          reenableCosmetics(domain).catch(() => {});
        }
      );

      fragment.append(item);
    }

    container.replaceChildren(fragment);
  }

  async function reenableCosmetics(domain) {
    if (!settingsLoaded || rulesMutationPending) return;

    rulesMutationPending = true;
    renderSettings();

    try {
      await runChange(async () => {
        const values = await storage.local.get([
          'cosmeticDisabledDomains',
        ]);

        await storage.local.set({
          cosmeticDisabledDomains:
            asArray(values.cosmeticDisabledDomains).filter(
              candidate => candidate !== domain
            ),
        });
      }, 'Cosmetic ad-hiding re-enabled for that site.');
    } finally {
      rulesMutationPending = false;
      renderSettings();
    }
  }

  async function cleanupExpiredRules() {
    await enqueueMutation(async () => {
      const values = await storage.local.get(['ignoreRules']);
      const currentRules = asArray(values.ignoreRules);
      const validRules = currentRules.filter(isActiveRule);

      if (validRules.length !== currentRules.length) {
        await storage.local.set({ ignoreRules: validRules });
      }
    });
  }

  function handleStorageChange(changes, namespace) {
    if (namespace !== 'local') return;

    const relevantKeys = STORAGE_KEYS.filter(key =>
      Object.prototype.hasOwnProperty.call(changes, key)
    );

    if (relevantKeys.length === 0) return;

    storageRevision++;

    for (const key of relevantKeys) {
      const value = changes[key].newValue;

      if (value === undefined) {
        delete snapshot[key];
      } else {
        snapshot[key] = value;
      }
    }

    if (settingsLoaded) {
      renderSettings();
    }
  }

  async function refreshOnFocus() {
    try {
      await refreshSettings();
      await cleanupExpiredRules();
    } catch {
      showMessage(
        'Could not refresh settings. Reload this page to try again.',
        true
      );
    }
  }

  async function initialize() {
    const ids = [
      'themeToggle',
      'themeIcon',
      'themeText',
      'enableAutoScan',
      'bannerEnabled',
      'scanChanges',
      'modeLocal',
      'modeCloud',
      'modeStatus',
      'apiKeyForm',
      'customApiKey',
      'saveKeyBtn',
      'ignoreList',
      'cosmeticOnlyList',
      'statusMessage',
    ];

    ui = {};

    for (const id of ids) {
      const element = document.getElementById(id);

      if (!element) {
        console.error('[Dadblock Settings] Missing required element:', id);
        return;
      }

      ui[id] = element;
    }

    updateThemeUI();

    ui.themeToggle.addEventListener('click', () => {
      applyTheme(theme === 'dark' ? 'light' : 'dark');
      updateThemeUI();

      try {
        localStorage.setItem('dadblock-theme', theme);
      } catch {
        showMessage(
          'Theme changed for this page, but could not be saved.',
          true
        );
      }
    });

    window.addEventListener('storage', event => {
      if (event.key === 'dadblock-theme') {
        applyTheme(event.newValue);
        updateThemeUI();
      }
    });

    const extensionAPI = globalThis.chrome;

    if (
      !extensionAPI?.runtime?.id ||
      typeof extensionAPI.storage?.local?.get !== 'function' ||
      typeof extensionAPI.storage?.local?.set !== 'function' ||
      typeof extensionAPI.storage?.onChanged?.addListener !== 'function'
    ) {
      renderSettings();
      showMessage('Open this settings page from the Dadblock extension.', true);
      return;
    }

    storage = extensionAPI.storage;

    for (const config of TOGGLE_SETTINGS) {
      ui[config.id].addEventListener('change', event => {
        saveToggle(config, event.currentTarget.checked).catch(() => {});
      });
    }

    ui.modeLocal.addEventListener('click', () => {
      setMode('local').catch(() => {});
    });

    ui.modeCloud.addEventListener('click', () => {
      setMode('cloud').catch(() => {});
    });

    ui.customApiKey.addEventListener('input', () => {
      apiKeyDirty = true;
    });

    ui.apiKeyForm.addEventListener('submit', event => {
      saveCustomApiKey(event).catch(() => {});
    });

    // Subscribe before the initial read so updates cannot be missed.
    storage.onChanged.addListener(handleStorageChange);
    window.addEventListener('focus', refreshOnFocus);

    const versionDisplay = document.getElementById('version-display');

    if (versionDisplay) {
      versionDisplay.textContent =
        `Dadblock Version ${extensionAPI.runtime.getManifest().version}`;
    }

    try {
      await refreshSettings();
      await cleanupExpiredRules();
    } catch {
      showMessage(
        'Could not load settings. Reload this page to try again.',
        true
      );
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      initialize().catch(() => {
        showMessage('Could not initialize settings. Reload this page.', true);
      });
    }, { once: true });
  } else {
    initialize().catch(() => {
      showMessage('Could not initialize settings. Reload this page.', true);
    });
  }
})();