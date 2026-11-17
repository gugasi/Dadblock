// video-player-module.js
// Register this file in ISOLATED, not MAIN.
// Uses shared DOM access and authenticated chrome.storage pause settings.

(function () {
  'use strict';

  const GUARD = Symbol.for('dadblock.video.pause.v2');

  if (document[GUARD]) return;

  const extensionAPI = globalThis.chrome;

  if (
    !extensionAPI?.runtime?.id ||
    typeof extensionAPI.storage?.local?.get !== 'function' ||
    typeof extensionAPI.storage?.onChanged?.addListener !== 'function'
  ) {
    // Fail closed: never manipulate the player without its pause setting.
    console.warn(
      '[Dadblock] Video module inactive: register video-player-module.js ' +
      'in ISOLATED to access chrome.storage.'
    );
    return;
  }

  Object.defineProperty(document, GUARD, {
    value: true,
    configurable: false,
    enumerable: false,
    writable: false,
  });

  const storage = extensionAPI.storage;
  const hostname = window.location.hostname.toLowerCase();

  function hostnameMatches(host, domain) {
    return host === domain || host.endsWith('.' + domain);
  }

  const isYouTube = (
    hostnameMatches(hostname, 'youtube.com') ||
    hostnameMatches(hostname, 'googlevideo.com')
  );

  const isTwitch = hostnameMatches(hostname, 'twitch.tv');

  if (!isYouTube && !isTwitch) return;

  const SKIP_BUTTON_SELECTORS = [
    '.ytp-ad-skip-button-modern',
    '.ytp-ad-skip-button',
    '.ytp-skip-ad-button',
    '.ytp-ad-skip-button-container button',
  ];

  const YOUTUBE_OVERLAY_SELECTORS = [
    '.ytp-ad-overlay-container',
    '.ytp-ad-text-overlay',
    '.ytp-ad-image-overlay',
    '.ytp-ad-player-overlay-instream-info',
  ];

  const AD_FLAGS = ['ad-showing', 'ad-interrupting'];

  const nativeClick = HTMLElement.prototype.click;

  let settingsReady = false;
  let paused = true;
  let suspended = false;
  let running = false;

  let storageRevision = 0;
  let engineGeneration = 0;

  let discoveryObserver = null;
  let playerObserver = null;

  let playerElement = null;
  let videoElement = null;
  let videoTimeUpdateListener = null;

  let discoveryTimer = null;
  let navigationTimer = null;

  let readyListener = null;
  let lastSkipAt = 0;
  let skipInProgress = false;

  const pendingTimers = new Set();
  const hiddenElements = new Map();

  function canRun() {
    return (
      settingsReady &&
      !paused &&
      !suspended &&
      running &&
      Boolean(extensionAPI.runtime?.id)
    );
  }

  function schedule(callback, delay) {
    if (!canRun()) return null;

    const generation = engineGeneration;

    const timer = window.setTimeout(() => {
      pendingTimers.delete(timer);

      if (
        generation !== engineGeneration ||
        !canRun()
      ) {
        return;
      }

      callback();
    }, delay);

    pendingTimers.add(timer);
    return timer;
  }

  function cancelTimer(timer) {
    if (timer === null) return;

    window.clearTimeout(timer);
    pendingTimers.delete(timer);
  }

  function restoreHiddenElements() {
    for (const [element, original] of hiddenElements) {
      try {
        // Do not overwrite a later style change made by the site.
        if (
          element.style.getPropertyValue('display') === 'none' &&
          element.style.getPropertyPriority('display') === 'important'
        ) {
          if (original.value) {
            element.style.setProperty(
              'display',
              original.value,
              original.priority
            );
          } else {
            element.style.removeProperty('display');
          }
        }
      } catch {
        // Detached or inaccessible nodes do not block cleanup.
      }
    }

    hiddenElements.clear();
  }

  function hideOverlay(element) {
    if (
      !canRun() ||
      !element?.isConnected ||
      hiddenElements.has(element)
    ) {
      return;
    }

    const value = element.style.getPropertyValue('display');
    const priority = element.style.getPropertyPriority('display');

    // Do not claim ownership of a style already supplied by the site.
    if (value === 'none') return;

    hiddenElements.set(element, { value, priority });

    element.style.setProperty('display', 'none', 'important');
  }

  function detachPlayer() {
    playerObserver?.disconnect();
    playerObserver = null;

    if (videoElement && videoTimeUpdateListener) {
      videoElement.removeEventListener(
        'timeupdate',
        videoTimeUpdateListener
      );
    }

    playerElement = null;
    videoElement = null;
    videoTimeUpdateListener = null;
    lastSkipAt = 0;
  }

  function stopEngine() {
    running = false;
    engineGeneration++;

    discoveryObserver?.disconnect();
    discoveryObserver = null;

    detachPlayer();

    for (const timer of pendingTimers) {
      window.clearTimeout(timer);
    }

    pendingTimers.clear();
    discoveryTimer = null;
    navigationTimer = null;

    if (readyListener) {
      document.removeEventListener(
        'DOMContentLoaded',
        readyListener
      );
      readyListener = null;
    }

    window.removeEventListener(
      'yt-navigate-finish',
      handleYouTubeNavigation
    );

    skipInProgress = false;

    // Undo only overlay styles owned by this module.
    restoreHiddenElements();
  }

  function hasYouTubeAd(player) {
    return (
      player?.isConnected &&
      AD_FLAGS.some(flag => player.classList.contains(flag))
    );
  }

  function isVisibleButton(button) {
    if (!(button instanceof HTMLElement)) return false;

    if (
      button.hasAttribute('disabled') ||
      button.getAttribute('aria-disabled') === 'true'
    ) {
      return false;
    }

    const style = window.getComputedStyle(button);
    const rect = button.getBoundingClientRect();

    return (
      style.display !== 'none' &&
      style.visibility !== 'hidden' &&
      style.opacity !== '0' &&
      rect.width > 0 &&
      rect.height > 0
    );
  }

  function skipCurrentYouTubeAd(player) {
    if (
      !canRun() ||
      player !== playerElement ||
      !hasYouTubeAd(player) ||
      skipInProgress
    ) {
      return;
    }

    const timestamp = Date.now();

    if (timestamp - lastSkipAt < 250) return;

    lastSkipAt = timestamp;
    skipInProgress = true;

    try {
      for (const selector of SKIP_BUTTON_SELECTORS) {
        const button = player.querySelector(selector);

        if (!isVisibleButton(button)) continue;

        if (!canRun() || !hasYouTubeAd(player)) return;

        try {
          Reflect.apply(nativeClick, button, []);
          return;
        } catch {
          // Continue with the bounded fallback below.
        }
      }

      const video = player.querySelector('video');

      // Seek only while explicit ad flags are present, and never seek a
      // live stream or an unbounded/long media item.
      if (
        canRun() &&
        hasYouTubeAd(player) &&
        video instanceof HTMLMediaElement &&
        video.readyState > 0 &&
        Number.isFinite(video.duration) &&
        video.duration > 0.5 &&
        video.duration <= 300 &&
        video.seekable.length > 0 &&
        !video.ended
      ) {
        const end = Math.max(0, video.duration - 0.05);

        let seekable = false;

        for (let index = 0; index < video.seekable.length; index++) {
          if (
            end >= video.seekable.start(index) &&
            end <= video.seekable.end(index)
          ) {
            seekable = true;
            break;
          }
        }

        if (
          seekable &&
          video.currentTime < end &&
          canRun() &&
          hasYouTubeAd(player)
        ) {
          try {
            video.currentTime = end;
          } catch {
            // Some player states temporarily disallow seeking.
          }
        }
      }

      for (const selector of YOUTUBE_OVERLAY_SELECTORS) {
        if (!canRun() || !hasYouTubeAd(player)) break;

        for (const overlay of player.querySelectorAll(selector)) {
          hideOverlay(overlay);
        }
      }
    } finally {
      skipInProgress = false;
    }
  }

  function evaluateYouTubePlayer() {
    if (!canRun() || !playerElement?.isConnected) return;

    if (hasYouTubeAd(playerElement)) {
      skipCurrentYouTubeAd(playerElement);
    } else {
      restoreHiddenElements();
    }
  }

  function bindYouTubeVideo(player) {
    const video = player.querySelector('video');

    if (video === videoElement) return;

    if (videoElement && videoTimeUpdateListener) {
      videoElement.removeEventListener(
        'timeupdate',
        videoTimeUpdateListener
      );
    }

    videoElement = video;
    videoTimeUpdateListener = null;

    if (!(video instanceof HTMLMediaElement)) return;

    videoTimeUpdateListener = () => {
      if (canRun()) evaluateYouTubePlayer();
    };

    video.addEventListener(
      'timeupdate',
      videoTimeUpdateListener,
      { passive: true }
    );
  }

  function findAndAttachYouTubePlayer() {
    if (!canRun()) return;

    const player = document.querySelector(
      '#movie_player, .html5-video-player'
    );

    if (!player) {
      if (playerElement) {
        detachPlayer();
        restoreHiddenElements();
      }
      return;
    }

    if (player !== playerElement) {
      detachPlayer();
      restoreHiddenElements();

      playerElement = player;

      playerObserver = new MutationObserver(() => {
        if (canRun()) evaluateYouTubePlayer();
      });

      playerObserver.observe(player, {
        attributes: true,
        attributeFilter: ['class'],
      });
    }

    bindYouTubeVideo(player);
    evaluateYouTubePlayer();
  }

  function evaluateTwitchPlayer() {
    if (!canRun()) return;

    const root = document.querySelector(
      '.video-player__container'
    );

    if (!root) {
      restoreHiddenElements();
      return;
    }

    const adNotice = root.querySelector(
      '[data-test-selector="ad-banner-default-text"], ' +
      '[data-a-target="video-ad-label"]'
    );

    const video = root.querySelector('video');

    if (!adNotice || !video) {
      restoreHiddenElements();
      return;
    }

    for (const banner of root.querySelectorAll(
      '.player-ad-notice'
    )) {
      hideOverlay(banner);
    }

    // Preserve the user's mute, volume, playback rate, and playback state.
    // Twitch server-side ad insertion is not treated as seekable media.
  }

  function evaluateCurrentPlayer() {
    if (!canRun()) return;

    if (isYouTube) {
      findAndAttachYouTubePlayer();
    } else if (isTwitch) {
      evaluateTwitchPlayer();
    }
  }

  function scheduleDiscovery() {
    if (!canRun() || discoveryTimer !== null) return;

    discoveryTimer = schedule(() => {
      discoveryTimer = null;
      evaluateCurrentPlayer();
    }, 120);
  }

  function attachDiscoveryObserver() {
    if (!canRun()) return;

    const root = document.documentElement;

    if (!root) {
      discoveryTimer = schedule(() => {
        discoveryTimer = null;
        attachDiscoveryObserver();
      }, 50);
      return;
    }

    discoveryObserver?.disconnect();

    discoveryObserver = new MutationObserver(() => {
      if (canRun()) scheduleDiscovery();
    });

    discoveryObserver.observe(root, {
      childList: true,
      subtree: true,
    });

    evaluateCurrentPlayer();
  }

  function handleYouTubeNavigation() {
    if (!canRun()) return;

    cancelTimer(navigationTimer);

    navigationTimer = schedule(() => {
      navigationTimer = null;

      detachPlayer();
      restoreHiddenElements();
      findAndAttachYouTubePlayer();
    }, 700);
  }

  function startEngine() {
    if (
      running ||
      !settingsReady ||
      paused ||
      suspended ||
      !extensionAPI.runtime?.id
    ) {
      return;
    }

    running = true;
    engineGeneration++;

    if (isYouTube) {
      window.addEventListener(
        'yt-navigate-finish',
        handleYouTubeNavigation
      );
    }

    attachDiscoveryObserver();

    if (document.readyState === 'loading') {
      readyListener = () => {
        readyListener = null;

        if (canRun()) {
          attachDiscoveryObserver();
        }
      };

      document.addEventListener(
        'DOMContentLoaded',
        readyListener,
        { once: true }
      );
    }
  }

  function applyPauseDomains(value) {
    if (value !== undefined && !Array.isArray(value)) {
      settingsReady = false;
      paused = true;
      stopEngine();
      return;
    }

    const domains = value || [];

    paused = domains.some(entry => {
      if (typeof entry !== 'string') return false;

      const domain = entry.trim().toLowerCase().replace(/\.$/, '');

      return domain !== '' && hostnameMatches(hostname, domain);
    });

    settingsReady = true;

    if (paused || suspended) {
      stopEngine();
    } else {
      startEngine();
    }
  }

  async function readPauseState() {
    const revision = storageRevision;

    try {
      const values = await storage.local.get([
        'adBlockDisabledDomains',
      ]);

      // A newer storage event already supplied the authoritative list.
      if (revision !== storageRevision) return;

      applyPauseDomains(values.adBlockDisabledDomains);
    } catch {
      if (revision !== storageRevision) return;

      settingsReady = false;
      paused = true;
      stopEngine();
    }
  }

  function handleStorageChange(changes, namespace) {
    if (
      namespace !== 'local' ||
      !Object.prototype.hasOwnProperty.call(
        changes,
        'adBlockDisabledDomains'
      )
    ) {
      return;
    }

    storageRevision++;

    // A pause event stops observers, callbacks, timers, and manipulation
    // synchronously, rather than waiting for another polling cycle.
    applyPauseDomains(
      changes.adBlockDisabledDomains.newValue
    );
  }

  storage.onChanged.addListener(handleStorageChange);

  window.addEventListener('pagehide', () => {
    suspended = true;
    stopEngine();
  });

  window.addEventListener('pageshow', event => {
    if (!event.persisted) return;

    suspended = false;
    settingsReady = false;
    paused = true;

    stopEngine();
    readPauseState().catch(() => {});
  });

  // No observer, skip operation, seek, or overlay modification starts
  // until the initial pause setting has successfully resolved.
  readPauseState().catch(() => {});
})();