// behavior-probe.js
// MAIN world, document_start, top frame only.
//
// Counts sensitive browser features that the page calls: notification
// prompts, location, camera/microphone/screen, and clipboard use. Calls
// are passed through unchanged; this only records that they happened.
// Counts live in one data attribute that report-collector.js reads.

(function () {
  'use strict';

  const GUARD = Symbol.for('dadblock.behaviorProbe.v1');

  try {
    if (window[GUARD]) return;
    Object.defineProperty(window, GUARD, { value: true });
  } catch {
    return;
  }

  const ATTRIBUTE = 'data-dadblock-sig';
  const apply = Reflect.apply;

  function bump(key) {
    try {
      const root = document.documentElement;
      if (!root) return;

      let state = {};

      try {
        state = JSON.parse(root.getAttribute(ATTRIBUTE) || '{}') || {};
      } catch {
        state = {};
      }

      state[key] = (Number(state[key]) || 0) + 1;
      root.setAttribute(ATTRIBUTE, JSON.stringify(state));
    } catch {
      // Recording must never affect the page.
    }
  }

  function wrap(target, name, key, predicate) {
    try {
      if (!target) return;

      const descriptor = Object.getOwnPropertyDescriptor(target, name);

      if (
        !descriptor ||
        typeof descriptor.value !== 'function' ||
        !descriptor.configurable
      ) {
        return;
      }

      const original = descriptor.value;

      const wrapped = function (...args) {
        try {
          if (!predicate || predicate(args)) bump(key);
        } catch {
          // Ignore recording failures.
        }

        return apply(original, this, args);
      };

      try {
        Object.defineProperty(wrapped, 'name', {
          value: name,
          configurable: true,
        });
      } catch {
        // Cosmetic only.
      }

      Object.defineProperty(target, name, {
        ...descriptor,
        value: wrapped,
      });
    } catch {
      // Never break the page if a hook cannot be installed.
    }
  }

  // n: notification prompt, g: location, c: clipboard read,
  // w: clipboard write/copy.
  wrap(window.Notification, 'requestPermission', 'n');
  wrap(window.Geolocation?.prototype, 'getCurrentPosition', 'g');
  wrap(window.Geolocation?.prototype, 'watchPosition', 'g');
  wrap(window.Clipboard?.prototype, 'readText', 'c');
  wrap(window.Clipboard?.prototype, 'read', 'c');
  wrap(window.Clipboard?.prototype, 'writeText', 'w');
  wrap(window.Clipboard?.prototype, 'write', 'w');
  // Camera, microphone and screen capture are deliberately NOT wrapped:
  // video-call and recording tools depend on those calls behaving exactly
  // like the browser's own, and Chrome already shows its own indicator.

  wrap(
    window.Document?.prototype,
    'execCommand',
    'w',
    args => /^(?:copy|cut)$/i.test(String(args[0]))
  );
})();
