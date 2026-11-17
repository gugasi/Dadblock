// injected.js
// Registered in MAIN at document_start, in all matching frames.
//
// Blocks unsolicited popup destinations and empty viewport click traps.
// Payment and authentication exceptions require a real user interaction
// and a relevant flow context. Allowed calls return the native WindowProxy.

(function () {
  'use strict';

  const GUARD = Symbol.for('dadblock.popunder.v4');
  const apply = Reflect.apply;
  const now = Date.now.bind(Date);
  const NativeError = Error;

  const INTERACTION_WINDOW_MS = 1000;
  const FLOW_WINDOW_MS = 30000;
  const MAX_NAMED_WINDOWS = 8;

  const AD_DOMAINS = [
    'popads.net',
    'popcash.net',
    'propellerads.com',
    'adsterra.com',
    'exoclick.com',
    'exosrv.com',
    'onclickads.net',
    'onclickalgo.com',
    'onclickmega.com',
    'highperformancegate.com',
    'highperformanceformat.com',
    'profitableratecpm.com',
    'effectivegatecpm.com',
  ];

  const PROVIDER_DOMAINS = [
    'accounts.google.com',
    'github.com',
    'facebook.com',
    'microsoftonline.com',
    'login.microsoft.com',
    'login.live.com',
    'okta.com',
    'auth0.com',
    'appleid.apple.com',
    'account.apple.com',
    'paypal.com',
    'stripe.com',
    'stripe.network',
    'adyen.com',
    'adyenpayments.com',
    'braintreegateway.com',
    'braintreepayments.com',
    'pay.google.com',
    'payments.google.com',
    'wallet.google.com',
    'pay.amazon.com',
  ];

  // Caller matching is a compatibility signal, not sender authentication.
  // It is combined with user interaction and a bounded flow window.
  const PROVIDER_SCRIPT_DOMAINS = [
    'paypal.com',
    'paypalobjects.com',
    'js.stripe.com',
    'checkout.stripe.com',
    'js.braintreegateway.com',
    'braintreepayments.com',
    'checkoutshopper-live.adyen.com',
    'checkoutshopper-test.adyen.com',
    'js.adyen.com',
    'accounts.google.com',
    'apis.google.com',
    'cdn.auth0.com',
    'auth0.com',
    'okta.com',
    'alcdn.msauth.net',
    'alcdn.msftauth.net',
    'connect.facebook.net',
    'facebook.net',
    'appleid.cdn-apple.com',
  ];

  const PLAYER_SELECTOR = [
    'video',
    'audio',
    '.jwplayer',
    '.plyr',
    '.video-js',
    '.html5-video-player',
    '[data-player]',
  ].join(',');

  const PROTECTED_REGION_SELECTOR = [
    PLAYER_SELECTOR,
    'form',
    'dialog',
    '[role="dialog"]',
    '[aria-modal="true"]',
    '[aria-busy="true"]',
    '[role="progressbar"]',
    '[id^="db-guard-"]',
  ].join(',');

  const CONTROL_SELECTOR = [
    'a[href]',
    'button',
    'input[type="submit"]',
    'input[type="button"]',
    '[role="button"]',
    '[role="link"]',
  ].join(',');

  const MEANINGFUL_CONTENT_SELECTOR = [
    'img',
    'svg',
    'canvas',
    'video',
    'audio',
    'iframe',
    'form',
    'input',
    'button',
    'select',
    'textarea',
    'a[href]',
    '[contenteditable]',
    'dialog',
    '[role="button"]',
    '[role="link"]',
    '[role="dialog"]',
    '[aria-modal="true"]',
    '[aria-busy="true"]',
    '[role="progressbar"]',
  ].join(',');

  const FLOW_CONTROL_PATTERN =
    /(?:^|[\s_-])(?:checkout|pay|payment|paypal|stripe|purchase|sign[\s_-]*in|log[\s_-]*in|oauth|authorize|authenticate|connect[\s_-]*account)(?:$|[\s_-])/i;

  const EXPORT_CONTROL_PATTERN =
    /\b(?:download|export|print|save[\s_-]*(?:file|pdf|report))\b/i;

  function hostnameMatches(hostname, domain) {
    const host = String(hostname || '').toLowerCase();
    return host === domain || host.endsWith('.' + domain);
  }

  function matchesDomains(hostname, domains) {
    return domains.some(domain => hostnameMatches(hostname, domain));
  }

  function closest(element, selector) {
    try {
      return element?.closest(selector) || null;
    } catch {
      return null;
    }
  }

  function installRealm(win) {
    let doc;

    try {
      doc = win.document;
      if (!doc || doc[GUARD]) return;
    } catch {
      // Cross-origin frames receive their own registered content script.
      return;
    }

    const nativeOpen = win.open;
    const nativeConfirm = win.confirm;
    const nativeSetTimeout = win.setTimeout.bind(win);

    if (typeof nativeOpen !== 'function') return;

    try {
      Object.defineProperty(doc, GUARD, {
        value: true,
        configurable: false,
        enumerable: false,
        writable: false,
      });
    } catch {
      return;
    }

    let active = true;
    let lastInteraction = null;
    let lastFlow = null;
    let lastBlockedAt = 0;
    let lastWarningAt = 0;

    const armedFrames = new WeakSet();
    const permittedNamedWindows = new Map();

    function parseURL(value) {
      try {
        return new win.URL(value, doc.baseURI);
      } catch {
        return null;
      }
    }

    function pageHref() {
      try {
        return win.location.href;
      } catch {
        return '';
      }
    }

    function currentPageURL() {
      try {
        return new win.URL(win.location.href);
      } catch {
        return null;
      }
    }

    function currentHostname() {
      try {
        if (win.location.hostname) {
          return win.location.hostname.toLowerCase();
        }

        // A page-controlled <base> element does not establish site identity.
        // Only a readable same-origin parent supplies inherited context.
        if (
          win.location.protocol === 'about:' &&
          win.parent !== win
        ) {
          return win.parent.location.hostname.toLowerCase();
        }
      } catch {
        // Opaque frames have no readable parent hostname.
      }

      return '';
    }

    function sameSiteDestination(destination) {
      const host = currentHostname();

      return Boolean(
        host &&
        destination?.hostname &&
        hostnameMatches(destination.hostname, host)
      );
    }

    function isProviderDocument() {
      const url = currentPageURL();

      return Boolean(
        url?.protocol === 'https:' &&
        matchesDomains(url.hostname, PROVIDER_DOMAINS)
      );
    }

    // Sign-in windows to the real identity providers. Sites often bundle
    // the provider's SDK into their own scripts, or open the window after
    // the click happened inside the provider's embedded button, so neither
    // the caller nor the last click identifies the flow. Chrome itself only
    // lets a window open while the user's click is still active, so that
    // activation is the safeguard. Only the providers' own sign-in URLs
    // qualify, never their general pages.
    const IDENTITY_LOGIN_ENDPOINTS = [
      { domains: ['accounts.google.com'], path: /./ },
      { domains: ['appleid.apple.com'], path: /./ },
      {
        domains: [
          'login.microsoftonline.com',
          'login.microsoft.com',
          'login.live.com',
        ],
        path: /./,
      },
      { domains: ['github.com'], path: /^\/login\/oauth\b/ },
      {
        domains: ['facebook.com'],
        path: /^\/(?:v\d+(?:\.\d+)?\/)?dialog\/oauth\b|^\/login\b|^\/dialog\//,
      },
      { domains: ['okta.com', 'auth0.com'], path: /./ },
    ];

    function identityProviderLogin(destination) {
      try {
        if (
          !destination ||
          destination.protocol !== 'https:' ||
          !nativeActivationAvailable()
        ) {
          return false;
        }

        return IDENTITY_LOGIN_ENDPOINTS.some(
          entry =>
            matchesDomains(destination.hostname, entry.domains) &&
            entry.path.test(destination.pathname)
        );
      } catch {
        return false;
      }
    }

    function isRecognizedCheckoutRoute() {
      const url = currentPageURL();

      // Compatibility scope for the observed Roblox checkout.
      // Other Roblox pages do not receive this exception.
      return Boolean(
        url?.protocol === 'https:' &&
        hostnameMatches(url.hostname, 'roblox.com') &&
        /^\/upgrades\/paymentmethods\/?$/.test(url.pathname)
      );
    }

    function nativeActivationAvailable() {
      try {
        return active && win.navigator.userActivation?.isActive === true;
      } catch {
        return false;
      }
    }

    function eventElement(event) {
      try {
        for (const node of event.composedPath()) {
          if (node?.nodeType === 1) return node;
        }
      } catch {
        // Fall back to event.target.
      }

      return event.target?.nodeType === 1
        ? event.target
        : event.target?.parentElement || null;
    }

    function visibleControl(element) {
      if (!element?.isConnected) return false;

      try {
        const rect = element.getBoundingClientRect();

        if (
          rect.width <= 0 ||
          rect.height <= 0 ||
          rect.right <= 0 ||
          rect.bottom <= 0 ||
          rect.left >= win.innerWidth ||
          rect.top >= win.innerHeight
        ) {
          return false;
        }

        for (
          let node = element;
          node && node.nodeType === 1;
          node = node.parentElement
        ) {
          const style = win.getComputedStyle(node);
          const opacity = Number.parseFloat(style.opacity);

          if (
            style.display === 'none' ||
            style.visibility === 'hidden' ||
            style.visibility === 'collapse' ||
            (Number.isFinite(opacity) && opacity <= 0.05)
          ) {
            return false;
          }
        }

        return true;
      } catch {
        return false;
      }
    }

    function controlMetadata(control) {
      if (!control) return '';

      // Input values and payment fields are never inspected.
      return [
        control.getAttribute('aria-label') || '',
        control.getAttribute('title') || '',
        control.getAttribute('id') || '',
        control.getAttribute('class') || '',
        control.getAttribute('data-testid') || '',
        control.tagName !== 'INPUT'
          ? (control.textContent || '').slice(0, 160)
          : '',
      ].join(' ').slice(0, 600);
    }

    function isTransparent(color) {
      return (
        color === 'transparent' ||
        /rgba\([^)]*,\s*0(?:\.0+)?\s*\)/i.test(color)
      );
    }

    function isLegitimateBackdrop(element) {
      const metadata = [
        element.getAttribute('id') || '',
        element.getAttribute('class') || '',
      ].join(' ');

      if (
        !/(?:^|[\s_-])(?:backdrop|scrim|modal|dialog)(?:$|[\s_-])/i
          .test(metadata)
      ) {
        return false;
      }

      try {
        return Array.from(doc.querySelectorAll(
          'dialog[open], [role="dialog"], [aria-modal="true"]'
        )).some(visibleControl);
      } catch {
        return false;
      }
    }

    // Whiteboards, design tools, maps and games draw on a full-screen
    // transparent canvas or event layer. That is an app surface, not an
    // ad click-trap, and switching its mouse input off breaks the app.
    const APP_SURFACE_SELECTOR = 'canvas, video, svg, object, embed';
    const APP_CURSOR =
      /^(?:crosshair|grab|grabbing|move|text|vertical-text|cell|copy|alias|zoom-in|zoom-out|all-scroll|col-resize|row-resize|[nsew]{1,2}-resize|nesw-resize|nwse-resize|url\()/i;
    const WORKSPACE_HOST =
      /(?:^|\.)(?:miro\.com|figma\.com|canva\.com|notion\.so|lucid\.app|lucidchart\.com|whimsical\.com|excalidraw\.com|tldraw\.com|diagrams\.net|draw\.io|mural\.co|overleaf\.com|airtable\.com|trello\.com|asana\.com|clickup\.com|office\.com|office365\.com|officeapps\.live\.com|onedrive\.live\.com|sharepoint\.com|github\.dev)$/i;

    let largeCanvasCheck = { at: 0, value: false };

    function pageHasLargeCanvas() {
      const now = Date.now();

      if (now - largeCanvasCheck.at < 3000) return largeCanvasCheck.value;

      largeCanvasCheck = { at: now, value: false };

      try {
        const area = win.innerWidth * win.innerHeight;

        for (const canvas of doc.querySelectorAll('canvas')) {
          const box = canvas.getBoundingClientRect();

          if (box.width * box.height >= area * 0.4) {
            largeCanvasCheck.value = true;
            break;
          }
        }
      } catch {
        // Treat as "no large canvas".
      }

      return largeCanvasCheck.value;
    }

    function isAppSurface(element, style) {
      try {
        if (
          element.matches(APP_SURFACE_SELECTOR) ||
          element.querySelector(APP_SURFACE_SELECTOR)
        ) {
          return true;
        }

        if (APP_CURSOR.test(style.cursor || '')) return true;

        if (
          element.hasAttribute('role') ||
          element.hasAttribute('tabindex') ||
          element.hasAttribute('contenteditable') ||
          element.hasAttribute('aria-label')
        ) {
          return true;
        }

        return (
          WORKSPACE_HOST.test(win.location.hostname || '') ||
          pageHasLargeCanvas()
        );
      } catch {
        return false;
      }
    }

    function isAbusiveOverlay(element) {
      if (
        !element?.isConnected ||
        element === doc.documentElement ||
        element === doc.body ||
        closest(element, PROTECTED_REGION_SELECTOR)
      ) {
        return false;
      }

      try {
        const style = win.getComputedStyle(element);

        if (
          style.display === 'none' ||
          style.visibility === 'hidden' ||
          style.pointerEvents === 'none' ||
          (
            style.position !== 'fixed' &&
            style.position !== 'absolute'
          )
        ) {
          return false;
        }

        if (isAppSurface(element, style)) return false;

        // Transparency alone is not sufficient: ordinary layouts,
        // loading containers and product regions can be transparent.
        if (
          (element.textContent || '').trim() ||
          element.querySelector(MEANINGFUL_CONTENT_SELECTOR) ||
          (
            style.backgroundImage &&
            style.backgroundImage !== 'none'
          ) ||
          isLegitimateBackdrop(element)
        ) {
          return false;
        }

        const rect = element.getBoundingClientRect();
        const viewportWidth = win.innerWidth;
        const viewportHeight = win.innerHeight;

        if (viewportWidth <= 0 || viewportHeight <= 0) return false;

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
          isTransparent(style.backgroundColor)
        );
      } catch {
        return false;
      }
    }

    function findOverlay(element) {
      let candidate = element;

      while (
        candidate &&
        candidate !== doc.body &&
        candidate !== doc.documentElement
      ) {
        if (isAbusiveOverlay(candidate)) return candidate;
        candidate = candidate.parentElement;
      }

      return null;
    }

    function sameInteractionTarget(previous, element, control) {
      if (!previous) return false;

      if (previous.control && control) {
        return previous.control === control;
      }

      return previous.element === element;
    }

    function recordInteraction(event) {
      if (!active || !event.isTrusted) return;

      if (
        event.type === 'keydown' &&
        event.key !== 'Enter' &&
        event.key !== ' ' &&
        event.key !== 'Spacebar'
      ) {
        return;
      }

      const element = eventElement(event);
      const overlay = findOverlay(element);
      const control = closest(element, CONTROL_SELECTOR);
      const timestamp = now();
      const previous = lastInteraction;

      const startsInteraction = (
        event.type === 'pointerdown' ||
        event.type === 'touchstart' ||
        event.type === 'keydown'
      );

      // pointerdown, mousedown and click can belong to the same physical
      // interaction. Preserve its consumed-window flag across those events.
      const continuesInteraction = Boolean(
        !startsInteraction &&
        previous &&
        timestamp - previous.timestamp <= 800 &&
        previous.pageHref === pageHref() &&
        sameInteractionTarget(previous, element, control)
      );

      const controlVisible = !overlay && visibleControl(control);

      let intendedURL = null;

      if (controlVisible && control.tagName === 'A') {
        intendedURL = parseURL(control.getAttribute('href') || '');
      }

      const flow = Boolean(
        !overlay &&
        (
          (
            controlVisible &&
            FLOW_CONTROL_PATTERN.test(controlMetadata(control))
          ) ||
          (
            isProviderDocument() &&
            visibleControl(element)
          )
        )
      );

      const interaction = {
        timestamp,
        pageHref: pageHref(),
        element,
        control,
        intendedHref: intendedURL?.href || '',
        flow,
        overlay: Boolean(overlay),
        popupUsed: continuesInteraction
          ? previous.popupUsed
          : false,
        clickEvent: (
          event.type === 'click' ||
          event.type === 'auxclick'
        )
          ? event
          : null,
      };

      lastInteraction = interaction;

      if (flow) {
        lastFlow = interaction;
      } else if (!continuesInteraction) {
        lastFlow = null;
      }
    }

    function recentInteraction() {
      return Boolean(
        active &&
        lastInteraction &&
        !lastInteraction.overlay &&
        lastInteraction.pageHref === pageHref() &&
        now() - lastInteraction.timestamp <= INTERACTION_WINDOW_MS
      );
    }

    function currentFlow() {
      if (
        !active ||
        !lastFlow ||
        lastFlow.overlay ||
        !lastFlow.flow ||
        lastFlow.pageHref !== pageHref() ||
        now() - lastFlow.timestamp > FLOW_WINDOW_MS
      ) {
        return null;
      }

      return lastFlow;
    }

    function explicitDestination(destination) {
      return Boolean(
        recentInteraction() &&
        destination &&
        lastInteraction.intendedHref === destination.href &&
        visibleControl(lastInteraction.control)
      );
    }

    function callerMatches(domains) {
      try {
        const stack = new NativeError().stack || '';
        const sources = stack.match(/https?:\/\/[^\s)<>"']+/g) || [];

        return sources.some(source => {
          const url = parseURL(source.replace(/:\d+(?::\d+)?$/, ''));

          return (
            url?.protocol === 'https:' &&
            matchesDomains(url.hostname, domains)
          );
        });
      } catch {
        return false;
      }
    }

    function recognizedAdCaller() {
      try {
        const stack = new NativeError().stack || '';
        const sources = stack.match(/https?:\/\/[^\s)<>"']+/g) || [];

        return sources.some(source => {
          const url = parseURL(source.replace(/:\d+(?::\d+)?$/, ''));
          return url && matchesDomains(url.hostname, AD_DOMAINS);
        });
      } catch {
        return false;
      }
    }

    function providerContextAuthorized(flow, providerCaller) {
      if (
        lastInteraction?.overlay &&
        lastInteraction.pageHref === pageHref() &&
        now() - lastInteraction.timestamp <= INTERACTION_WINDOW_MS
      ) {
        return false;
      }

      if (flow) return true;

      // Activation can propagate from a payment iframe to its parent
      // without the iframe's DOM click bubbling into the parent.
      return Boolean(
        nativeActivationAvailable() &&
        (
          isProviderDocument() ||
          providerCaller ||
          isRecognizedCheckoutRoute()
        )
      );
    }

    function blankContextAuthorized(flow, providerCaller) {
      if (!providerContextAuthorized(flow, providerCaller)) {
        return false;
      }

      // A generic page click or a button merely labelled "checkout"
      // does not authorize an arbitrary redirectable blank window.
      return (
        isProviderDocument() ||
        providerCaller ||
        isRecognizedCheckoutRoute()
      );
    }

    function existingNamedWindow(target) {
      if (
        !target ||
        ['_blank', '_self', '_parent', '_top']
          .includes(target.toLowerCase())
      ) {
        return null;
      }

      const entry = permittedNamedWindows.get(target);

      if (
        !entry ||
        entry.pageHref !== pageHref() ||
        now() - entry.timestamp > FLOW_WINDOW_MS
      ) {
        permittedNamedWindows.delete(target);
        return null;
      }

      try {
        if (entry.window.closed) {
          permittedNamedWindows.delete(target);
          return null;
        }
      } catch {
        permittedNamedWindows.delete(target);
        return null;
      }

      return entry;
    }

    function rememberNamedWindow(target, openedWindow) {
      if (
        !openedWindow ||
        !target ||
        ['_blank', '_self', '_parent', '_top']
          .includes(target.toLowerCase())
      ) {
        return;
      }

      if (
        permittedNamedWindows.size >= MAX_NAMED_WINDOWS &&
        !permittedNamedWindows.has(target)
      ) {
        const oldest = permittedNamedWindows.keys().next().value;
        permittedNamedWindows.delete(oldest);
      }

      permittedNamedWindows.set(target, {
        window: openedWindow,
        pageHref: pageHref(),
        timestamp: now(),
      });
    }

    function consumeWindowGrant(flow) {
      if (recentInteraction()) {
        lastInteraction.popupUsed = true;
      }

      if (flow) {
        flow.popupUsed = true;
      }
    }

    function preventDuplicateAnchorNavigation(destination) {
      const event = lastInteraction?.clickEvent;
      const anchor = lastInteraction?.control;

      if (
        !event ||
        !event.cancelable ||
        anchor?.tagName !== 'A' ||
        !destination ||
        lastInteraction.intendedHref !== destination.href
      ) {
        return;
      }

      const baseTarget = doc.querySelector('base[target]')
        ?.getAttribute('target') || '';

      const target = (
        anchor.getAttribute('target') || baseTarget || '_self'
      ).toLowerCase();

      if (!['_self', '_parent', '_top'].includes(target)) {
        // The script has opened the intended destination. Avoid an
        // additional browser-default tab for the same anchor click.
        event.preventDefault();
      }
    }

    function blockPopup(reason, destination) {
      const timestamp = now();
      lastBlockedAt = timestamp;

      // Counted for Dad's report (read by report-collector.js).
      try {
        const root = win.document && win.document.documentElement;

        if (root) {
          let state = {};

          try {
            state = JSON.parse(
              root.getAttribute('data-dadblock-sig') || '{}'
            ) || {};
          } catch {
            state = {};
          }

          state.p = (Number(state.p) || 0) + 1;

          try {
            state.pr = String(reason || '').slice(0, 80);
            state.pd = destination && destination.hostname
              ? String(destination.hostname).slice(0, 80)
              : '';
          } catch {
            // Diagnostics only.
          }
          root.setAttribute('data-dadblock-sig', JSON.stringify(state));
        }
      } catch {
        // Counting must never affect blocking.
      }

      if (timestamp - lastWarningAt >= 1000) {
        lastWarningAt = timestamp;

        console.warn(
          '[Dadblock] Blocked pop-under:',
          reason,
          destination?.hostname || '(blank or unsupported destination)'
        );
      }

      return null;
    }

    // Counts and a hostname only, never page content. Read by
    // report-collector.js for Dad's report.
    function recordSignal(countKey, valueKey, value) {
      try {
        const root = win.document && win.document.documentElement;

        if (!root) return;

        let state = {};

        try {
          state = JSON.parse(
            root.getAttribute('data-dadblock-sig') || '{}'
          ) || {};
        } catch {
          state = {};
        }

        state[countKey] = (Number(state[countKey]) || 0) + 1;

        if (valueKey && value) {
          state[valueKey] = String(value).slice(0, 80);
        }

        root.setAttribute('data-dadblock-sig', JSON.stringify(state));
      } catch {
        // Recording must never affect the page.
      }
    }

    function installHook(name, replacement) {
      try {
        const descriptor = Object.getOwnPropertyDescriptor(win, name);

        if (descriptor && !descriptor.configurable) {
          if ('value' in descriptor && descriptor.writable) {
            Reflect.set(win, name, replacement);
          }

          return;
        }

        Object.defineProperty(win, name, {
          configurable: true,
          enumerable: descriptor?.enumerable ?? true,
          writable: true,
          value: replacement,
        });
      } catch {
        console.warn('[Dadblock] Could not install hook:', name);
      }
    }

    installHook('open', function dadblockOpen(...args) {
      const rawURL = args[0] === undefined ? '' : String(args[0]);
      const target = args[1] === undefined ? '' : String(args[1]);
      const destination = parseURL(rawURL);
      const targetLower = target.toLowerCase();

      const existingContext = [
        '_self',
        '_parent',
        '_top',
      ].includes(targetLower);

      const httpDestination = Boolean(
        destination &&
        (
          destination.protocol === 'http:' ||
          destination.protocol === 'https:'
        )
      );

      const blankDestination = (
        !rawURL.trim() ||
        (
          destination?.protocol === 'about:' &&
          destination.pathname === 'blank'
        )
      );

      if (!active) {
        return blockPopup('inactive document', destination);
      }

      if (
        destination &&
        matchesDomains(destination.hostname, AD_DOMAINS)
      ) {
        return blockPopup('advertising destination', destination);
      }

      if (recognizedAdCaller()) {
        return blockPopup('advertising script', destination);
      }

      if (destination?.protocol === 'javascript:') {
        return blockPopup('executable popup destination', destination);
      }

      // Ordinary same-site navigation does not create a popup.
      if (
        existingContext &&
        httpDestination &&
        sameSiteDestination(destination)
      ) {
        args[0] = rawURL;
        if (args.length > 1) args[1] = target;
        return apply(nativeOpen, this, args);
      }

      const flow = currentFlow();
      const providerCaller = callerMatches(PROVIDER_SCRIPT_DOMAINS);
      const namedWindow = existingNamedWindow(target);

      let allowed = false;

      if (blankDestination) {
        allowed = existingContext
          ? recentInteraction()
          : blankContextAuthorized(flow, providerCaller);
      } else if (httpDestination) {
        const providerDestination = (
          destination.protocol === 'https:' &&
          matchesDomains(destination.hostname, PROVIDER_DOMAINS)
        );

        allowed = (
          (
            recentInteraction() &&
            sameSiteDestination(destination)
          ) ||
          explicitDestination(destination) ||
          identityProviderLogin(destination) ||
          (
            providerDestination &&
            (
              providerContextAuthorized(flow, providerCaller) ||
              Boolean(namedWindow)
            )
          )
        );
      } else if (destination) {
        const explicitSpecialLink = (
          ['blob:', 'data:', 'mailto:', 'tel:']
            .includes(destination.protocol) &&
          explicitDestination(destination)
        );

        const currentPage = currentPageURL();

        const deliberateBlobExport = (
          destination.protocol === 'blob:' &&
          currentPage &&
          destination.origin === currentPage.origin &&
          recentInteraction() &&
          visibleControl(lastInteraction.control) &&
          EXPORT_CONTROL_PATTERN.test(
            controlMetadata(lastInteraction.control)
          )
        );

        allowed = explicitSpecialLink || deliberateBlobExport;
      }

      if (!allowed) {
        return blockPopup(
          blankDestination
            ? 'blank window outside an intended payment or sign-in flow'
            : 'unrequested popup destination',
          destination
        );
      }

      if (
        !existingContext &&
        !namedWindow &&
        (
          (recentInteraction() && lastInteraction.popupUsed) ||
          flow?.popupUsed
        )
      ) {
        return blockPopup(
          'multiple windows from one interaction',
          destination
        );
      }

      if (!existingContext && !namedWindow) {
        consumeWindowGrant(flow);
      }

      args[0] = rawURL;
      if (args.length > 1) args[1] = target;

      // Preserve native WindowProxy, focus, closed, location and messaging.
      const openedWindow = apply(nativeOpen, this, args);

      if (!existingContext) {
        recordSignal('pa', 'pah', destination && destination.hostname);
        rememberNamedWindow(target, openedWindow);

        if (openedWindow) {
          preventDuplicateAnchorNavigation(destination);
        }
      }

      return openedWindow;
    });

    if (typeof nativeConfirm === 'function') {
      installHook('confirm', function dadblockConfirm(...args) {
        if (
          lastBlockedAt > 0 &&
          now() - lastBlockedAt < 2000 &&
          recognizedAdCaller()
        ) {
          return false;
        }

        return apply(nativeConfirm, this, args);
      });
    }

    function stopEvent(event) {
      if (event.cancelable) event.preventDefault();
      event.stopImmediatePropagation();
    }

    function interceptEvent(event) {
      if (!active) return;

      const element = eventElement(event);
      if (!element) return;

      const overlay = findOverlay(element);

      if (overlay) {
        stopEvent(event);

        // Empty click traps lose interception without hiding containers
        // or changing page stacking order.
        overlay.style.setProperty('pointer-events', 'none', 'important');

        recordSignal('ov');
        if (lastInteraction) lastInteraction.overlay = true;
        lastFlow = null;
        return;
      }

      if (event.type !== 'click' && event.type !== 'auxclick') return;

      const anchor = closest(element, 'a[href]');
      if (!anchor) return;

      const destination = parseURL(anchor.getAttribute('href') || '');
      if (!destination) return;

      if (matchesDomains(destination.hostname, AD_DOMAINS)) {
        stopEvent(event);
        blockPopup('advertising link', destination);
        return;
      }

      const baseTarget = doc.querySelector('base[target]')
        ?.getAttribute('target') || '';

      const target = (
        anchor.getAttribute('target') || baseTarget || '_self'
      ).toLowerCase();

      const newContext = !['_self', '_parent', '_top'].includes(target);

      if (anchor.hasAttribute('download') || !newContext) return;

      if (destination.protocol === 'javascript:') {
        stopEvent(event);
        blockPopup('executable new-tab link', destination);
        return;
      }

      if (!explicitDestination(destination)) {
        stopEvent(event);
        blockPopup('unrequested new-tab link', destination);
        return;
      }

      if (lastInteraction.popupUsed) {
        stopEvent(event);
        blockPopup('multiple windows from one interaction', destination);
        return;
      }

      const interaction = lastInteraction;

      // Do not consume the grant in capture phase. Site click handlers
      // may prevent the default navigation and open the intended window.
      // A timer runs after dispatch; a microtask could run between listeners.
      nativeSetTimeout(() => {
        if (
          active &&
          lastInteraction === interaction &&
          !event.defaultPrevented
        ) {
          interaction.popupUsed = true;
        }
      }, 0);
    }

    for (const type of [
      'pointerdown',
      'mousedown',
      'touchstart',
      'keydown',
      'click',
      'auxclick',
    ]) {
      win.addEventListener(type, recordInteraction, true);

      win.addEventListener(type, interceptEvent, {
        capture: true,
        passive: false,
      });
    }

    win.addEventListener('pagehide', event => {
      if (!event.isTrusted) return;

      active = false;
      lastInteraction = null;
      lastFlow = null;
      permittedNamedWindows.clear();
    });

    win.addEventListener('pageshow', event => {
      if (!event.isTrusted) return;

      active = true;
      lastInteraction = null;
      lastFlow = null;
      permittedNamedWindows.clear();
    });

    function armFrame(frame) {
      if (!frame || frame.tagName !== 'IFRAME') return;

      if (!armedFrames.has(frame)) {
        armedFrames.add(frame);

        frame.addEventListener('load', () => {
          try {
            installRealm(frame.contentWindow);
          } catch {
            // Cross-origin frames use registered all-frame injection.
          }
        });
      }

      try {
        installRealm(frame.contentWindow);
      } catch {
        // Cross-origin access remains unavailable.
      }
    }

    // Protect synchronous access to newly created same-origin frames.
    // Each frame captures its own native window.open and receiver.
    const framePrototype = win.HTMLIFrameElement?.prototype;

    if (framePrototype) {
      for (const property of ['contentWindow', 'contentDocument']) {
        try {
          const descriptor = Object.getOwnPropertyDescriptor(
            framePrototype,
            property
          );

          if (!descriptor?.configurable || !descriptor.get) continue;

          const nativeGetter = descriptor.get;

          Object.defineProperty(framePrototype, property, {
            ...descriptor,
            get: function () {
              const value = apply(nativeGetter, this, []);

              try {
                const child = property === 'contentWindow'
                  ? value
                  : value?.defaultView;

                if (child) installRealm(child);
              } catch {
                // Preserve native cross-origin access behavior.
              }

              return value;
            },
          });
        } catch {
          // Registered all-frame injection remains available.
        }
      }
    }

    doc.querySelectorAll('iframe').forEach(armFrame);

    const observer = new win.MutationObserver(records => {
      for (const record of records) {
        for (const node of record.addedNodes) {
          if (node.nodeType !== 1) continue;

          if (node.tagName === 'IFRAME') armFrame(node);
          node.querySelectorAll('iframe').forEach(armFrame);
        }
      }
    });

    observer.observe(doc, {
      childList: true,
      subtree: true,
    });

    console.info('[Dadblock] Anti-popunder guard v4 armed.');
  }

  installRealm(window);
})();