// report-collector.js
// ISOLATED world content script, document_start, top frame only.
//
// Collects observable facts about what the current page does so the popup
// can build "Dad's report". Everything stays in this page's memory and is
// sent only to the Dadblock popup when it asks. No network, no storage,
// no analysis: the popup turns these facts into text.

(() => {
  'use strict';

  const GUARD = '__dadblockReportCollectorV1';

  try {
    if (window[GUARD]) return;
    Object.defineProperty(window, GUARD, { value: true });
  } catch {
    return;
  }

  const MAX_HOSTS = 400;
  const MAX_DOM_NODES = 800;
  const MAX_ANCHORS = 3000;
  const MAX_FORMS = 40;
  const MAX_FRAMES = 40;
  const SIG_ATTRIBUTE = 'data-dadblock-sig';
  const SIG_KEYS = ['n', 'g', 'c', 'w', 'm', 'p', 'pa', 'ov'];

  const hosts = new Map();
  let hostsTruncated = false;

  function cleanHost(value) {
    return String(value || '')
      .toLowerCase()
      .replace(/\.$/, '');
  }

  function noteUrl(raw, kind, onlyIfNew = false) {
    try {
      const url = new URL(
        raw,
        document.baseURI || window.location.href
      );

      if (!/^(?:https?|wss?):$/.test(url.protocol)) return;

      const host = cleanHost(url.hostname);
      if (!host) return;

      let entry = hosts.get(host);

      if (!entry) {
        if (hosts.size >= MAX_HOSTS) {
          hostsTruncated = true;
          return;
        }

        entry = { n: 0, k: {} };
        hosts.set(host, entry);
      } else if (onlyIfNew) {
        return;
      }

      entry.n++;
      entry.k[kind] = (entry.k[kind] || 0) + 1;
    } catch {
      // Ignore malformed URLs.
    }
  }

  // Resource Timing covers what the page actually loaded, including
  // late scripts. A live observer is not limited by the 250-entry
  // timeline buffer.
  try {
    const observer = new PerformanceObserver(list => {
      for (const entry of list.getEntries()) {
        noteUrl(entry.name, entry.initiatorType || 'other');
      }
    });

    observer.observe({ type: 'resource', buffered: true });
  } catch {
    // Older engines: DOM scan below still gives a partial view.
  }

  function readSignals() {
    const out = {};

    try {
      const raw = document.documentElement
        ?.getAttribute(SIG_ATTRIBUTE);

      if (!raw) return out;

      const parsed = JSON.parse(raw);

      for (const key of SIG_KEYS) {
        const value = Number(parsed?.[key]);

        if (Number.isFinite(value) && value > 0) {
          out[key] = Math.min(Math.floor(value), 9999);
        }
      }
    } catch {
      // Missing or malformed signals mean "nothing observed".
    }

    return out;
  }

  // Link signals a legitimate shop normally shows (EN, DE, FR, ES, PL).
  const LINK_PATTERNS = [
    ['contact', /contact|kontakt|contacto|contactez/],
    ['about', /about|über uns|ueber-uns|qui sommes|o nas/],
    ['returns', /return|refund|rückgabe|ruckgabe|widerruf|retour|devoluci|zwrot/],
    ['shipping', /shipping|delivery|versand|lieferung|livraison|env[ií]o|dostaw/],
    ['terms', /terms|conditions|agb|cgv|regulamin/],
    ['privacy', /privacy|datenschutz|confidentialit|prywatno/],
    ['imprint', /imprint|impressum|legal.?notice|mentions.?l[eé]gales|aviso.?legal/],
  ];

  const PAY_PROTECTED = [
    ['PayPal', /paypal/],
    ['cards', /visa|mastercard|master card|american express|amex|credit card|debit card|kreditkarte|carte bancaire/],
    ['Klarna', /klarna/],
    ['Apple Pay', /apple ?pay/],
    ['Google Pay', /google ?pay|gpay/],
    ['local methods', /sofort|ideal|bancontact|blik|przelewy24|\beps\b/],
  ];

  const PAY_RISKY = [
    ['crypto', /bitcoin|ethereum|usdt|crypto/],
    ['bank or wire transfer', /bank transfer|wire transfer|western union|moneygram|vorkasse|prepayment|bank[üu]berweisung/],
  ];

  const CART_WORDS =
    /add to (?:cart|bag|basket)|in den warenkorb|zum warenkorb|ajouter au panier|a[ñn]adir al carrito|dodaj do koszyka|buy now|checkout|jetzt kaufen/;

  const PRICE =
    /(?:[$€£]\s?\d|\d+[.,]\d{2}\s?(?:€|eur|usd|\$|£|zł|pln))/i;

  // Why Dadblock stopped a pop-up and where it was heading. Hostname
  // and a short reason only, never page content.
  function readPopupInfo() {
    try {
      const parsed = JSON.parse(
        document.documentElement.getAttribute(SIG_ATTRIBUTE) || '{}'
      );

      const clean = value =>
        String(value || '')
          .replace(/[^a-zA-Z0-9 .:_-]/g, '')
          .slice(0, 80);

      return {
        reason: clean(parsed.pr),
        host: clean(parsed.pd),
        allowedHost: clean(parsed.pah),
      };
    } catch {
      return { reason: '', host: '' };
    }
  }

  const CARD_FIELD =
    /card.?(?:number|num|no)\b|cc.?num|cardnumber|\bcvv\b|\bcvc\b|security.?code/i;

  function scanDom() {
    const pageHost = cleanHost(window.location.hostname);

    const facts = {
      password: 0,
      card: 0,
      forms: [],
      frames: [],
      downloadAttr: 0,
      programLinks: 0,
      shop: null,
    };

    const shopLinks = {};

    // Hosts the page asked for even if a blocker stopped the request.
    try {
      const nodes = document.querySelectorAll(
        'script[src], iframe[src], img[src], source[src], ' +
        'video[src], audio[src], link[rel~="stylesheet"][href]'
      );

      let count = 0;

      for (const node of nodes) {
        if (++count > MAX_DOM_NODES) break;

        noteUrl(
          node.getAttribute('src') || node.getAttribute('href'),
          'dom',
          true
        );
      }
    } catch {
      // Partial data is acceptable.
    }

    try {
      facts.password =
        document.querySelectorAll('input[type="password"]').length;

      const cardInputs = new Set(
        document.querySelectorAll('input[autocomplete^="cc-" i]')
      );

      let inspected = 0;

      for (const input of document.querySelectorAll('input')) {
        if (++inspected > 300) break;

        const label = [
          input.name,
          input.id,
          input.getAttribute('placeholder'),
          input.getAttribute('aria-label'),
        ].join(' ');

        if (CARD_FIELD.test(label)) cardInputs.add(input);
      }

      facts.card = cardInputs.size;

      const seenForms = new Set();
      let formCount = 0;

      for (const form of document.querySelectorAll('form')) {
        if (++formCount > MAX_FORMS) break;

        const hasPassword = !!form.querySelector(
          'input[type="password"]'
        );

        const hasCard = !!form.querySelector(
          'input[autocomplete^="cc-" i]'
        );

        if (!hasPassword && !hasCard) continue;

        let host = pageHost;

        try {
          host = cleanHost(
            new URL(
              form.getAttribute('action') || window.location.href,
              document.baseURI || window.location.href
            ).hostname
          );
        } catch {
          continue;
        }

        const kind = hasPassword ? 'password' : 'card';
        const id = host + '|' + kind;

        if (seenForms.has(id) || facts.forms.length >= 6) continue;

        seenForms.add(id);
        facts.forms.push({ h: host, kind });
      }
    } catch {
      // Keep whatever was collected.
    }

    try {
      const seenFrames = new Set();
      let frameCount = 0;

      for (const frame of document.querySelectorAll('iframe[src]')) {
        if (++frameCount > MAX_FRAMES) break;

        try {
          const host = cleanHost(
            new URL(
              frame.getAttribute('src'),
              document.baseURI || window.location.href
            ).hostname
          );

          if (
            host &&
            host !== pageHost &&
            !seenFrames.has(host) &&
            facts.frames.length < 20
          ) {
            seenFrames.add(host);
            facts.frames.push(host);
          }
        } catch {
          // Ignore malformed frame URLs.
        }
      }
    } catch {
      // Keep whatever was collected.
    }

    try {
      const program =
        /\.(?:exe|msi|apk|dmg|scr|bat|cmd|jar|pkg)(?:[?#]|$)/i;

      let anchorCount = 0;

      // Footer links first: on shops with hundreds of product links
      // the legal and contact links sit at the very end of the page.
      const ordered = Array.from(new Set([
        ...document.querySelectorAll(
          'footer a[href], [role="contentinfo"] a[href], [class*="footer" i] a[href], [id*="footer" i] a[href]'
        ),
        ...document.querySelectorAll('a[href]'),
      ]));

      for (const anchor of ordered) {
        if (++anchorCount > MAX_ANCHORS) break;

        if (anchor.hasAttribute('download')) facts.downloadAttr++;

        const href = anchor.getAttribute('href') || '';

        if (program.test(href)) facts.programLinks++;

        const linkText = (
          String(anchor.textContent || '').slice(0, 80) + ' ' +
          (anchor.getAttribute('aria-label') || '') + ' ' +
          (anchor.getAttribute('title') || '') + ' ' + href
        ).toLowerCase();

        for (const [name, pattern] of LINK_PATTERNS) {
          if (!shopLinks[name] && pattern.test(linkText)) {
            shopLinks[name] = true;
          }
        }
      }
    } catch {
      // Keep whatever was collected.
    }

    try {
      const bodyText = String(
        (document.body &&
          (document.body.innerText ?? document.body.textContent)) || ''
      ).slice(0, 80000);

      const lower = bodyText.toLowerCase();
      const looksLikeShop = CART_WORDS.test(lower) && PRICE.test(bodyText);

      if (looksLikeShop) {
        let imageHints = '';
        let imageCount = 0;

        for (const img of document.querySelectorAll('img')) {
          if (++imageCount > 300) break;

          imageHints +=
            ' ' + (img.getAttribute('alt') || '') +
            ' ' + (img.getAttribute('title') || '') +
            ' ' + (img.getAttribute('src') || '').split('/').pop();
        }

        const haystack = (lower + ' ' + imageHints.toLowerCase());

        const protectedMethods = PAY_PROTECTED
          .filter(([, pattern]) => pattern.test(haystack))
          .map(([label]) => label);

        const riskyMethods = PAY_RISKY
          .filter(([, pattern]) => pattern.test(haystack))
          .map(([label]) => label);

        let discountMax = 0;

        for (const match of bodyText.matchAll(
          /(?:-|−)\s?(\d{2})\s?%|(\d{2})\s?%\s?(?:off|rabatt|discount|sale)/gi
        )) {
          const value = Number(match[1] || match[2]);

          if (value > discountMax && value <= 99) discountMax = value;
        }

        facts.shop = {
          links: shopLinks,
          protectedPay: protectedMethods,
          riskyPay: riskyMethods,
          discountMax,
        };
      }
    } catch {
      // The shop check is optional; the rest of the report still works.
    }

    return facts;
  }

  function collect() {
    const dom = scanDom();

    const list = Array.from(hosts.entries())
      .sort((a, b) => b[1].n - a[1].n)
      .slice(0, 300)
      .map(([host, entry]) => [host, entry.n]);

    return {
      v: 1,
      pageHost: cleanHost(window.location.hostname),
      protocol: window.location.protocol,
      hosts: list,
      hostsTruncated,
      ...dom,
      sig: readSignals(),
      popupInfo: readPopupInfo(),
    };
  }

  chrome.runtime.onMessage.addListener(
    (request, sender, sendResponse) => {
      if (
        !request ||
        typeof request !== 'object' ||
        request.action !== 'dadblockSiteReport'
      ) {
        return false;
      }

      if (sender?.id && sender.id !== chrome.runtime.id) {
        return false;
      }

      try {
        sendResponse({ ok: true, facts: collect() });
      } catch {
        sendResponse({ ok: false });
      }

      return false;
    }
  );
})();
