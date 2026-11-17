// popup-report.js
// Builds "Dad's report" in the popup from facts that report-collector.js
// measured on the page. All wording is template-based: every sentence is
// tied to a measured fact, so nothing here can be a guess or a verdict.

(function () {
  'use strict';

  // Approximate "registrable domain" (site) matching without a full
  // public-suffix list. Good enough to tell "other websites" apart.
  const TWO_PART_SUFFIXES = new Set([
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au',
    'co.nz', 'co.jp', 'ne.jp', 'or.jp', 'com.br', 'com.mx', 'com.ar',
    'com.tr', 'com.cn', 'com.hk', 'com.sg', 'com.tw', 'co.kr', 'co.in',
    'co.za', 'com.ua', 'com.pl', 'co.il', 'com.sa', 'com.eg', 'com.ng',
    'com.pk', 'com.vn', 'com.my', 'co.id', 'co.th',
  ]);

  function registrable(host) {
    const value = String(host || '').toLowerCase();

    if (!value || value.includes(':') || /^\d+(?:\.\d+){3}$/.test(value)) {
      return value;
    }

    const parts = value.split('.');

    if (parts.length <= 2) return value;

    const lastTwo = parts.slice(-2).join('.');

    return TWO_PART_SUFFIXES.has(lastTwo)
      ? parts.slice(-3).join('.')
      : lastTwo;
  }

  // Well-known ad and tracking services, used in addition to the
  // domains Dadblock already blocks (rules.json and synced rules).
  const EXTRA_TRACKER_DOMAINS = [
    'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
    'google-analytics.com', 'adnxs.com', 'criteo.com', 'criteo.net',
    'taboola.com', 'outbrain.com', 'scorecardresearch.com', 'hotjar.com',
    'clarity.ms', 'amazon-adsystem.com', 'connect.facebook.net',
    'mixpanel.com', 'segment.io', 'segment.com', 'fullstory.com',
    'adsrvr.org', 'rubiconproject.com', 'openx.net', 'casalemedia.com',
    'pubmatic.com', 'popads.net', 'popcash.net', 'propellerads.com',
    'adsterra.com', 'exoclick.com', 'exosrv.com', 'onclickads.net',
    'onclickalgo.com', 'onclickmega.com', 'highperformancegate.com',
    'highperformanceformat.com', 'profitableratecpm.com',
    'effectivegatecpm.com',
  ];

  const PAYMENT_DOMAINS = [
    'stripe.com', 'stripe.network', 'paypal.com', 'adyen.com',
    'adyenpayments.com', 'braintreegateway.com', 'braintreepayments.com',
    'pay.google.com', 'payments.google.com', 'pay.amazon.com',
    'klarna.com', 'checkout.com', 'squareup.com', 'mollie.com',
  ];

  function domainsFromRules(rules) {
    const found = [];

    if (!Array.isArray(rules)) return found;

    for (const rule of rules) {
      const filter = rule?.condition?.urlFilter;

      if (typeof filter !== 'string') continue;

      const match = filter.match(
        /([a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,})/i
      );

      if (match) found.push(match[1].toLowerCase());
    }

    return found;
  }

  function hostMatches(host, domainSet) {
    const parts = String(host || '').toLowerCase().split('.');

    for (let i = 0; i < parts.length - 1; i++) {
      if (domainSet.has(parts.slice(i).join('.'))) return true;
    }

    return false;
  }

  function plural(count, one, many) {
    return count + ' ' + (count === 1 ? one : many);
  }

  // facts: object from report-collector.js. trackerSet: Set of domains.
  function analyze(facts, trackerSet) {
    const paymentSet = new Set(PAYMENT_DOMAINS);
    const pageSite = registrable(facts.pageHost);
    const sig = facts.sig || {};
    const items = [];
    const tips = [];

    const outsideSites = new Map();

    for (const [host] of facts.hosts || []) {
      const site = registrable(host);

      if (site !== pageSite && !outsideSites.has(site)) {
        outsideSites.set(site, host);
      }
    }

    const trackerSites = [];

    for (const [site, host] of outsideSites) {
      if (
        hostMatches(host, trackerSet) ||
        hostMatches(site, trackerSet)
      ) {
        trackerSites.push(site);
      }
    }

    const outside = outsideSites.size;
    const trackers = trackerSites.length;
    const hasPassword = facts.password > 0;
    const hasCard = facts.card > 0;
    const insecure = facts.protocol === 'http:';

    // ---- Connection and requests for sensitive details
    let passwordTipPending = false;

    if (insecure && (hasPassword || hasCard)) {
      items.push({
        tone: 'warn',
        text:
          'This page is not encrypted (http://) and it has a ' +
          (hasPassword ? 'password' : 'card') +
          ' box. What you type could be read on the way.',
      });

      tips.push(
        'Do not type passwords or card numbers on this page.'
      );
    } else if (insecure) {
      items.push({
        tone: 'note',
        text: 'This page is not encrypted (http://). Avoid typing anything private here.',
      });
    }

    if ((hasPassword || hasCard) && !insecure) {
      const asks = [];

      if (hasPassword) asks.push('a password box');
      if (hasCard) asks.push('card-detail boxes');

      items.push({
        tone: 'note',
        text: 'This page has ' + asks.join(' and ') + '.',
      });

      if (hasPassword) {
        passwordTipPending = true;
      }
    }

    const outsideForms = [];

    for (const form of facts.forms || []) {
      if (registrable(form.h) !== pageSite) outsideForms.push(form);
    }

    for (const form of outsideForms) {
      const site = registrable(form.h);
      const isPayment = hostMatches(form.h, paymentSet);
      const what = form.kind === 'card' ? 'card details' : 'password';

      items.push({
        tone: isPayment ? 'note' : 'warn',
        text: isPayment
          ? 'A ' + what + ' form sends to ' + site +
            ', a payment service. That is normal for many shops.'
          : 'A form with a ' + what + ' box sends what you type to a different website: ' +
            site + '.',
      });

      if (!isPayment) {
        tips.push(
          'A form here sends your ' + what + ' to ' + site +
          '. Only continue if you recognize that name.'
        );
      }
    }

    if (passwordTipPending && outsideForms.length === 0) {
      tips.push(
        'Only type a password here if you came to this site on purpose and the address in the bar is exactly right.'
      );
    }

    if (
      (hasPassword || hasCard) &&
      outsideForms.length === 0 &&
      (facts.forms || []).length > 0
    ) {
      items.push({
        tone: 'ok',
        text: 'The form points back to this same site, not to a different one.',
      });
    }

    if (!hasPassword && !hasCard) {
      items.push({
        tone: 'ok',
        text: 'Nothing on this page asks for a password or card details.',
      });
    }

    const paymentFrames = (facts.frames || []).filter(
      host => hostMatches(host, paymentSet)
    );

    if (paymentFrames.length) {
      items.push({
        tone: 'note',
        text:
          'Payment details are handled in a frame from ' +
          registrable(paymentFrames[0]) +
          ', a payment service.',
      });
    }

    // ---- Outside connections
    if (outside === 0) {
      items.push({
        tone: 'ok',
        text: 'I did not see this page reach out to other websites.',
      });
    } else {
      const base =
        'This page reached out to ' +
        plural(outside, 'other website', 'other websites') +
        (facts.hostsTruncated ? ' or more' : '') + '. ';

      items.push({
        tone: trackers > 0 ? 'note' : 'ok',
        text: trackers > 0
          ? base +
            (trackers === 1
              ? '1 of them is a known ad or tracking service.'
              : trackers + ' of them are known ad or tracking services.')
          : base +
            'None are on Dadblock’s ad and tracker list. Many are normal, like fonts, images and video.',
        detail: trackers > 0
          ? 'Includes: ' + trackerSites.slice(0, 5).join(', ') +
            (trackers > 5 ? ', and ' + (trackers - 5) + ' more' : '')
          : null,
      });
    }

    // ---- Behavior of the page
    let behaviorNotes = 0;

    function behavior(tone, text, detail) {
      behaviorNotes++;
      items.push({ tone, text, detail: detail || null });
    }

    if (sig.n) {
      behavior('note', 'This page asked to send you notifications.');
      tips.push(
        'Choose Block when the browser asks about notifications unless you really want them. They are a common source of spam later.'
      );
    }

    if (sig.g) {
      behavior('note', 'This page asked for your location.');
      tips.push(
        'Only share your location if it is obvious why this site needs it.'
      );
    }

    if (sig.m) {
      behavior('warn', 'This page asked to use your camera, microphone or screen.');
      tips.push(
        'Only allow camera, microphone or screen sharing if you started something that needs it.'
      );
    }

    if (sig.c) {
      behavior('warn', 'This page tried to read what is on your clipboard.');
      tips.push(
        'Be careful with anything you copy while this page is open.'
      );
    }

    if (sig.w) {
      behavior('note', 'This page copied something to your clipboard.');
      tips.push(
        'Copy buttons do this normally, but check what you paste. Never paste copied text into a terminal, the Windows Run box or a crypto wallet unless you know exactly what it is.'
      );
    }

    if (sig.p) {
      const info = facts.popupInfo || {};
      const detailBits = [];

      if (info.host) detailBits.push('Heading to: ' + info.host);
      if (info.reason) detailBits.push('Why: ' + info.reason);

      behavior(
        'note',
        'Dadblock stopped ' + plural(sig.p, 'pop-up attempt', 'pop-up attempts') + '.',
        detailBits.join(' · ')
      );

      const signInHosts = new Set([
        'accounts.google.com', 'login.microsoftonline.com',
        'login.live.com', 'appleid.apple.com', 'github.com',
        'facebook.com', 'paypal.com', 'stripe.com',
      ]);

      if (info.host && hostMatches(info.host, signInHosts)) {
        tips.push(
          'Dadblock stopped a window to ' + info.host +
          '. If you were signing in or paying and it did not open, please tell us through the feedback link so we can fix it.'
        );
      } else {
        tips.push(
          'If a new tab or window opens by itself, close it without clicking anything.'
        );
      }
    }

    if (facts.programLinks > 0) {
      behavior(
        'warn',
        'This page links to program files (like .exe or .apk): ' +
        facts.programLinks + '.'
      );
      tips.push(
        'Download software only from the official maker’s own website.'
      );
    } else if (facts.downloadAttr > 0) {
      behavior(
        'note',
        'This page has ' + plural(facts.downloadAttr, 'download link', 'download links') + '.'
      );
    }

    if (sig.ov) {
      behavior(
        'note',
        'Dadblock neutralized ' +
        plural(sig.ov, 'invisible click-trap', 'invisible click-traps') +
        ' covering the page.'
      );
    }

    if (sig.pa) {
      const allowedHost = (facts.popupInfo || {}).allowedHost;

      items.push({
        tone: 'ok',
        text:
          'Dadblock let ' + plural(sig.pa, 'window', 'windows') +
          ' open that you asked for.',
        detail: allowedHost ? 'Heading to: ' + allowedHost : null,
      });
    }

    if (behaviorNotes === 0) {
      items.push({
        tone: 'ok',
        text: 'No unwanted pop-ups, permission requests or clipboard tricks so far.',
      });
    }

    if (trackers >= 5 || sig.p) {
      tips.push(
        'If a button says “Update player”, “Download” or “Allow to continue”, treat it as an ad, not a feature.'
      );
    }

    if (trackers >= 5) {
      tips.push(
        'If a site asks you to sign up, a throwaway email keeps your real inbox out of it.'
      );
    }

    // ---- Dad’s voice for the intro and headline
    const warns = items.filter(item => item.tone === 'warn').length;
    const quiet =
      warns === 0 &&
      !hasPassword &&
      !hasCard &&
      behaviorNotes === 0 &&
      trackers === 0 &&
      !insecure;

    let intro;

    if (warns > 0 && trackers >= 10) {
      intro =
        'Dad looked around. This page is chatty with outsiders, and a few things deserve a second look:';
    } else if (warns > 0) {
      intro = 'Dad looked around. A few things are worth knowing:';
    } else if (quiet) {
      intro =
        'Dad peeked around: quiet page. Nothing asked for passwords or payments, nothing popped up, and no ad or tracking services I could see.';
    } else if (trackers >= 10) {
      intro =
        'This page is chatty with outsiders. Nothing scary in what it asks of you, but your privacy is getting a workout.';
    } else {
      intro = 'Dad looked around. Here is what this page does:';
    }

    const headlineBits = [];

    if (outside > 0) {
      headlineBits.push(
        outside + ' other ' + (outside === 1 ? 'site' : 'sites') +
        (trackers > 0 ? ' (' + trackers + ' ad/tracking)' : '')
      );
    }

    if (hasPassword) headlineBits.push('password box');
    if (hasCard) headlineBits.push('card box');
    if (sig.p) headlineBits.push(plural(sig.p, 'pop-up stopped', 'pop-ups stopped'));
    if (sig.c || sig.m) headlineBits.push('sensitive access');

    let headline =
      'Dad’s report · ' +
      (quiet ? 'quiet page' : headlineBits.join(', ') || 'what this page does');

    const seen = new Set();
    const uniqueTips = [];

    for (const tip of tips) {
      if (!seen.has(tip)) {
        seen.add(tip);
        uniqueTips.push(tip);
      }
    }

    // ---- Shop check (only when the page looks like an online shop)
    const shopItems = [];
    let shopCaution = false;
    let shopIntro = null;
    const shopTips = [];

    if (facts.shop) {
      const links = facts.shop.links || {};
      const protectedPay = facts.shop.protectedPay || [];
      const riskyPay = facts.shop.riskyPay || [];

      shopIntro =
        'This looks like an online shop. Dad checked what honest shops usually show:';

      function linkRow(key, found, missing) {
        shopItems.push(
          links[key]
            ? { tone: 'ok', text: found }
            : { tone: 'note', text: missing }
        );
      }

      linkRow(
        'imprint',
        'There is a link to a legal notice or imprint (who runs the shop).',
        'I did not spot a legal notice or imprint link. It may be called something else, but shops in Europe generally must show who runs them.'
      );
      linkRow(
        'contact',
        'There is a contact page link.',
        'I did not spot a contact page link.'
      );
      linkRow(
        'returns',
        'There is a returns or refund policy link.',
        'I did not spot a returns or refund policy link.'
      );
      linkRow(
        'shipping',
        'There is a shipping or delivery information link.',
        'I did not spot a shipping or delivery information link.'
      );

      if (protectedPay.length && !riskyPay.length) {
        shopItems.push({
          tone: 'ok',
          text: 'Payment options with buyer protection are mentioned: ' +
            protectedPay.join(', ') + '.',
        });
      } else if (protectedPay.length) {
        shopItems.push({
          tone: 'note',
          text: 'Mentioned payment options include ' +
            protectedPay.join(', ') + ' and also ' +
            riskyPay.join(' and ') + ', which are harder to get back.',
        });
      } else if (riskyPay.length) {
        shopItems.push({
          tone: 'warn',
          text: 'The only payment ways I saw mentioned are ' +
            riskyPay.join(' and ') +
            ', which give you little protection.',
        });

        shopTips.push(
          'Do not pay by bank transfer, wire or crypto unless you already trust this shop. A card or PayPal lets you dispute a payment.'
        );
      } else {
        shopItems.push({
          tone: 'note',
          text: 'I did not see payment options on this page. They may only appear at checkout.',
        });
      }

      if (facts.shop.discountMax >= 70) {
        shopItems.push({
          tone: 'note',
          text: 'Some items show discounts of ' + facts.shop.discountMax +
            '% or more. Huge discounts are a common lure in fake shops, though real clearance sales exist.',
        });
      }

      const missingLinks = ['imprint', 'contact', 'returns', 'shipping']
        .filter(key => !links[key]).length;

      shopCaution =
        shopItems.some(item => item.tone === 'warn') ||
        (facts.shop.discountMax >= 70 && missingLinks >= 2);

      shopTips.push(
        'Before paying: check the shop’s name and address in the legal notice, look at recent reviews with the review buttons at the top, and tap “Check domain age”. Very new shops deserve extra care.'
      );
    }

    if (facts.shop) {
      const shopWarns = shopItems.filter(i => i.tone === 'warn').length;

      if (shopWarns > 0 && warns === 0) {
        intro = 'Dad looked around. A few things are worth knowing:';
      } else if (quiet) {
        intro = 'Dad looked around. Here is what this page does:';
      }

      headline = quiet
        ? 'Dad’s report · online shop'
        : headline + ', online shop';
    }

    return {
      pageDomain: pageSite,
      shopCaution,
      headline,
      intro,
      shopIntro,
      shopItems,
      shopTips,
      items,
      tips: uniqueTips.slice(0, 5),
      shopFootnote: facts.shop
        ? 'A tidy checklist does not prove a shop is honest, and a missing item does not prove it is fake. Dad cannot check delivery or refunds.'
        : null,
      footnote:
        'Dad only sees what this page does in this tab right now. He cannot see what a site does with your data on its servers, and a calm report is not a safety guarantee.',
    };
  }

  // ---- Domain age (user-initiated, via the public RDAP registry system)
  function describeDomainAge(date, now) {
    const days = Math.floor((now - date.getTime()) / 86400000);

    if (!Number.isFinite(days) || days < 0) return null;

    const when = date.toLocaleDateString(undefined, {
      month: 'short',
      year: 'numeric',
    });

    if (days < 30) {
      return {
        tone: 'warn',
        text:
          'This domain was registered only ' + plural(days, 'day', 'days') +
          ' ago (' + when + '). Many fake shops are only days or weeks old.',
      };
    }

    if (days < 180) {
      return {
        tone: 'note',
        text:
          'This domain was registered about ' +
          plural(Math.round(days / 30), 'month', 'months') + ' ago (' + when +
          '). A young domain is a reason to be extra careful.',
      };
    }

    const years = days / 365;
    const age =
      years >= 2
        ? plural(Math.floor(years), 'year', 'years')
        : plural(Math.round(days / 30), 'month', 'months');

    return {
      tone: 'ok',
      text:
        'This domain was registered about ' + age + ' ago (' + when +
        '). Age is only a clue: honest shops can be new, and scam shops can buy old domains.',
    };
  }

  const api = {
    analyze,
    registrable,
    domainsFromRules,
    describeDomainAge,
    EXTRA_TRACKER_DOMAINS,
  };

  try {
    globalThis.DadSiteReport = api;
  } catch {
    // Not available in some test environments.
  }

  if (typeof document === 'undefined' || typeof chrome === 'undefined') {
    return;
  }

  // ---------------------------------------------------------------
  // Popup wiring
  // ---------------------------------------------------------------

  async function loadTrackerSet() {
    const domains = new Set(EXTRA_TRACKER_DOMAINS);

    try {
      const response = await fetch(chrome.runtime.getURL('rules.json'));
      domainsFromRules(await response.json()).forEach(d => domains.add(d));
    } catch {
      // Built-in list still applies.
    }

    try {
      domainsFromRules(
        await chrome.declarativeNetRequest.getDynamicRules()
      ).forEach(d => domains.add(d));
    } catch {
      // Dynamic rules are optional.
    }

    return domains;
  }

  async function fetchWithTimeout(url, ms) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), ms);

    try {
      return await fetch(url, {
        signal: controller.signal,
        credentials: 'omit',
        cache: 'no-store',
      });
    } finally {
      clearTimeout(timer);
    }
  }

  // IANA publishes which registry answers for each ending (.com, .pl ...).
  // Asking IANA does not reveal any shop domain.
  async function rdapBaseFor(tld) {
    let services = null;

    try {
      const stored = (await chrome.storage.local.get('rdapBootstrap'))
        .rdapBootstrap;

      if (stored && Date.now() - stored.at < 7 * 86400000) {
        services = stored.services;
      }
    } catch {
      services = null;
    }

    if (!services) {
      const response = await fetchWithTimeout(
        'https://data.iana.org/rdap/dns.json',
        6000
      );

      services = (await response.json()).services;

      try {
        await chrome.storage.local.set({
          rdapBootstrap: { at: Date.now(), services },
        });
      } catch {
        // Caching is optional.
      }
    }

    for (const [tlds, urls] of services || []) {
      if (tlds.includes(tld)) {
        return urls.find(url => url.startsWith('https://')) || null;
      }
    }

    return null;
  }

  async function lookupDomainAge(domain) {
    try {
      const base = await rdapBaseFor(domain.split('.').pop());

      if (!base) return { status: 'unsupported' };

      const response = await fetchWithTimeout(
        base.replace(/\/?$/, '/') + 'domain/' + encodeURIComponent(domain),
        7000
      );

      if (!response.ok) {
        return { status: response.status === 404 ? 'notfound' : 'error' };
      }

      const data = await response.json();

      const event = (data.events || []).find(
        item => /registration/i.test(item.eventAction || '')
      );

      const date = event && event.eventDate ? new Date(event.eventDate) : null;

      return date && !isNaN(date.getTime())
        ? { status: 'ok', date }
        : { status: 'nodate' };
    } catch {
      return { status: 'error' };
    }
  }

  const ICONS = { ok: '✓', note: 'ℹ', warn: '⚠' };
  const LABELS = { ok: 'Fine', note: 'Note', warn: 'Heads-up' };

  function element(tag, className, text) {
    const node = document.createElement(tag);

    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;

    return node;
  }

  let shopOpenedOnce = false;
  let ageRow = null;
  let ageRowFor = '';
  let lastFactsKey = '';
  let loading = false;

  // Domain age box: one tap, only the domain name is sent.
  function appendAgeBox(parent, report) {
    const box = element('div', 'report-age');

    if (ageRow && ageRowFor === report.pageDomain) {
      renderList(box, [ageRow]);
      parent.appendChild(box);
      return;
    }

    const button = element('button', 'report-refresh', 'Check domain age');

    button.type = 'button';

    button.addEventListener('click', async () => {
      button.disabled = true;
      button.textContent = 'Checking…';

      const found = await lookupDomainAge(report.pageDomain);
      let row = null;

      if (found.status === 'ok') {
        row = describeDomainAge(found.date, Date.now());
      }

      if (!row) {
        row = {
          tone: 'note',
          text: found.status === 'error'
            ? 'I could not reach the domain registry just now. Try again later.'
            : 'I could not find a registration date for this domain. Some country domains do not share it. A WHOIS lookup may still show it.',
        };
      }

      ageRow = row;
      ageRowFor = report.pageDomain;

      box.textContent = '';
      renderList(box, [row]);
    });

    box.appendChild(button);
    box.appendChild(
      element(
        'p',
        'report-foot',
        'Asks the public domain registry when this domain was registered. Only the domain name is sent, nothing from the page.'
      )
    );
    parent.appendChild(box);
  }
  let shopCautionActive = false;
  let heroWatcher = null;
  const SAFE_TITLE = 'No scam indicators found';

  // The headline reports on scam wording in the page text. When the shop
  // check finds warning signs, a plain green "no indicators" headline would
  // contradict it, so the headline says both.
  function applyShopCaution() {
    if (!shopCautionActive) return;

    const title = document.getElementById('statusTitle');
    const description = document.getElementById('statusDescription');

    if (!title || !description || title.textContent !== SAFE_TITLE) return;

    title.textContent = 'No scam wording found, but be careful';
    description.textContent =
      'Dadblock found no scam wording in the page text. The shop check below shows warning signs, so look closely before you pay.';

    const hero = title.closest('.hero-section');

    if (hero) hero.classList.add('shop-caution');
  }

  function renderList(parent, entries) {
    const list = element('ul', 'report-list');

    for (const item of entries) {
      const row = element('li', 'report-row report-' + item.tone);
      const icon = element('span', 'report-icon', ICONS[item.tone]);

      icon.setAttribute('aria-hidden', 'true');

      const text = element('span', 'report-text');
      const label = element('span', 'report-sr', LABELS[item.tone] + ': ');

      text.appendChild(label);
      text.appendChild(document.createTextNode(item.text));

      if (item.detail) {
        text.appendChild(element('span', 'report-detail', item.detail));
      }

      row.appendChild(icon);
      row.appendChild(text);
      list.appendChild(row);
    }

    parent.appendChild(list);
  }

  function render(report, justUpdated) {
    const details = document.getElementById('siteReport');
    const summary = document.getElementById('siteReportSummary');
    const body = document.getElementById('siteReportBody');

    if (!details || !summary || !body) return;

    summary.textContent = report.headline;
    body.textContent = '';
    body.appendChild(element('p', 'report-intro', report.intro));

    renderList(body, report.items);

    if (!report.shopItems.length) {
      body.appendChild(element('h4', 'report-heading', 'Site age'));
      appendAgeBox(body, report);
    }

    if (report.shopItems.length) {
      body.appendChild(element('h4', 'report-heading', 'Shop check'));
      body.appendChild(element('p', 'report-intro', report.shopIntro));
      renderList(body, report.shopItems);

      appendAgeBox(body, report);
    }

    const allTips = report.shopTips.concat(report.tips).slice(0, 6);

    if (allTips.length) {
      body.appendChild(element('h4', 'report-heading', 'What you can do'));

      const tips = element('ul', 'report-tips');

      for (const tip of allTips) {
        tips.appendChild(element('li', '', tip));
      }

      body.appendChild(tips);
    }

    const refresh = element(
      'button',
      'report-refresh',
      justUpdated ? 'Updated ✓' : 'Refresh now'
    );

    refresh.type = 'button';

    refresh.addEventListener('click', async () => {
      refresh.disabled = true;
      refresh.textContent = 'Checking…';
      await load(true);

      // If nothing was re-rendered (no data), restore the button.
      if (refresh.isConnected) {
        refresh.disabled = false;
        refresh.textContent = 'Refresh now';
      }
    });

    if (justUpdated) {
      setTimeout(() => {
        if (refresh.isConnected) refresh.textContent = 'Refresh now';
      }, 1800);
    }

    body.appendChild(refresh);

    const stamp = new Date().toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });

    body.appendChild(
      element('p', 'report-foot', 'Checked at ' + stamp + '. ' + report.footnote)
    );

    if (report.shopFootnote) {
      body.appendChild(element('p', 'report-foot', report.shopFootnote));
    }

    details.hidden = false;

    shopCautionActive = Boolean(report.shopCaution);
    applyShopCaution();

    if (!heroWatcher && typeof MutationObserver !== 'undefined') {
      const title = document.getElementById('statusTitle');

      if (title) {
        heroWatcher = new MutationObserver(applyShopCaution);
        heroWatcher.observe(title, {
          childList: true,
          characterData: true,
          subtree: true,
        });
      }
    }

    // Shops are where people lose money, so the report opens by itself
    // the first time. After that, the user stays in control.
    if (report.shopItems.length && !shopOpenedOnce) {
      shopOpenedOnce = true;
      details.open = true;
    }
  }

  async function load(manual) {
    if (loading) return;

    loading = true;

    try {
      const [tab] = await chrome.tabs.query({
        active: true,
        currentWindow: true,
      });

      if (!tab || !tab.id || !/^https?:/i.test(tab.url || '')) return;

      const response = await chrome.tabs.sendMessage(tab.id, {
        action: 'dadblockSiteReport',
      });

      if (!response || !response.ok || !response.facts) return;

      // The popup closes when you click the page, so while it stays
      // open the report quietly refreshes itself, and only redraws
      // when something on the page actually changed.
      const key = JSON.stringify(response.facts);

      if (manual !== true && key === lastFactsKey) return;

      lastFactsKey = key;

      render(analyze(response.facts, await loadTrackerSet()), manual === true);
    } catch {
      // No collector on this page (restricted page, or opened before
      // the extension updated). The report section stays hidden.
    } finally {
      loading = false;
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    load(false);
    setInterval(() => load(false), 3000);
  });
})();
