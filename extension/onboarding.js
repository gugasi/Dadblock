// onboarding.js — Dadblock Onboarding Controller
// External file: satisfies MV3 CSP (no inline scripts / onclick attrs allowed)
 
(function () {
  'use strict';
 
  const TOTAL = 7;
  let current = 0;
 
  const dc = document.getElementById('dc');
  const bk = document.getElementById('bk');
  const nx = document.getElementById('nx');
 
  for (let i = 0; i < TOTAL; i++) {
    const d = document.createElement('div');
    d.className = 'pip' + (i === 0 ? ' on' : '');
    d.addEventListener('click', () => goTo(i));
    dc.appendChild(d);
  }
 
  function goTo(index) {
    const slides = document.querySelectorAll('.slide');
    const pips   = document.querySelectorAll('.pip');
 
    slides[current].classList.remove('active');
    slides[current].classList.add('exit');
    const prev = current;
    setTimeout(() => slides[prev].classList.remove('exit'), 380);
 
    current = Math.max(0, Math.min(TOTAL - 1, index));
    slides[current].classList.add('active');
 
    pips.forEach((d, j) => d.classList.toggle('on', j === current));
 
    bk.style.opacity       = current === 0 ? '0' : '1';
    bk.style.pointerEvents = current === 0 ? 'none' : 'all';
 
    if (current === TOTAL - 1) {
      nx.textContent = 'Close Tour';
      nx.className   = 'btn btn-f';
    } else {
      nx.textContent = 'Continue';
      nx.className   = 'btn btn-p';
    }
  }
 
  function navigate(dir) {
    if (current === TOTAL - 1 && dir === 1) { window.close(); return; }
    goTo(current + dir);
  }
 
  bk.addEventListener('click', () => navigate(-1));
  nx.addEventListener('click', () => navigate(1));
 
  bk.style.opacity       = '0';
  bk.style.pointerEvents = 'none';
  bk.style.transition    = 'opacity 0.2s';
 
  // ==========================================================================
  // Live controls
  //
  // Steps 3 and 4 used to render engine cards and toggles that looked exactly
  // like the real ones in the popup but did nothing — people reasonably tried
  // to set up the extension from here and concluded it was broken. These now
  // write to the same chrome.storage.local keys the popup and settings page
  // read, so whatever the user picks during the tour is what they get.
  // ==========================================================================
 
  const RULE_KEYS = ['autoScan', 'showBanner', 'scanChanges'];
 
  function setTog(el, on) {
    if (el) el.classList.toggle('off', !on);
  }
 
  function note(id, text) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = text;
  }
 
  function onActivate(el, handler) {
    if (!el) return;
    el.addEventListener('click', handler);
    el.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); handler(); }
    });
  }
 
  async function initControls() {
    if (typeof chrome === 'undefined' || !chrome.storage?.local) return;
 
    const localCard  = document.getElementById('ob-mode-local');
    const cloudCard  = document.getElementById('ob-mode-cloud');
    const localBadge = document.getElementById('ob-badge-local');
    const cloudBadge = document.getElementById('ob-badge-cloud');
 
    // Can this browser actually run the on-device engine? If not, say so here
    // rather than letting someone pick Strict Offline and then watch every
    // scan fail.
    let localUsable = false;
    try {
      if (self.LanguageModel) {
        let availability;

        try {
          availability = await self.LanguageModel.availability({
            expectedOutputs: [{ type: 'text', languages: ['en'] }],
          });
        } catch {
          availability = await self.LanguageModel.availability();
        }
        localUsable = availability === 'available' || availability === 'readily'
                   || availability === 'downloadable' || availability === 'downloading'
                   || availability === 'after-download';
      }
    } catch { localUsable = false; }
 
    const stored = await chrome.storage.local.get(['activeMode', ...RULE_KEYS]);
    let mode = stored.activeMode || (localUsable ? 'local' : 'cloud');
    if (mode === 'local' && !localUsable) mode = 'cloud';
 
    function paintMode(selected) {
      localCard?.classList.toggle('sel', selected === 'local');
      cloudCard?.classList.toggle('sel', selected === 'cloud');
      if (localBadge) localBadge.textContent = !localUsable
        ? 'Not available here'
        : (selected === 'local' ? 'Selected' : 'Recommended');
      if (cloudBadge) cloudBadge.style.display = selected === 'cloud' ? '' : 'none';
    }
 
    if (!localUsable) {
      localCard?.classList.add('disabled');
      note('ob-engine-note-text', "Your browser can't run the on-device engine, so Dad's using Hybrid Cloud. Saved automatically.");
    } else {
      note('ob-engine-note-text', 'Saved automatically — change it anytime in the popup.');
    }
    paintMode(mode);
 
    async function setMode(next) {
      if (next === 'local' && !localUsable) return;
      paintMode(next);
      await chrome.storage.local.set({ activeMode: next });
      try { await chrome.runtime.sendMessage({ action: 'setMode', mode: next }); } catch { /* worker asleep; storage still wins */ }
      note('ob-engine-note-text', next === 'local'
        ? 'Strict Offline it is. Nothing leaves your device.'
        : 'Hybrid Cloud it is. Fast everywhere.');
    }
 
    onActivate(localCard, () => setMode('local'));
    onActivate(cloudCard, () => setMode('cloud'));
 
    // --- Step 4 toggles (default on, matching settings.js) ---
    RULE_KEYS.forEach((key) => {
      const el = document.getElementById('ob-' + key);
      if (!el) return;
      let value = stored[key] !== false;
      setTog(el, value);
      onActivate(el, async () => {
        value = !value;
        setTog(el, value);
        await chrome.storage.local.set({ [key]: value });
        note('ob-rules-note', 'Saved. Dad took notes.');
      });
    });
  }
 
  initControls();
})();