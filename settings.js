/* settings.js — shared settings layer for Server Hub.
 *
 * Persists user personalization in localStorage under 'server-hub:settings'.
 * Consumed by both index.html (applies settings on load) and settings.html
 * (renders the editor UI). Keeping logic here avoids drift between the two.
 *
 * Keys:
 *   theme        'auto' | 'light' | 'dark'
 *   accent       hex string like '#5E6AD2'
 *   userName     string shown in greeting (empty = generic "Hello")
 *   pageTitle    string used as <h1> + document.title
 *   wallpaper    { mode, gradient, url } — background wallpaper ('none' | 'gradient' | 'custom')
 *   features     { clock, greeting, stats, statusPings, blobs, search }  (booleans)
 *   services     array of user-defined service entries (merged over defaults)
 *
 * Exposes:
 *   window.HubSettings.get()              -> current settings object
 *   window.HubSettings.set(partial)        -> merge + save + emit 'hub:settings'
 *   window.HubSettings.apply(settings)     -> apply to current document (tokens, features)
 *   window.HubSettings.defaults            -> pristine defaults
 *   window.HubSettings.subscribe(fn)       -> listener; returns unsubscribe
 */

const SETTINGS_KEY = 'server-hub:settings';

/* Storage shim — survives SecurityError on opaque origins (file://, sandbox,
 * private mode). Always returns a working storage; if localStorage throws,
 * we fall back to an in-memory Map so the rest of the app still functions.
 * Writes persist for the session; reloading the page resets to defaults.
 * Real persistence requires serving via http(s) — see SETUP.md. */
const safeStorage = (() => {
  try {
    const probe = '__hub_probe__';
    localStorage.setItem(probe, '1'); localStorage.removeItem(probe);
    return localStorage;
  } catch {
    const mem = new Map();
    return {
      getItem: k => mem.has(String(k)) ? mem.get(String(k)) : null,
      setItem: (k, v) => { mem.set(String(k), String(v)); },
      removeItem: k => { mem.delete(String(k)); },
      _ephemeral: true,
    };
  }
})();

const DEFAULTS = Object.freeze({
  theme: 'auto',
  accent: '#5E6AD2',
  userName: '',
  defaultDomain: '',
  pageTitle: 'Server Hub',
  subtitle: 'Your apps and services, reachable from one place.',
  wallpaper: {
    mode: 'none',
    gradient: 'aurora',
    url: '',
  },
  features: {
    clock: true,
    greeting: true,
    stats: true,
    statusPings: true,
    blobs: false,
    search: true,
    beszelUptime: true,
  },
  search: {
    provider: 'google',
    searxngUrl: '',
  },
  services: [],
});

function read() {
  try {
    const raw = JSON.parse(safeStorage.getItem(SETTINGS_KEY) || '{}');
    return deepMerge(structuredCloneSafe(DEFAULTS), raw);
  } catch {
    return structuredCloneSafe(DEFAULTS);
  }
}

// structuredClone exists in modern browsers; fall back if available only via JSON.
function structuredCloneSafe(o) {
  try { return structuredClone(o); }
  catch { return JSON.parse(JSON.stringify(o)); }
}

function deepMerge(base, over) {
  for (const k of Object.keys(over)) {
    // Reject prototype-pollution keys; they can come from a crafted imported
    // backup file or hand-edited localStorage.
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    if (over[k] && typeof over[k] === 'object' && !Array.isArray(over[k])) {
      base[k] = deepMerge(base[k] || {}, over[k]);
    } else if (over[k] !== undefined) {
      base[k] = over[k];
    }
  }
  return base;
}

const listeners = new Set();

function emit(s) { listeners.forEach(fn => { try { fn(s); } catch {} }); }

/* ---- Supabase/server sync (multi-user) ----
 * localStorage remains the fast local cache; every set() is ALSO pushed to
 * the server (/api/settings -> Supabase user_settings), and loadFromServer()
 * pulls the persisted copy on page load so settings follow the user across
 * devices. Failures are silent (local-first: the app must never break).
 */
let _syncTimer = null;
function _saveToServer(partial) {
  if (typeof fetch !== 'function') return;
  clearTimeout(_syncTimer);
  _syncTimer = setTimeout(() => {
    // SADECE değişen partial gönderilir — tam settings object değil.
    // Böylece DEFAULTS dolgusu (userName:'') server'daki gerçek değeri asla
    // ezmez; server tarafında deep-merge ile birleştirilir.
    fetch('/api/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ settings: partial, layout: {} }),
    }).catch(() => {});
  }, 250);
}

function set(partial) {
  const cur = read();
  const next = deepMerge(cur, partial);
  try { safeStorage.setItem(SETTINGS_KEY, JSON.stringify(next)); } catch {}
  _saveToServer(partial);
  emit(next);
  return next;
}

/* Pull settings from the server (Supabase) when available and merge them over
 * current ones (server wins — it is the cross-device source of truth). */
async function loadFromServer() {
  if (typeof fetch !== 'function') return null;
  // Retry: serverless cold-start ilk istekte 500 dönebilir — 2 ek deneme.
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const resp = await fetch('/api/settings', { headers: { 'Accept': 'application/json' }, cache: 'no-store' });
      if (!resp.ok) {
        if (attempt < 2) { await new Promise(r => setTimeout(r, 800 * (attempt + 1))); continue; }
        return null;
      }
      const row = await resp.json();
      const remote = (row && (row.settings || row)) || null;
      if (!remote || typeof remote !== 'object') return null;
      // If remote is empty (new user), don't keep old user's local settings — reset to defaults first
      const isEmptyRemote = Object.keys(remote).length === 0;
      let next;
      if (isEmptyRemote) {
        // Check if local has non-default values that would leak to new user
        const cur = read();
        const hasLocalChanges = JSON.stringify(cur) !== JSON.stringify(DEFAULTS);
        if (hasLocalChanges) {
          next = deepMerge(structuredCloneSafe(DEFAULTS), remote);
          try { safeStorage.setItem(SETTINGS_KEY, JSON.stringify(next)); } catch {}
        } else {
          next = cur;
        }
      } else {
        const cur = read();
        next = deepMerge(cur, remote);
        try { safeStorage.setItem(SETTINGS_KEY, JSON.stringify(next)); } catch {}
      }
      emit(next);
      return next;
    } catch {
      if (attempt < 2) { await new Promise(r => setTimeout(r, 800 * (attempt + 1))); continue; }
      return null;
    }
  }
  return null;
}

function subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); }

function clear() {
  try { safeStorage.removeItem(SETTINGS_KEY); } catch {}
  try { safeStorage.removeItem('server-hub:services'); } catch {}
  try { safeStorage.removeItem('server-hub:theme'); } catch {}
  const next = structuredCloneSafe(DEFAULTS);
  emit(next);
  return next;
}

function preferredDark() {
  return window.matchMedia('(prefers-color-scheme: dark)').matches;
}

function isDark(s) { return s.theme === 'dark' || (s.theme === 'auto' && preferredDark()); }

/* apply(settings)
 * Apply visual settings to the current document. Does NOT touch services
 * (index.html's renderGroups handles that separately so it can re-render).
 */
function apply(s) {
  const dark = isDark(s);
  document.documentElement.classList.toggle('dark',  dark);
  document.documentElement.classList.toggle('light', !dark);

  // Accent color
  document.documentElement.style.setProperty('--accent', s.accent);
  document.documentElement.style.setProperty('--accent-glow', hexToRgba(s.accent, 0.20));

  // Page title + subtitle
  document.title = s.pageTitle + ' — Self-Hosted Services';
  const h1 = document.querySelector('h1');
  if (h1 && h1.dataset.dynamic === 'true') h1.textContent = s.pageTitle;
  const sub = document.querySelector('[data-dynamic-subtitle]');
  if (sub) sub.textContent = s.subtitle;

  // Toggle feature visibility
  const f = s.features;
  const toggle = (sel, on) => { const el = document.querySelector(sel); if (el) el.style.display = on ? '' : 'none'; };
  toggle('[data-feature="clock"]',     f.clock);
  toggle('[data-feature="greeting"]',  f.greeting);
  toggle('[data-feature="stats"]',     f.stats);
  toggle('[data-feature="search"]',    f.search);
  toggle('[data-feature="blobs"]',     f.blobs); // container with all blobs (set in index)
  toggle('[data-feature="status"]',     f.statusPings); // dotted control handled in render

  // userName into greeting (marker element)
  const gEl = document.querySelector('[data-greeting-name]');
  if (gEl && f.greeting) gEl.dataset.userName = s.userName || '';
}

function hexToRgba(hex, a) {
  if (!hex || hex[0] !== '#') return 'rgba(94,106,210,' + a + ')';
  const h = hex.length === 4
    ? hex.slice(1).split('').map(c => c + c).join('')
    : hex.slice(1);
  const n = parseInt(h, 16);
  if (isNaN(n)) return 'rgba(94,106,210,' + a + ')';
  return 'rgba(' + ((n >> 16) & 255) + ',' + ((n >> 8) & 255) + ',' + (n & 255) + ',' + a + ')';
}

const GRADIENTS = {
  aurora: 'radial-gradient(1200px 800px at 15% 10%, #1e3a5f 0%, transparent 55%), radial-gradient(1000px 700px at 85% 20%, #5E6AD2 0%, transparent 50%), linear-gradient(160deg, #0b1020 0%, #1a2b4a 100%)',
  dusk: 'radial-gradient(1100px 750px at 80% 15%, #4a1e5f 0%, transparent 50%), radial-gradient(900px 650px at 20% 85%, #0f4a5f 0%, transparent 55%), linear-gradient(160deg, #0d0b1e 0%, #2a1438 100%)',
  ocean: 'radial-gradient(1100px 750px at 20% 15%, #0e4d64 0%, transparent 55%), linear-gradient(160deg, #04121c 0%, #0b2c3d 100%)',
  forest: 'radial-gradient(1000px 700px at 80% 10%, #1a4d2a 0%, transparent 55%), linear-gradient(160deg, #06120a 0%, #0f2a18 100%)',
  mono: 'linear-gradient(160deg, #0a0a0c 0%, #17171a 100%)',
  grid: 'radial-gradient(900px 520px at 7% 2%, rgba(140,167,255,0.12), transparent 66%), radial-gradient(700px 620px at 100% 100%, rgba(68,95,165,0.12), transparent 65%), linear-gradient(rgba(255,255,255,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.025) 1px, transparent 1px), linear-gradient(145deg, #080b12 0%, #101726 100%)',
};

/* Light-theme gradient palettes — used when the user picked light theme so
   the wallpaper stays bright instead of forcing a dark gradient. */
const LIGHT_GRADIENTS = {
  aurora: 'radial-gradient(1200px 800px at 15% 10%, #dbe7ff 0%, transparent 55%), radial-gradient(1000px 700px at 85% 20%, #c7d2fe 0%, transparent 50%), linear-gradient(160deg, #eef2ff 0%, #dbe4ff 100%)',
  dusk: 'radial-gradient(1100px 750px at 80% 15%, #f3e8ff 0%, transparent 50%), radial-gradient(900px 650px at 20% 85%, #e0f2fe 0%, transparent 55%), linear-gradient(160deg, #faf5ff 0%, #f0e6ff 100%)',
  ocean: 'radial-gradient(1100px 750px at 20% 15%, #cffafe 0%, transparent 55%), linear-gradient(160deg, #f0f9ff 0%, #d6f0ff 100%)',
  forest: 'radial-gradient(1000px 700px at 80% 10%, #dcfce7 0%, transparent 55%), linear-gradient(160deg, #f0fdf4 0%, #d9f5e0 100%)',
  mono: 'linear-gradient(160deg, #f8f8fa 0%, #eceef2 100%)',
  grid: 'radial-gradient(900px 520px at 7% 2%, rgba(73,104,216,0.08), transparent 66%), radial-gradient(700px 620px at 100% 100%, rgba(68,95,165,0.08), transparent 65%), linear-gradient(rgba(15,23,42,0.06) 1px, transparent 1px), linear-gradient(90deg, rgba(15,23,42,0.06) 1px, transparent 1px), linear-gradient(145deg, #f2f5fa 0%, #e7edf7 100%)',
};

const GradientLuminance = { aurora: false, dusk: false, ocean: false, forest: false, mono: false };

function applyWallpaper(s) {
  const w = (s && s.wallpaper) || DEFAULTS.wallpaper;
  const body = document.body;
  body.classList.remove('wallpaper', 'wp-active');
  const root = document.documentElement;
  root.classList.remove('wallpaper-dark', 'wallpaper-light');
  // Hide the animated gradient blobs behind a custom URL wallpaper.
  const blobsEl = document.querySelector('[data-feature="blobs"]');
  const setBlobs = (show) => { if (blobsEl) blobsEl.style.display = show ? '' : 'none'; };
  if (w.mode === 'gradient' && GRADIENTS[w.gradient]) {
    body.classList.add('wallpaper', 'wp-active');
    // Light theme uses the bright palette; dark theme keeps the rich palette.
    const isLightTheme = s && !isDark(s);
    const palette = isLightTheme && LIGHT_GRADIENTS[w.gradient] ? LIGHT_GRADIENTS[w.gradient] : GRADIENTS[w.gradient];
    body.style.setProperty('--wp-image', palette);
    // Login grid needs special background-size (44px grid), others use cover
    const wallpaperEl = document.getElementById('wallpaper');
    if (w.gradient === 'grid' && wallpaperEl) {
      wallpaperEl.style.backgroundSize = 'auto, auto, 44px 44px, 44px 44px, auto';
    } else if (wallpaperEl) {
      wallpaperEl.style.backgroundSize = '';
    }
    // Light palette gradients are bright → wallpaper-light (light text over
    // blur stays readable); dark palette → wallpaper-dark as before.
    root.classList.add(isLightTheme ? 'wallpaper-light' : 'wallpaper-dark');
    setBlobs(true);
  } else if (w.mode === 'custom' && w.url) {
    body.classList.add('wallpaper', 'wp-active');
    body.style.setProperty('--wp-image', 'url("' + w.url.replace(/"/g, '%22') + '")');
    setBlobs(false);
    sampleImageLuminance(w.url).then(dark => {
      root.classList.toggle('wallpaper-dark', dark);
      root.classList.toggle('wallpaper-light', !dark);
    }).catch(err => {
      if (err && err.tainted) {
        // Image loaded but pixels can't be read (no CORS). Keep the wallpaper
        // and default to dark — better than silently dropping a working image.
        root.classList.add('wallpaper-dark');
        root.classList.remove('wallpaper-light');
        return;
      }
      // Genuine load failure (e.g. dead URL): fall back to transparent + toast.
      applyWallpaper({ wallpaper: { mode: 'none' } });
      try { window.__hubToast && window.__hubToast('Wallpaper failed to load — reverted'); } catch {}
    });
  } else {
    body.style.removeProperty('--wp-image');
    setBlobs(true);
  }
}

/* Sentinel error so callers can distinguish a tainted canvas (image loaded,
 * but CORS blocked reading its pixels) from a genuine load failure. */
const TAINTED_CANVAS = { tainted: true };

function sampleImageLuminance(url) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    // No crossOrigin: hosts without CORS headers still load the image. We
    // just can't sample its pixels, so the caller defaults to wallpaper-dark.
    img.onload = () => {
      const c = document.createElement('canvas');
      c.width = 32; c.height = 32;
      const ctx = c.getContext('2d');
      try {
        ctx.drawImage(img, 0, 0, 32, 32);
        const d = ctx.getImageData(0, 0, 32, 32).data;
        let sum = 0, n = 0;
        for (let i = 0; i < d.length; i += 4) {
          sum += 0.2126 * d[i] + 0.7152 * d[i + 1] + 0.0722 * d[i + 2];
          n++;
        }
        resolve((sum / n) < 128); // dark background -> wallpaper-dark
      } catch (e) {
        // SecurityError on getImageData: canvas is tainted by a non-CORS
        // image. Reject with a distinct sentinel, not a generic error.
        if (e && (e.name === 'SecurityError' || e.code === 18)) reject(TAINTED_CANVAS);
        else reject(e);
      }
    };
    img.onerror = reject;
    img.src = url;
  });
}

if (typeof window !== 'undefined') {
  window.HubSettings = {
    KEY: SETTINGS_KEY,
    defaults: DEFAULTS,
    get: read,
    set,
    clear,
    apply,
    subscribe,
    loadFromServer,
    isDark,
    hexToRgba,
    GRADIENTS,
    applyWallpaper,
  };
}