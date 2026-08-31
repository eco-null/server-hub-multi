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
 *   features     { clock, greeting, stats, statusPings, search, beszelUptime }  (booleans)
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
const BOOTSTRAP_CACHE_KEY = 'server-hub:bootstrap-cache';
const BOOTSTRAP_TTL = 5*60*1000;

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
    mode: 'gradient',
    gradient: 'grid',
    url: '',
    showGrid: true,
  },
  features: {
    clock: true,
    greeting: true,
    stats: true,
    statusPings: true,
    search: true,
    beszelUptime: true,
  },
  search: {
    provider: 'google',
    searxngUrl: '',
  },
  beszel: {
    url: '',
    user: '',
    password: '',
  },
  beszels: [],
  services: [],
});

// --- beszel passwords kept only in memory and server, never in localStorage ---
let _memoryBeszelPasswords = new Map(); // id -> password, '__single__' for legacy single beszel
// read() memoization — cache last raw string and parsed result
let _readCacheRawStr = null;
let _readCacheResult = null;
let _readCachePassword = null;
function _mapCacheKey() {
  try { return JSON.stringify([..._memoryBeszelPasswords.entries()].sort((a,b)=>String(a[0]).localeCompare(String(b[0])))); } catch { return ''; }
}
// wallpaper helpers — cache DOM lookup + race guard
let wallpaperElCache = null;
let wallpaperSeq = 0;
function _getWallpaperEl() {
  if (wallpaperElCache) return wallpaperElCache;
  try { wallpaperElCache = document.getElementById('wallpaper'); } catch { wallpaperElCache = null; }
  return wallpaperElCache;
}
function _invalidateReadCache() {
  _readCacheRawStr = null;
  _readCacheResult = null;
  _readCachePassword = null;
}
function _captureBeszelPasswordsFromRemote(remote) {
  if (!remote || typeof remote !== 'object') return false;
  let changed = false;
  if (Array.isArray(remote.beszels)) {
    remote.beszels.forEach(b => {
      if (!b || typeof b.id !== 'string' || !b.id) return;
      if (typeof b.password === 'string' && b.password) {
        _memoryBeszelPasswords.set(b.id, b.password);
        changed = true;
      } else if ('password' in b) {
        // empty string -> keep existing Map value, delete from remote so deepMerge keeps old
        if (b.password === '' || b.password === null || b.password === undefined) {
          delete b.password;
        } else if (typeof b.password === 'string' && !b.password) {
          delete b.password;
        }
      }
    });
  }
  if (remote.beszel && typeof remote.beszel.password === 'string') {
    if (remote.beszel.password) {
      _memoryBeszelPasswords.set('__single__', remote.beszel.password);
      changed = true;
      // also sync to first beszels entry if present (legacy -> multi migration)
      if (Array.isArray(remote.beszels) && remote.beszels[0] && typeof remote.beszels[0].id === 'string' && remote.beszels[0].id) {
        _memoryBeszelPasswords.set(remote.beszels[0].id, remote.beszel.password);
      }
    } else if ('password' in remote.beszel) {
      delete remote.beszel.password;
    }
  }
  if (changed) _invalidateReadCache();
  return changed;
}
function _sanitizeForLocal(settings) {
  try {
    const copy = JSON.parse(JSON.stringify(settings));
    if (copy && copy.beszel && 'password' in copy.beszel) delete copy.beszel.password;
    if (copy && Array.isArray(copy.beszels)) copy.beszels.forEach(b => { if (b && 'password' in b) b.password = ''; });
    return copy;
  } catch { return settings; }
}
function _isValidHttpUrl(s) {
  try { const u = new URL(String(s)); return u.protocol === 'https:' || u.protocol === 'http:'; } catch { return false; }
}
function _updateBootstrapCacheWithSettings(nextSettings, layout) {
  try {
    let existing = null;
    try {
      const raw = safeStorage.getItem(BOOTSTRAP_CACHE_KEY);
      if (raw) { const p = JSON.parse(raw); if (p && p.data) existing = p.data; }
    } catch {}
    const sanitized = _sanitizeForLocal(nextSettings);
    const payload = existing ? { ...existing } : {};
    payload.settings = sanitized;
    if (layout !== undefined) payload.layout = layout;
    else if (existing && existing.layout !== undefined) payload.layout = existing.layout;
    try { safeStorage.setItem(BOOTSTRAP_CACHE_KEY, JSON.stringify({ t: Date.now(), data: payload })); } catch {}
  } catch {}
}

function read() {
  let rawStr;
  try { rawStr = safeStorage.getItem(SETTINGS_KEY) || '{}'; } catch { rawStr = '{}'; }
  const _curMapKey = _mapCacheKey();
  if (rawStr === _readCacheRawStr && _readCacheResult !== null && _readCachePassword === _curMapKey) {
    return _readCacheResult;
  }
  try {
    const raw = JSON.parse(rawStr);
    const merged = deepMerge(structuredCloneSafe(DEFAULTS), raw);
    // legacy beszel -> beszels migration: if raw has beszel with url and beszels empty/missing, create beszels array
    const rawHasBeszelUrl = raw && raw.beszel && typeof raw.beszel.url === 'string' && raw.beszel.url.trim() !== '';
    const rawBeszelsMissingOrEmpty = !raw || !Array.isArray(raw.beszels) || raw.beszels.length === 0;
    const mergedBeszelsEmpty = !Array.isArray(merged.beszels) || merged.beszels.length === 0;
    if (rawHasBeszelUrl && rawBeszelsMissingOrEmpty && mergedBeszelsEmpty) {
      merged.beszels = [{ id: Math.random().toString(36).slice(2,10), name: "", url: raw.beszel.url, user: raw.beszel.user || "", password: "" }];
    }
    // re-inject passwords per beszels entry from Map
    if (Array.isArray(merged.beszels)) {
      merged.beszels.forEach(b => {
        if (b && typeof b.id === 'string' && _memoryBeszelPasswords.has(b.id)) {
          b.password = _memoryBeszelPasswords.get(b.id);
        } else if (b && b.id && !_memoryBeszelPasswords.has(b.id) && 'password' in b && b.password) {
          // sanitize stray non-empty password that wasn't captured (should be blanked)
          b.password = '';
        } else if (b && !b.id) {
          // no id, cannot inject, ensure password blank if present
          if ('password' in b && b.password) b.password = '';
        }
      });
    }
    // legacy single beszel password re-inject
    if (_memoryBeszelPasswords.has('__single__')) {
      merged.beszel = merged.beszel || { url: '', user: '', password: '' };
      merged.beszel.password = _memoryBeszelPasswords.get('__single__');
    } else if (merged.beszel && 'password' in merged.beszel) {
      // ensure empty string when no stored password
      merged.beszel.password = '';
    } else if (merged.beszel && !('password' in merged.beszel)) {
      merged.beszel.password = '';
    }
    _readCacheRawStr = rawStr;
    _readCacheResult = merged;
    _readCachePassword = _curMapKey;
    return merged;
  } catch {
    const fallback = structuredCloneSafe(DEFAULTS);
    if (Array.isArray(fallback.beszels)) {
      fallback.beszels.forEach(b => {
        if (b && b.id && _memoryBeszelPasswords.has(b.id)) b.password = _memoryBeszelPasswords.get(b.id);
      });
    }
    if (_memoryBeszelPasswords.has('__single__')) {
      fallback.beszel = fallback.beszel || { url: '', user: '', password: '' };
      fallback.beszel.password = _memoryBeszelPasswords.get('__single__');
    } else if (fallback.beszel && 'password' in fallback.beszel) {
      fallback.beszel.password = '';
    }
    _readCacheRawStr = rawStr;
    _readCacheResult = fallback;
    _readCachePassword = _curMapKey;
    return fallback;
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
  const originalPartial = partial ? JSON.parse(JSON.stringify(partial)) : {};
  // Work on a clone so we can strip empty passwords before deepMerge
  let working = partial ? JSON.parse(JSON.stringify(partial)) : {};
  let mapChanged = false;
  // capture beszels passwords: for each entry in partial.beszels
  if (working && Array.isArray(working.beszels)) {
    working.beszels.forEach((entry) => {
      if (!entry || typeof entry !== 'object') return;
      const origEntry = Array.isArray(originalPartial.beszels)
        ? originalPartial.beszels.find(e => e && e.id === entry.id)
        : null;
      if (typeof entry.password === 'string' && entry.password) {
        if (entry.id) { _memoryBeszelPasswords.set(entry.id, entry.password); mapChanged = true; }
      } else {
        // password === "" or missing -> keep old Map value and delete password from partial before deepMerge
        if ('password' in entry) delete entry.password;
        if (origEntry && 'password' in origEntry) delete origEntry.password;
      }
    });
  } else if (Array.isArray(originalPartial.beszels)) {
    // clean empty passwords from server payload even if working has no beszels (edge)
    originalPartial.beszels.forEach(entry => {
      if (!entry) return;
      if (typeof entry.password === 'string' && entry.password === '') delete entry.password;
      else if (!('password' in entry) || entry.password === undefined) { if ('password' in entry) delete entry.password; }
    });
  }
  // capture legacy single beszel password and sync to first beszels entry
  if (working && working.beszel && typeof working.beszel.password === 'string') {
    if (working.beszel.password) {
      _memoryBeszelPasswords.set('__single__', working.beszel.password);
      mapChanged = true;
      // sync to first beszels entry id if available
      let targetId = null;
      if (Array.isArray(working.beszels) && working.beszels[0] && working.beszels[0].id) targetId = working.beszels[0].id;
      else if (Array.isArray(originalPartial.beszels) && originalPartial.beszels[0] && originalPartial.beszels[0].id) targetId = originalPartial.beszels[0].id;
      if (targetId) { _memoryBeszelPasswords.set(targetId, working.beszel.password); }
    } else if ('password' in working.beszel) {
      delete working.beszel.password;
      if (originalPartial && originalPartial.beszel && 'password' in originalPartial.beszel) delete originalPartial.beszel.password;
      // also strip empty password from first beszels entry if it mirrored legacy
      if (Array.isArray(working.beszels) && working.beszels[0] && 'password' in working.beszels[0] && working.beszels[0].password === '') {
        delete working.beszels[0].password;
      }
      if (Array.isArray(originalPartial.beszels) && originalPartial.beszels[0] && 'password' in originalPartial.beszels[0] && originalPartial.beszels[0].password === '') {
        delete originalPartial.beszels[0].password;
      }
    }
  }
  if (mapChanged) _invalidateReadCache();
  const cur = read();
  const next = deepMerge(cur, working);
  // re-inject Map passwords into next for current session
  if (Array.isArray(next.beszels)) {
    next.beszels.forEach(b => {
      if (b && b.id && _memoryBeszelPasswords.has(b.id)) b.password = _memoryBeszelPasswords.get(b.id);
      else if (b && 'password' in b && b.password && b.id && !_memoryBeszelPasswords.has(b.id)) b.password = '';
    });
  }
  if (_memoryBeszelPasswords.has('__single__')) {
    next.beszel = next.beszel || { url: '', user: '', password: '' };
    next.beszel.password = _memoryBeszelPasswords.get('__single__');
  } else if (next.beszel && 'password' in next.beszel) {
    next.beszel.password = '';
  }
  try { safeStorage.setItem(SETTINGS_KEY, JSON.stringify(_sanitizeForLocal(next))); } catch {}
  _invalidateReadCache();
  try { _readCacheRawStr = safeStorage.getItem(SETTINGS_KEY) || '{}'; _readCacheResult = next; _readCachePassword = _mapCacheKey(); } catch {}
  _saveToServer(originalPartial);
  emit(next);
  return next;
}

/* Pull settings from the server (Supabase) when available and merge them over
 * current ones (server wins — it is the cross-device source of truth). */
function _stableStringify(obj) {
  // Order-independent JSON for hasLocalChanges check (MED-05)
  const seen = new WeakSet();
  function sortKeys(o) {
    if (o && typeof o === 'object' && !Array.isArray(o)) {
      if (seen.has(o)) return o;
      seen.add(o);
      const out = {};
      Object.keys(o).sort().forEach(k => { out[k] = sortKeys(o[k]); });
      return out;
    }
    if (Array.isArray(o)) return o.map(sortKeys);
    return o;
  }
  return JSON.stringify(sortKeys(obj));
}
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
      // capture beszels and legacy beszel passwords into Map before sanitizing
      _captureBeszelPasswordsFromRemote(remote);
      // If remote is empty (new user), don't keep old user's local settings — reset to defaults first
      const isEmptyRemote = Object.keys(remote).length === 0;
      let next;
      if (isEmptyRemote) {
        // Check if local has non-default values that would leak to new user
        const cur = read();
        const hasLocalChanges = _stableStringify(_sanitizeForLocal(cur)) !== _stableStringify(_sanitizeForLocal(DEFAULTS));
        if (hasLocalChanges) {
          next = deepMerge(structuredCloneSafe(DEFAULTS), remote);
          if (Array.isArray(next.beszels)) next.beszels.forEach(b => { if (b && b.id && _memoryBeszelPasswords.has(b.id)) b.password = _memoryBeszelPasswords.get(b.id); });
          if (_memoryBeszelPasswords.has('__single__')) { next.beszel = next.beszel || {}; next.beszel.password = _memoryBeszelPasswords.get('__single__'); }
          else if (next.beszel && 'password' in next.beszel) next.beszel.password = '';
          try { safeStorage.setItem(SETTINGS_KEY, JSON.stringify(_sanitizeForLocal(next))); } catch {}
          _invalidateReadCache();
          try { _readCacheRawStr = safeStorage.getItem(SETTINGS_KEY) || '{}'; _readCacheResult = next; _readCachePassword = _mapCacheKey(); } catch {}
        } else {
          next = cur;
        }
      } else {
        // MED-05: server is authoritative — deletions must propagate.
        // deepMerge(cur, remote) kept stale local keys; instead build from defaults+remote
        // and replace top-level keys wholesale so removed keys are deleted.
        next = deepMerge(structuredCloneSafe(DEFAULTS), remote);
        if (Array.isArray(next.beszels)) next.beszels.forEach(b => { if (b && b.id && _memoryBeszelPasswords.has(b.id)) b.password = _memoryBeszelPasswords.get(b.id); });
        if (_memoryBeszelPasswords.has('__single__')) { next.beszel = next.beszel || {}; next.beszel.password = _memoryBeszelPasswords.get('__single__'); }
        else if (next.beszel && 'password' in next.beszel) next.beszel.password = '';
        // Also handle case where remote explicitly deleted a top-level key that exists in cur
        // (already covered because we start from DEFAULTS not cur). For safety, also
        // ensure any non-default top-level key in cur not present in remote is removed
        // (next already doesn't have it).
        try { safeStorage.setItem(SETTINGS_KEY, JSON.stringify(_sanitizeForLocal(next))); } catch {}
        _invalidateReadCache();
        try { _readCacheRawStr = safeStorage.getItem(SETTINGS_KEY) || '{}'; _readCacheResult = next; _readCachePassword = _mapCacheKey(); } catch {}
      }
      emit(next);
      try { _updateBootstrapCacheWithSettings(next, row && row.layout); } catch {}
      return next;
    } catch {
      if (attempt < 2) { await new Promise(r => setTimeout(r, 800 * (attempt + 1))); continue; }
      return null;
    }
  }
  return null;
}
function _applyBootstrap(settings, layout) {
  if (!settings || typeof settings !== 'object') return null;
  _captureBeszelPasswordsFromRemote(settings);
  const isEmptyRemote = Object.keys(settings).length === 0;
  let next;
  if (isEmptyRemote) {
    const cur = read();
    const hasLocalChanges = _stableStringify(_sanitizeForLocal(cur)) !== _stableStringify(_sanitizeForLocal(DEFAULTS));
    if (hasLocalChanges) {
      next = deepMerge(structuredCloneSafe(DEFAULTS), settings);
      if (Array.isArray(next.beszels)) next.beszels.forEach(b => { if (b && b.id && _memoryBeszelPasswords.has(b.id)) b.password = _memoryBeszelPasswords.get(b.id); });
      if (_memoryBeszelPasswords.has('__single__')) { next.beszel = next.beszel || {}; next.beszel.password = _memoryBeszelPasswords.get('__single__'); }
      else if (next.beszel && 'password' in next.beszel) next.beszel.password = '';
      try { safeStorage.setItem(SETTINGS_KEY, JSON.stringify(_sanitizeForLocal(next))); } catch {}
      _invalidateReadCache();
      try { _readCacheRawStr = safeStorage.getItem(SETTINGS_KEY) || '{}'; _readCacheResult = next; _readCachePassword = _mapCacheKey(); } catch {}
    } else {
      next = cur;
    }
  } else {
    next = deepMerge(structuredCloneSafe(DEFAULTS), settings);
    if (Array.isArray(next.beszels)) next.beszels.forEach(b => { if (b && b.id && _memoryBeszelPasswords.has(b.id)) b.password = _memoryBeszelPasswords.get(b.id); });
    if (_memoryBeszelPasswords.has('__single__')) { next.beszel = next.beszel || {}; next.beszel.password = _memoryBeszelPasswords.get('__single__'); }
    else if (next.beszel && 'password' in next.beszel) next.beszel.password = '';
    try { safeStorage.setItem(SETTINGS_KEY, JSON.stringify(_sanitizeForLocal(next))); } catch {}
    _invalidateReadCache();
    try { _readCacheRawStr = safeStorage.getItem(SETTINGS_KEY) || '{}'; _readCacheResult = next; _readCachePassword = _mapCacheKey(); } catch {}
  }
  emit(next);
  try { _updateBootstrapCacheWithSettings(next, layout); } catch {}
  return next;
}

function subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); }

function clear() {
  try { clearTimeout(_syncTimer); } catch {}
  _syncTimer = null;
  _memoryBeszelPasswords.clear();
  try { safeStorage.removeItem(SETTINGS_KEY); } catch {}
  try { safeStorage.removeItem('server-hub:services'); } catch {}
  try { safeStorage.removeItem('server-hub:theme'); } catch {}
  _invalidateReadCache();
  const next = structuredCloneSafe(DEFAULTS);
  _readCacheRawStr = '{}';
  _readCacheResult = next;
  _readCachePassword = _mapCacheKey();
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

  // Page title + subtitle — don't overwrite Settings page title (MED-04)
  if (!location.pathname.includes('settings')) {
    document.title = s.pageTitle + ' — Self-Hosted Services';
  }
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

const GRID_OVERLAY_DARK = 'linear-gradient(rgba(255,255,255,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.025) 1px, transparent 1px)';
const GRID_OVERLAY_LIGHT = 'linear-gradient(rgba(15,23,42,0.06) 1px, transparent 1px), linear-gradient(90deg, rgba(15,23,42,0.06) 1px, transparent 1px)';

const GRADIENTS_BASE = {
  // Luxurious dark — racing green, dark velvet, midnight, carbon, no glows
  aurora: 'linear-gradient(160deg, #0a1f1a 0%, #0f2e1f 100%)',
  dusk: 'linear-gradient(160deg, #1a0a1a 0%, #2a0f2e 100%)',
  ocean: 'linear-gradient(160deg, #070f1a 0%, #0a1f33 100%)',
  forest: 'linear-gradient(160deg, #052e16 0%, #0a3321 100%)',
  mono: 'linear-gradient(160deg, #0a0a0a 0%, #141414 100%)',
  grid: 'linear-gradient(160deg, #0a0a0a 0%, #111111 100%)',
  slate: 'linear-gradient(160deg, #0f0f0f 0%, #1a1a1a 100%)',
  sage: 'linear-gradient(160deg, #0a1a12 0%, #143322 100%)',
};
const LIGHT_GRADIENTS_BASE = {
  aurora: 'linear-gradient(160deg, #e7e5e4 0%, #d6d3d1 100%)',
  dusk: 'linear-gradient(160deg, #ede9fe 0%, #ddd6fe 100%)',
  ocean: 'linear-gradient(160deg, #dbeafe 0%, #bfdbfe 100%)',
  forest: 'linear-gradient(160deg, #dcfce7 0%, #bbf7d0 100%)',
  mono: 'linear-gradient(160deg, #f5f5f4 0%, #e7e5e4 100%)',
  grid: 'linear-gradient(160deg, #fafaf9 0%, #f5f5f4 100%)',
  slate: 'linear-gradient(160deg, #f1f5f9 0%, #e2e8f0 100%)',
  sage: 'linear-gradient(160deg, #ecfdf5 0%, #d1fae5 100%)',
};
function buildGradient(key, isLight, showGrid) {
  const base = (isLight ? LIGHT_GRADIENTS_BASE[key] : GRADIENTS_BASE[key]) || GRADIENTS_BASE.mono;
  if (showGrid === false) return base;
  const grid = isLight ? GRID_OVERLAY_LIGHT : GRID_OVERLAY_DARK;
  return grid + ', ' + base;
}
// Back-compat: GRADIENTS and LIGHT_GRADIENTS return with grid by default (for swatches)
const GRADIENTS = GRADIENTS_BASE;
const LIGHT_GRADIENTS = LIGHT_GRADIENTS_BASE;

const GradientLuminance = { aurora: false, dusk: false, ocean: false, forest: false, mono: false };

function applyWallpaper(s) {
  const w = (s && s.wallpaper) || DEFAULTS.wallpaper;
  const body = document.body;
  body.classList.remove('wallpaper', 'wp-active');
  const root = document.documentElement;
  root.classList.remove('wallpaper-dark', 'wallpaper-light');
  // Blobs were removed permanently (see index.html:119) — keep no-op guard
  // for wallpaper mode switches so custom wallpapers still hide/show correctly
  // if the element is ever re-added.
  const blobsEl = document.querySelector('[data-feature="blobs"]');
  const setBlobs = (show) => { if (blobsEl) blobsEl.style.display = show ? '' : 'none'; };
  const showGrid = w.showGrid !== false;
  // Toggle body grid (for mode:none and as base for wallpaper)
  if (showGrid) {
    body.style.removeProperty('background-image');
    body.style.removeProperty('background-size');
  } else {
    body.style.backgroundImage = 'none';
    body.style.backgroundSize = 'auto';
  }
  if (w.mode === 'gradient' && GRADIENTS[w.gradient]) {
    wallpaperSeq++;
    body.classList.add('wallpaper', 'wp-active');
    // Light theme uses the bright palette; dark theme keeps the rich palette.
    const isLightTheme = s && !isDark(s);
    const palette = buildGradient(w.gradient, isLightTheme, showGrid);
    body.style.setProperty('--wp-image', palette);
    const wallpaperEl = _getWallpaperEl();
    if (wallpaperEl) {
      if (showGrid) {
        wallpaperEl.style.backgroundSize = '32px 32px, 32px 32px, cover';
        wallpaperEl.style.backgroundRepeat = 'repeat, repeat, no-repeat';
        if (w.gradient === 'grid') wallpaperEl.style.backgroundSize = '44px 44px, 44px 44px, cover';
      } else {
        wallpaperEl.style.backgroundSize = 'cover';
        wallpaperEl.style.backgroundRepeat = 'no-repeat';
      }
    }
    // Light palette gradients are bright → wallpaper-light (light text over
    // blur stays readable); dark palette → wallpaper-dark as before.
    root.classList.add(isLightTheme ? 'wallpaper-light' : 'wallpaper-dark');
    setBlobs(true);
  } else if (w.mode === 'custom' && w.url) {
    if (!_isValidHttpUrl(w.url)) {
      wallpaperSeq++;
      body.style.removeProperty('--wp-image');
      const wallpaperElBad = _getWallpaperEl();
      if (wallpaperElBad) wallpaperElBad.style.backgroundSize = '';
      setBlobs(true);
      return;
    }
    body.classList.add('wallpaper', 'wp-active');
    const isLightThemeCustom = s && !isDark(s);
    const gridOverlay = showGrid ? (isLightThemeCustom ? GRID_OVERLAY_LIGHT : GRID_OVERLAY_DARK) : '';
    const escapedUrl = w.url.replace(/"/g, '%22').replace(/\(/g, '%28').replace(/\)/g, '%29');
    const urlPart = 'url("' + escapedUrl + '")';
    const combined = gridOverlay ? gridOverlay + ', ' + urlPart : urlPart;
    body.style.setProperty('--wp-image', combined);
    const wallpaperElCustom = _getWallpaperEl();
    if (wallpaperElCustom) {
      if (showGrid) {
        wallpaperElCustom.style.backgroundSize = '32px 32px, 32px 32px, cover';
        wallpaperElCustom.style.backgroundRepeat = 'repeat, repeat, no-repeat';
      } else {
        wallpaperElCustom.style.backgroundSize = 'cover';
        wallpaperElCustom.style.backgroundRepeat = 'no-repeat';
      }
    }
    setBlobs(false);
    const seq = ++wallpaperSeq;
    sampleImageLuminance(w.url).then(dark => {
      if (seq !== wallpaperSeq) return;
      root.classList.toggle('wallpaper-dark', dark);
      root.classList.toggle('wallpaper-light', !dark);
    }).catch(err => {
      if (seq !== wallpaperSeq) return;
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
    wallpaperSeq++;
    body.style.removeProperty('--wp-image');
    const wallpaperEl = _getWallpaperEl();
    if (wallpaperEl) wallpaperEl.style.backgroundSize = '';
    // Respect showGrid for none/custom too (body grid)
    if (!showGrid) {
      body.style.backgroundImage = 'none';
    }
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
    _applyBootstrap,
    isDark,
    hexToRgba,
    GRADIENTS,
    applyWallpaper,
  };
}