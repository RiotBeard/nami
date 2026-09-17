// Synchronous main-process transactions cannot interleave across IPC handlers.
// The encrypted journal is committed before plaintext cleanup and survives restarts.
const fs = require('node:fs');
const { writePrivateConfig } = require('./private-config');
const LEGACY = ['openaiKey', 'elevenKey', 'sttKey'];
const ALIASES = { OPENAI_API_KEY: 'openaiKey', ELEVENLABS_API_KEY: 'elevenKey' };
const ioDefault = { exists: fs.existsSync, read: f => fs.readFileSync(f, 'utf8'), write: writePrivateConfig };
const record = v => v && typeof v === 'object' && !Array.isArray(v);
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const validName = n => typeof n === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(n) && !['__proto__', 'constructor', 'prototype'].includes(n);
const masked = value => '••••••••' + (value.length > 4 ? value.slice(-4) : '');
const validRef = name => typeof name === 'string' && (validName(name) || (name.startsWith('legacy:') && LEGACY.includes(name.slice(7))));
const validId = id => typeof id === 'string' && (id.startsWith('named:') ? validName(id.slice(6)) : id.startsWith('legacy:') && LEGACY.includes(id.slice(7)));
const ERROR = 'Saved keys are unavailable. Unlock your system key store, check disk space and file permissions, then retry. If the credential file is damaged, restore an encrypted copy for this app profile.';
const SETTINGS_ERROR = 'settings.json is unreadable. Fix or restore that file, then retry. Nothing was overwritten.';
function preferences(doc) {
  const out = { ...doc }; delete out.envKeys;
  for (const key of LEGACY) delete out[key];
  return out;
}
function secretFields(doc) {
  return Object.fromEntries(['envKeys', ...LEGACY].filter(key => own(doc, key)).map(key => [key, doc[key]]));
}
function sourceError() { const e = new Error(SETTINGS_ERROR); e.kind = 'settings'; return e; }
function createCredentialStore({ file, settingsFile, encryption, io = ioDefault, platform = process.platform }) {
  // `state` is the last vault this process verified. Reads serve it from memory
  // and never throw: a store that is unavailable yields no saved keys, it does
  // not take terminals, agent status or shell-provided keys down with it.
  let state = null, error = 'Saved keys have not been initialized.', kind = 'storage';
  function protect() {
    if (!['darwin', 'win32', 'linux'].includes(platform) || !encryption.isEncryptionAvailable()) throw new Error(ERROR);
    if (platform === 'linux' && ['basic_text', 'unknown'].includes(encryption.getSelectedStorageBackend())) throw new Error(ERROR);
  }
  function settings() {
    try {
      if (!io.exists(settingsFile)) return {};
      const doc = JSON.parse(io.read(settingsFile));
      if (!record(doc)) throw new Error();
      return doc;
    } catch (_) { throw sourceError(); }
  }
  // Remove plaintext key fields from settings.json, keeping every preference.
  function scrubSettings() {
    const current = settings();
    if (own(current, 'envKeys') || LEGACY.some(k => own(current, k))) io.write(settingsFile, JSON.stringify(preferences(current), null, 2) + '\n');
  }
  function validate(doc) {
    if (!record(doc) || doc.version !== 1 || !['pending', 'complete'].includes(doc.migration)
      || !record(doc.named) || !record(doc.legacy) || !record(doc.tombstones) || !Array.isArray(doc.imported)) throw new Error(ERROR);
    const namedValid = Object.entries(doc.named).every(([k, v]) => validName(k) && typeof v === 'string');
    const legacyValid = Object.entries(doc.legacy).every(([k, v]) => LEGACY.includes(k) && typeof v === 'string');
    if (!namedValid || !legacyValid) throw new Error(ERROR);
    if (!doc.imported.every(validId) || !Object.entries(doc.tombstones).every(([k,v]) => validId(k) && v === true)) throw new Error(ERROR);
    return doc;
  }
  function load() {
    const envelope = JSON.parse(io.read(file));
    if (!record(envelope) || envelope.version !== 1 || typeof envelope.ciphertext !== 'string'
      || !envelope.ciphertext || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(envelope.ciphertext)) throw new Error(ERROR);
    return validate(JSON.parse(encryption.decryptString(Buffer.from(envelope.ciphertext, 'base64'))));
  }
  function persist(next) {
    protect();
    const text = JSON.stringify(validate(next));
    const encrypted = encryption.encryptString(text);
    // Catch unusable encryption output before replacing a previously valid vault.
    if (!Buffer.isBuffer(encrypted) || !encrypted.length || encryption.decryptString(encrypted) !== text) throw new Error(ERROR);
    io.write(file, JSON.stringify({ version: 1, ciphertext: encrypted.toString('base64') }) + '\n');
    const verified = load();
    if (JSON.stringify(verified) !== text) throw new Error(ERROR);
    state = verified;
  }
  // The store itself is unusable (as opposed to one operation having failed).
  function unavailable(why) {
    state = null; kind = why === 'settings' ? 'settings' : 'storage';
    error = kind === 'settings' ? SETTINGS_ERROR : ERROR;
    return { ok: false, error };
  }
  function initialize() {
    try {
      protect();
      const next = io.exists(file) ? load() : { version: 1, migration: 'pending', named: {}, legacy: {}, imported: [], tombstones: {} };
      if (next.migration === 'complete') {
        // load() has already verified the persisted ciphertext. A finished
        // migration no longer needs settings.json, so a damaged preferences file
        // must not take saved keys down; stale plaintext is scrubbed when it can be.
        state = next; error = null;
        try { scrubSettings(); } catch (_) {}
        return { ok: true };
      }
      // A pending migration needs its source: fail closed and leave it untouched.
      const source = settings();
      if (source.envKeys !== undefined && !record(source.envKeys)) throw sourceError();
      for (const [name, value] of Object.entries(source.envKeys || {})) {
        if (!validName(name) || typeof value !== 'string') throw sourceError();
        const id = 'named:' + name;
        if (!own(next.named, name) && !own(next.tombstones, id) && !next.imported.includes(id)) next.named[name] = value;
        if (!next.imported.includes(id)) next.imported.push(id);
      }
      for (const name of LEGACY) if (own(source, name) && source[name] != null) {
        if (typeof source[name] !== 'string') throw sourceError();
        const id = 'legacy:' + name;
        if (!own(next.legacy, name) && !own(next.tombstones, id) && !next.imported.includes(id)) next.legacy[name] = source[name];
        if (!next.imported.includes(id)) next.imported.push(id);
      }
      persist(next);
      // An external writer may add a key while ciphertext is being persisted.
      // Preserve its source and retry instead of removing an unimported value.
      if (JSON.stringify(secretFields(settings())) !== JSON.stringify(secretFields(source))) throw new Error(ERROR);
      scrubSettings();
      persist({ ...next, migration: 'complete' });
      error = null;
      return { ok: true };
    } catch (e) { return unavailable(e && e.kind); }
  }
  function change(fn) {
    if (error || !state) return { ok: false, error: error || ERROR };
    let next;
    // Cannot encrypt right now: refuse the write, keep serving what is in memory.
    try { protect(); } catch (_) { return { ok: false, error: ERROR }; }
    // A damaged or replaced vault must not be overwritten from a stale cache.
    try { next = load(); if (next.migration !== 'complete') throw new Error(ERROR); }
    catch (_) { return unavailable('storage'); }
    fn(next);
    const wanted = JSON.stringify(next);
    try { persist(next); }
    catch (_) {
      // The write is an atomic rename, so the disk holds the old vault or the
      // new one, never a partial. Adopt whichever verifies; only a vault that no
      // longer verifies makes the store unavailable.
      try { state = load(); } catch (_) { return unavailable('storage'); }
      if (JSON.stringify(state) !== wanted) return { ok: false, error: ERROR };
    }
    // The key is committed. Plaintext cleanup is retried on the next change or launch.
    try { scrubSettings(); } catch (_) {}
    return { ok: true };
  }
  function set(name, value) {
    if (!validName(name) || typeof value !== 'string' || !value.trim()) return { ok: false, error: 'Enter a valid key name and nonempty secret.' };
    return change(next => { next.named[name] = value.trim(); delete next.tombstones['named:' + name]; });
  }
  function remove(name) {
    if (!validRef(name)) return { ok: false, error: 'Invalid key name.' };
    return change(next => {
      if (name.startsWith('legacy:')) { const k = name.slice(7); delete next.legacy[k]; next.tombstones[name] = true; }
      else {
        delete next.named[name]; next.tombstones['named:' + name] = true;
        if (own(ALIASES, name)) { delete next.legacy[ALIASES[name]]; next.tombstones['legacy:' + ALIASES[name]] = true; }
      }
    });
  }
  function setLegacy(patch) {
    if (!record(patch) || LEGACY.some(k => own(patch, k) && patch[k] !== null && typeof patch[k] !== 'string')) {
      return { ok: false, error: 'API keys must be text, or null to remove them.' };
    }
    return change(next => {
      for (const k of LEGACY) {
        if (!own(patch, k)) continue;
        const value = patch[k];
        if (value === null || value === '') {
          delete next.legacy[k];
          next.tombstones['legacy:' + k] = true;
        } else {
          next.legacy[k] = value;
          delete next.tombstones['legacy:' + k];
        }
      }
    });
  }
  const usable = () => !error && !!state;
  const status = () => ({ ok: !error, error, kind: error ? kind : null });
  // Total by design: consumers (session env, speech, agent status) get no saved
  // keys when the store is unavailable, and ask status() if they need to say why.
  function context() { return usable() ? { envKeys: { ...state.named }, ...state.legacy } : { envKeys: {} }; }
  function list() {
    if (!usable()) return { ok: false, error: error || ERROR, kind };
    const stored = Object.entries(state.named)
      .map(([name, value]) => ({ name, masked: masked(value) }))
      .sort((a, b) => a.name.localeCompare(b.name));
    const legacy = Object.entries(state.legacy)
      .map(([name, value]) => ({ name: 'legacy:' + name, masked: masked(value) }));
    return { ok: true, stored, legacy };
  }
  function reveal(name) {
    if (!validRef(name)) return { ok: false, error: 'Invalid key name.' };
    if (!usable()) return { ok: false, error: error || ERROR };
    const legacy = name.startsWith('legacy:');
    const entries = legacy ? state.legacy : state.named;
    const key = legacy ? name.slice(7) : name;
    return { ok: true, value: own(entries, key) ? entries[key] : '' };
  }
  return { initialize, set, remove, setLegacy, context, list, reveal, status };
}
module.exports = { createCredentialStore, preferences, LEGACY, ERROR, SETTINGS_ERROR };
