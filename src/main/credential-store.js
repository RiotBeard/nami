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
const validId = id => typeof id === 'string' && (id.startsWith('named:') ? validName(id.slice(6)) : id.startsWith('legacy:') && LEGACY.includes(id.slice(7)));
const ERROR = 'Saved keys are unavailable. Unlock your system key store, check disk space and file permissions, then retry. If the credential file is damaged, restore an encrypted copy for this app profile.';
function preferences(doc) {
  const out = { ...doc }; delete out.envKeys;
  for (const key of LEGACY) delete out[key];
  return out;
}
function secretFields(doc) {
  return Object.fromEntries(['envKeys', ...LEGACY].filter(key => own(doc, key)).map(key => [key, doc[key]]));
}
function createCredentialStore({ file, settingsFile, encryption, io = ioDefault, platform = process.platform }) {
  let state = null, error = 'Saved keys have not been initialized.';
  function protect() {
    if (!['darwin', 'win32', 'linux'].includes(platform) || !encryption.isEncryptionAvailable()) throw new Error(ERROR);
    if (platform === 'linux' && ['basic_text', 'unknown'].includes(encryption.getSelectedStorageBackend())) throw new Error(ERROR);
  }
  function settings() {
    if (!io.exists(settingsFile)) return {};
    const doc = JSON.parse(io.read(settingsFile));
    if (!record(doc)) throw new Error(ERROR);
    return doc;
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
  function guarded(fn) {
    try { return fn(); } catch (_) { state = null; error = ERROR; return { ok: false, error }; }
  }
  function ready() {
    try { if (error || !state) throw new Error(ERROR); protect(); }
    catch (_) { state = null; error = ERROR; throw new Error(ERROR); }
  }
  function initialize() {
    return guarded(() => {
      protect();
      const source = settings();
      const next = io.exists(file) ? load() : { version: 1, migration: 'pending', named: {}, legacy: {}, imported: [], tombstones: {} };
      if (next.migration === 'pending') {
        if (source.envKeys !== undefined && !record(source.envKeys)) throw new Error(ERROR);
        for (const [name, value] of Object.entries(source.envKeys || {})) {
          if (!validName(name) || typeof value !== 'string') throw new Error(ERROR);
          const id = 'named:' + name;
          if (!own(next.named, name) && !own(next.tombstones, id) && !next.imported.includes(id)) next.named[name] = value;
          if (!next.imported.includes(id)) next.imported.push(id);
        }
        for (const name of LEGACY) if (own(source, name) && source[name] != null) {
          if (typeof source[name] !== 'string') throw new Error(ERROR);
          const id = 'legacy:' + name;
          if (!own(next.legacy, name) && !own(next.tombstones, id) && !next.imported.includes(id)) next.legacy[name] = source[name];
          if (!next.imported.includes(id)) next.imported.push(id);
        }
      }
      if (next.migration === 'pending') persist(next);
      else state = next; // load() has already verified the persisted ciphertext.
      const current = settings();
      // An external writer may add a key while ciphertext is being persisted.
      // Preserve its source and retry instead of removing an unimported value.
      if (next.migration === 'pending' && JSON.stringify(secretFields(current)) !== JSON.stringify(secretFields(source))) throw new Error(ERROR);
      if (own(current, 'envKeys') || LEGACY.some(k => own(current, k))) io.write(settingsFile, JSON.stringify(preferences(current), null, 2) + '\n');
      if (next.migration !== 'complete') persist({ ...next, migration: 'complete' });
      error = null;
      return { ok: true };
    });
  }
  function change(fn) {
    return guarded(() => {
      ready();
      // A damaged or replaced vault must not be overwritten from a stale cache.
      const next = load();
      if (next.migration !== 'complete') throw new Error(ERROR);
      settings(); // preserve unreadable sources before starting a transaction
      fn(next);
      persist(next);
      const current = settings();
      if (own(current, 'envKeys') || LEGACY.some(k => own(current, k))) {
        io.write(settingsFile, JSON.stringify(preferences(current), null, 2) + '\n');
      }
      return { ok: true };
    });
  }
  function set(name, value) {
    if (!validName(name) || typeof value !== 'string' || !value.trim()) return { ok: false, error: 'Enter a valid key name and nonempty secret.' };
    return change(next => { next.named[name] = value.trim(); delete next.tombstones['named:' + name]; });
  }
  function remove(name) {
    if (typeof name !== 'string' || !(validName(name) || (name.startsWith('legacy:') && LEGACY.includes(name.slice(7))))) return { ok: false, error: 'Invalid key name.' };
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
  function context() { ready(); return { envKeys: { ...state.named }, ...state.legacy }; }
  function list() {
    return guarded(() => {
      ready();
      const stored = Object.entries(state.named)
        .map(([name, value]) => ({ name, masked: masked(value) }))
        .sort((a, b) => a.name.localeCompare(b.name));
      const legacy = Object.entries(state.legacy)
        .map(([name, value]) => ({ name: 'legacy:' + name, masked: masked(value) }));
      return { ok: true, stored, legacy };
    });
  }
  function reveal(name) {
    if (typeof name !== 'string' || !(validName(name) || (name.startsWith('legacy:') && LEGACY.includes(name.slice(7))))) return { ok: false, error: 'Invalid key name.' };
    return guarded(() => {
      ready();
      const legacy = name.startsWith('legacy:');
      const entries = legacy ? state.legacy : state.named;
      const key = legacy ? name.slice(7) : name;
      return { ok: true, value: own(entries, key) ? entries[key] : '' };
    });
  }
  return { initialize, set, remove, setLegacy, context, list, reveal, status: () => ({ ok: !error, error }), preferences };
}
module.exports = { createCredentialStore, preferences, LEGACY, ERROR };
