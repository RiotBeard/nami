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
const CLEANUP_WARNING = 'Plaintext cleanup is incomplete. Encrypted data is preserved. Check settings.json permissions and contents, then retry cleanup.';
const CLEANUP_ERROR = 'Plaintext cleanup could not finish during migration. Check settings.json permissions, then retry. Encrypted data is preserved.';
const SOURCE_CHANGED_ERROR = 'Settings keys changed during migration. Nothing was removed from settings.json. Retry to import the updated source.';
const skippedWarning = names => `These settings.json entries could not be imported and remain unencrypted there: ${names.join(', ')}. Fix or remove them in settings.json.`;
// What migration takes out of settings.json: a well-formed name with a text
// value. Anything else is left where it is and reported by name.
const importable = (name, value) => validName(name) && typeof value === 'string';
function preferences(doc) {
  const out = { ...doc }; delete out.envKeys;
  for (const key of LEGACY) delete out[key];
  return out;
}
function secretFields(doc) {
  return Object.fromEntries(['envKeys', ...LEGACY].filter(key => own(doc, key)).map(key => [key, doc[key]]));
}
// The names migration cannot take, never their values.
function skippedIn(doc) {
  const out = [];
  if (doc.envKeys != null) {
    if (!record(doc.envKeys)) out.push('envKeys');
    else for (const [name, value] of Object.entries(doc.envKeys)) if (!importable(name, value)) out.push(name);
  }
  for (const key of LEGACY) if (doc[key] != null && typeof doc[key] !== 'string') out.push(key);
  return out;
}
function hasImportable(doc) {
  if (record(doc.envKeys) && Object.entries(doc.envKeys).some(([name, value]) => importable(name, value))) return true;
  return LEGACY.some(key => typeof doc[key] === 'string');
}
// settings.json minus everything migration could import; skipped entries stay.
function scrubbed(doc) {
  const out = { ...doc };
  if (record(out.envKeys)) {
    const keep = Object.fromEntries(Object.entries(out.envKeys).filter(([name, value]) => !importable(name, value)));
    if (Object.keys(keep).length) out.envKeys = keep; else delete out.envKeys;
  } else if (out.envKeys == null) delete out.envKeys;
  for (const key of LEGACY) if (typeof out[key] === 'string' || out[key] == null) delete out[key];
  return out;
}
function tagged(message, kind) { const e = new Error(message); e.kind = kind; return e; }
function sourceError() { return tagged(SETTINGS_ERROR, 'settings'); }
function createCredentialStore({ file, settingsFile, encryption, io = ioDefault, platform = process.platform }) {
  // `state` is the last vault this process verified. Reads serve it from memory
  // and never throw: a store that is unavailable yields no saved keys, it does
  // not take terminals, agent status or shell-provided keys down with it.
  let state = null, error = 'Saved keys have not been initialized.', kind = 'storage';
  // What the vault on disk says, as far as this process could read it. Callers
  // use it to decide whether settings.json still holds a migration source.
  let migration = 'unknown';
  let cleanupPending = false, cleanupWarning = null, skippedKeys = [];
  const result = value => ({ ...value, cleanupPending, cleanupWarning, skippedKeys, skippedWarning: skippedKeys.length ? skippedWarning(skippedKeys) : null });
  function protect() {
    if (!['darwin', 'win32', 'linux'].includes(platform) || !encryption.isEncryptionAvailable()) throw new Error(ERROR);
    if (platform === 'linux' && ['basic_text', 'unknown'].includes(encryption.getSelectedStorageBackend())) throw new Error(ERROR);
  }
  function settings() {
    try {
      if (!io.exists(settingsFile)) return {};
      const text = io.read(settingsFile);
      if (!text.trim()) return {};
      const doc = JSON.parse(text);
      if (!record(doc)) throw new Error();
      return doc;
    } catch (_) { throw sourceError(); }
  }
  function settingsReadable() { try { settings(); return true; } catch (_) { return false; } }
  // Validate and sanitize exactly one snapshot; never reread between comparison
  // and replacement. Independent processes must still use separate profiles.
  function scrubSettings(source) {
    cleanupPending = true; cleanupWarning = CLEANUP_WARNING;
    const current = settings();
    skippedKeys = skippedIn(current);
    if (source && JSON.stringify(secretFields(current)) !== JSON.stringify(secretFields(source))) throw tagged(SOURCE_CHANGED_ERROR, 'source');
    if (hasImportable(current)) {
      try {
        io.write(settingsFile, JSON.stringify(scrubbed(current), null, 2) + '\n');
        if (hasImportable(settings())) throw new Error();
      } catch (_) { throw tagged(CLEANUP_ERROR, 'settings'); }
    }
    cleanupPending = false; cleanupWarning = null;
  }
  function retryCleanup() {
    try { scrubSettings(); } catch (_) { /* Keep verified encrypted keys usable. */ }
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
  // Raw file text behind `state`, so a mutation can tell "unchanged on disk"
  // from "replaced or damaged" without asking the key store to decrypt again.
  let verifiedText = null;
  function load() {
    const raw = io.read(file);
    const envelope = JSON.parse(raw);
    if (!record(envelope) || envelope.version !== 1 || typeof envelope.ciphertext !== 'string'
      || !envelope.ciphertext || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(envelope.ciphertext)) throw new Error(ERROR);
    const doc = validate(JSON.parse(encryption.decryptString(Buffer.from(envelope.ciphertext, 'base64'))));
    verifiedText = raw;
    return doc;
  }
  // Whether the last persist() attempted the atomic rename; before that point
  // the disk still holds the previous vault and the in-memory state is valid.
  let written = false;
  function persist(next) {
    written = false;
    protect();
    const text = JSON.stringify(validate(next));
    const encrypted = encryption.encryptString(text);
    // Catch unusable encryption output before replacing a previously valid vault.
    if (!Buffer.isBuffer(encrypted) || !encrypted.length || encryption.decryptString(encrypted) !== text) throw new Error(ERROR);
    // Once the write is attempted the disk may hold either vault, so any later
    // failure has to re-read to find out which.
    written = true;
    io.write(file, JSON.stringify({ version: 1, ciphertext: encrypted.toString('base64') }) + '\n');
    const verified = load();
    if (JSON.stringify(verified) !== text) throw new Error(ERROR);
    state = verified;
    migration = verified.migration;
  }
  // The store itself is unusable (as opposed to one operation having failed).
  // Errors that know which file is at fault carry `kind`; everything else is
  // reported as the key store or vault.
  function unavailable(err) {
    state = null;
    kind = err && err.kind ? 'settings' : 'storage';
    error = err && err.kind ? err.message : ERROR;
    return result({ ok: false, error });
  }
  function initialize() {
    try { protect(); } catch (_) { return unavailable(null); }
    let next;
    try { next = io.exists(file) ? load() : { version: 1, migration: 'pending', named: {}, legacy: {}, imported: [], tombstones: {} }; }
    catch (e) { migration = 'unknown'; return unavailable(e); }
    migration = next.migration;
    try {
      if (next.migration === 'complete') {
        // load() has already verified the persisted ciphertext. A finished
        // migration no longer needs settings.json, so a damaged preferences file
        // must not take saved keys down; stale plaintext is scrubbed when it can be.
        state = next; error = null;
        retryCleanup();
        return result({ ok: true });
      }
      // A pending migration needs its source: fail closed and leave it untouched.
      const source = settings();
      skippedKeys = skippedIn(source);
      for (const [name, value] of Object.entries(record(source.envKeys) ? source.envKeys : {})) {
        if (!importable(name, value) || value === '') continue;
        const id = 'named:' + name;
        if (!own(next.named, name) && !own(next.tombstones, id) && !next.imported.includes(id)) next.named[name] = value;
        if (!next.imported.includes(id)) next.imported.push(id);
      }
      for (const name of LEGACY) if (typeof source[name] === 'string' && source[name] !== '') {
        const id = 'legacy:' + name;
        if (!own(next.legacy, name) && !own(next.tombstones, id) && !next.imported.includes(id)) next.legacy[name] = source[name];
        if (!next.imported.includes(id)) next.imported.push(id);
      }
      persist(next);
      // An external writer may add a key while ciphertext is being persisted.
      // Preserve its source and retry instead of removing an unimported value.
      scrubSettings(source);
      persist({ ...next, migration: 'complete' });
      error = null;
      return result({ ok: true });
    } catch (e) { return unavailable(e); }
  }
  // What the Retry control does: a usable store only needs its plaintext cleanup
  // retried, which never touches the key store; anything else starts over.
  function retry() {
    if (usable()) { retryCleanup(); return status(); }
    return initialize();
  }
  function change(fn) {
    if (error || !state) return result({ ok: false, error: error || ERROR });
    let next;
    // Cannot encrypt right now: refuse the write, keep serving what is in memory.
    try { protect(); } catch (_) { return result({ ok: false, error: ERROR }); }
    // A damaged or replaced vault must not be overwritten from a stale cache.
    // An unchanged file needs no decrypt, so a locked key store cannot turn a
    // verified vault into an unavailable one here.
    try {
      next = io.read(file) === verifiedText ? JSON.parse(JSON.stringify(state)) : load();
      if (next.migration !== 'complete') throw new Error(ERROR);
    } catch (_) { return unavailable(null); }
    fn(next);
    const wanted = JSON.stringify(next);
    try { persist(next); }
    catch (_) {
      // Nothing reached disk (locked key store, bad ciphertext, failed rename):
      // the verified vault in memory is still the one on disk.
      if (!written) return result({ ok: false, error: ERROR });
      // The write is an atomic rename, so the disk holds the old vault or the
      // new one, never a partial. Adopt whichever verifies; only a vault that no
      // longer verifies makes the store unavailable.
      try { state = load(); } catch (_) { return unavailable(null); }
      if (JSON.stringify(state) !== wanted) return result({ ok: false, error: ERROR });
    }
    // The key is committed. Plaintext cleanup is retried on the next change or launch.
    retryCleanup();
    return result({ ok: true });
  }
  function set(name, value) {
    if (!validName(name) || typeof value !== 'string' || !value.trim()) return result({ ok: false, error: 'Enter a valid key name and nonempty secret.' });
    return change(next => { next.named[name] = value.trim(); delete next.tombstones['named:' + name]; });
  }
  function remove(name) {
    if (!validRef(name)) return result({ ok: false, error: 'Invalid key name.' });
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
      return result({ ok: false, error: 'API keys must be text, or null to remove them.' });
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
  const status = () => result({ ok: !error, error, kind: error ? kind : null, migration });
  // Total by design: consumers (session env, speech, agent status) get no saved
  // keys when the store is unavailable, and ask status() if they need to say why.
  function context() { return usable() ? { envKeys: { ...state.named }, ...state.legacy } : { envKeys: {} }; }
  function list() {
    if (!usable()) return result({ ok: false, error: error || ERROR, kind });
    const stored = Object.entries(state.named)
      .map(([name, value]) => ({ name, masked: masked(value) }))
      .sort((a, b) => a.name.localeCompare(b.name));
    const legacy = Object.entries(state.legacy)
      .map(([name, value]) => ({ name: 'legacy:' + name, masked: masked(value) }));
    return result({ ok: true, stored, legacy });
  }
  function reveal(name) {
    if (!validRef(name)) return result({ ok: false, error: 'Invalid key name.' });
    if (!usable()) return result({ ok: false, error: error || ERROR });
    const legacy = name.startsWith('legacy:');
    const entries = legacy ? state.legacy : state.named;
    const key = legacy ? name.slice(7) : name;
    return result({ ok: true, value: own(entries, key) ? entries[key] : '' });
  }
  return { initialize, retry, set, remove, setLegacy, context, list, reveal, status, settingsReadable };
}
module.exports = { createCredentialStore, preferences, LEGACY, ERROR, SETTINGS_ERROR, CLEANUP_WARNING, CLEANUP_ERROR, SOURCE_CHANGED_ERROR };
