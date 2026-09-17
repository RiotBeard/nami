import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { createCredentialStore, preferences, ERROR, SETTINGS_ERROR } from '../src/main/credential-store.js';
import { writeSettings } from '../src/main/settings.js';
import { sttConfig } from '../src/main/stt.js';
const secret = ['dummy','value','987654321'].join('-');
function fixture(source = {}) {
  const files = new Map([['settings', JSON.stringify(source)]]), writes = [];
  const key = crypto.randomBytes(32);
  const encryption = {
    isEncryptionAvailable: () => true,
    getSelectedStorageBackend: () => 'gnome_libsecret',
    encryptString: text => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', key, iv); const data = Buffer.concat([c.update(text), c.final()]); return Buffer.concat([iv, c.getAuthTag(), data]); },
    decryptString: data => { const d = crypto.createDecipheriv('aes-256-gcm', key, data.subarray(0,12)); d.setAuthTag(data.subarray(12,28)); return Buffer.concat([d.update(data.subarray(28)), d.final()]).toString(); },
  };
  const io = { exists: f => files.has(f), read: f => files.get(f), write: (f,t) => { writes.push([f,t]); files.set(f,t); } };
  const make = (extra = {}) => createCredentialStore({ file: 'vault', settingsFile: 'settings', io, encryption, ...extra });
  return { files, writes, io, encryption, make };
}
test('fresh save, masked listing, explicit reveal, restart and deletion', () => {
  const f = fixture({ theme: 'paper' }), s = f.make();
  assert.equal(s.initialize().ok, true);
  assert.equal(s.set('OPENAI_API_KEY', secret).ok, true);
  assert.equal(s.reveal('OPENAI_API_KEY').value, secret);
  assert.ok(!JSON.stringify(s.list()).includes(secret));
  assert.ok(![...f.files.values()].join('').includes(secret));
  const restart = f.make(); assert.equal(restart.initialize().ok, true);
  assert.equal(restart.context().envKeys.OPENAI_API_KEY, secret);
  assert.equal(restart.remove('OPENAI_API_KEY').ok, true);
  const again = f.make(); again.initialize(); assert.equal(again.reveal('OPENAI_API_KEY').value, '');
});
test('migrates all legacy fields, preserves preferences and precedence without persisting environment', () => {
  const f = fixture({ theme: 'glass', envKeys: { OPENAI_API_KEY: secret }, openaiKey: 'legacy-openai', elevenKey: 'legacy-eleven', sttKey: 'legacy-custom' }), s = f.make();
  assert.equal(s.initialize().ok, true);
  assert.deepEqual(JSON.parse(f.files.get('settings')), { theme: 'glass' });
  assert.equal(sttConfig(s.context(), { OPENAI_API_KEY: 'env-only' }).openaiKey, secret);
  assert.equal(sttConfig(s.context(), {}).elevenKey, 'legacy-eleven');
  assert.ok(!f.files.get('vault').includes('env-only'));
  s.remove('OPENAI_API_KEY'); assert.equal(s.context().openaiKey, undefined);
  assert.equal(sttConfig(s.context(), { OPENAI_API_KEY: 'env-only' }).openaiKey, 'env-only');
  assert.equal(s.remove('legacy:sttKey').ok, true); assert.equal(s.context().sttKey, undefined);
});
for (const failAt of [1,2,3]) test(`migration recovers after failure at write ${failAt}`, () => {
  const f = fixture({ envKeys: { TEST_KEY: secret }, theme: 'glass' });
  const original = f.io.write; let count = 0;
  f.io.write = (file,text) => { if (++count === failAt) throw new Error(secret); original(file,text); };
  const s = f.make(); assert.deepEqual(s.initialize(), { ok: false, error: ERROR });
  assert.deepEqual(s.context(), { envKeys: {} }); // reads never throw
  f.io.write = original;
  const restarted = f.make(); assert.equal(restarted.initialize().ok, true);
  assert.equal(restarted.reveal('TEST_KEY').value, secret);
  assert.deepEqual(JSON.parse(f.files.get('settings')), { theme: 'glass' });
});
test('read-back corruption never removes plaintext and is not overwritten on retry', () => {
  const f = fixture({ openaiKey: secret }), original = f.io.write;
  f.io.write = (file,text) => original(file, file === 'vault' ? '{"version":1,"ciphertext":"YmFk"}' : text);
  const s = f.make(); assert.equal(s.initialize().ok, false);
  assert.equal(JSON.parse(f.files.get('settings')).openaiKey, secret);
  const before = f.files.get('vault'); f.io.write = original;
  assert.equal(s.initialize().ok, false); assert.equal(f.files.get('vault'), before);
});
test('unavailable encryption and insecure Linux backend preserve source and reject saves', () => {
  for (const platform of ['darwin','linux']) {
    const f = fixture({ openaiKey: secret });
    f.encryption.isEncryptionAvailable = () => platform === 'linux';
    f.encryption.getSelectedStorageBackend = () => 'basic_text';
    const s = f.make({ platform }); assert.equal(s.initialize().ok, false);
    assert.equal(s.set('KEY',secret).ok, false); assert.equal(f.writes.length, 0);
    assert.equal(JSON.parse(f.files.get('settings')).openaiKey, secret);
    f.encryption.isEncryptionAvailable = () => true; f.encryption.getSelectedStorageBackend = () => 'gnome_libsecret';
    assert.equal(s.initialize().ok, true);
  }
});
test('mixed state never replaces newer keys or resurrects deletions', () => {
  const f = fixture({ envKeys: { KEY: secret } }), s = f.make(); s.initialize();
  s.set('KEY', 'newer-secret'); s.set('GONE', 'deleted-secret'); s.remove('GONE');
  // Simulate encrypted pending cleanup with newer mutations already durable.
  const envelope = JSON.parse(f.files.get('vault'));
  const doc = JSON.parse(f.encryption.decryptString(Buffer.from(envelope.ciphertext,'base64')));
  doc.migration = 'pending';
  f.files.set('vault', JSON.stringify({ version:1, ciphertext:f.encryption.encryptString(JSON.stringify(doc)).toString('base64') }));
  f.files.set('settings', JSON.stringify({ envKeys: { KEY: secret, GONE: 'stale-secret' }, theme:'dusk' }));
  const next = f.make(); assert.equal(next.initialize().ok,true);
  assert.equal(next.reveal('KEY').value,'newer-secret'); assert.equal(next.reveal('GONE').value,'');
  assert.deepEqual(JSON.parse(f.files.get('settings')), { theme:'dusk' });
});
test('cleanup rereads preferences; normal preference writes preserve pending source', () => {
  const f = fixture({ envKeys: { KEY: secret }, theme:'paper' }), original = f.io.write;
  f.io.write = (file,text) => { original(file,text); if (file === 'vault') { const s = JSON.parse(f.files.get('settings')); s.theme='dusk'; f.files.set('settings',JSON.stringify(s)); } };
  assert.equal(f.make().initialize().ok,true); assert.equal(JSON.parse(f.files.get('settings')).theme,'dusk');
  const blocked = fixture({ openaiKey:secret });
  writeSettings({ file:'settings', patch:{ theme:'glass' }, io:blocked.io });
  assert.equal(JSON.parse(blocked.files.get('settings')).openaiKey, secret);
  assert.deepEqual(preferences(JSON.parse(blocked.files.get('settings'))), { theme:'glass' });
});
test('unknown versions, malformed settings and failed updates preserve data and return safe errors', () => {
  const f = fixture(); f.files.set('vault','{"version":99}');
  assert.equal(f.make().initialize().ok,false); assert.equal(f.writes.length,0);
  f.files.delete('vault'); f.files.set('settings','broken'); assert.equal(f.make().initialize().ok,false);
  f.files.set('settings','{}'); const s=f.make(); s.initialize(); s.set('KEY',secret);
  const before=f.files.get('vault'); f.encryption.encryptString=()=>{throw new Error(secret);};
  assert.deepEqual(s.set('KEY','new'),{ok:false,error:ERROR}); assert.equal(f.files.get('vault'),before);
  assert.ok(!JSON.stringify(s.list()).includes(secret));
});
test('real private writer uses owner-only atomic files with encrypted content', t => {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'nami-credentials-')); t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const f=fixture(), file=path.join(dir,'credentials.json'), settingsFile=path.join(dir,'settings.json');
  fs.writeFileSync(settingsFile,JSON.stringify({openaiKey:secret}));
  const s=createCredentialStore({file,settingsFile,encryption:f.encryption}); assert.equal(s.initialize().ok,true);
  assert.equal(fs.statSync(file).mode & 0o777,0o600); assert.equal(fs.statSync(settingsFile).mode & 0o777,0o600);
  assert.ok(!fs.readFileSync(file,'utf8').includes(secret)); assert.equal(fs.readdirSync(dir).length,2);
});
test('short secrets stay fully masked and unsafe names are rejected', () => {
  const s=fixture().make(); s.initialize(); s.set('SHORT','abc');
  assert.ok(!JSON.stringify(s.list()).includes('abc'));
  for (const name of ['__proto__','constructor','prototype',undefined,{}]) {
    assert.equal(s.set(name,secret).ok,false); assert.equal(s.reveal(name).ok,false);
  }
});
for (const failAt of [1,2,3]) test(`migration recovers if write ${failAt} commits before interruption`, () => {
  const f=fixture({envKeys:{KEY:secret},elevenKey:secret,view:'split'}), original=f.io.write;
  let count=0; f.io.write=(file,text)=>{original(file,text);if(++count===failAt)throw Error('interrupted');};
  assert.equal(f.make().initialize().ok,false); f.io.write=original;
  const restarted=f.make(); assert.equal(restarted.initialize().ok,true);
  assert.equal(restarted.context().envKeys.KEY,secret); assert.equal(restarted.context().elevenKey,secret);
  assert.deepEqual(JSON.parse(f.files.get('settings')),{view:'split'});
});
test('completed migration rejects stale source resurrection and validates journal structure',()=>{
  const f=fixture({envKeys:{OPENAI_API_KEY:secret},openaiKey:secret}),s=f.make(); s.initialize();s.remove('OPENAI_API_KEY');
  f.files.set('settings',JSON.stringify({envKeys:{OPENAI_API_KEY:secret},openaiKey:secret}));
  const next=f.make();assert.equal(next.initialize().ok,true);assert.equal(next.reveal('OPENAI_API_KEY').value,'');assert.equal(next.context().openaiKey,undefined);
  const envelope=JSON.parse(f.files.get('vault'));
  const doc=JSON.parse(f.encryption.decryptString(Buffer.from(envelope.ciphertext,'base64')));
  doc.tombstones={'named:bad-name':true};
  f.files.set('vault',JSON.stringify({version:1,ciphertext:f.encryption.encryptString(JSON.stringify(doc)).toString('base64')}));
  const before=f.files.get('vault'); assert.equal(f.make().initialize().ok,false);assert.equal(f.files.get('vault'),before);
});
test('mutations do not overwrite a vault damaged after startup; deletion cleans restored plaintext',()=>{
  const f=fixture(),s=f.make();s.initialize();s.set('OPENAI_API_KEY',secret);
  f.files.set('settings',JSON.stringify({envKeys:{OPENAI_API_KEY:secret},openaiKey:secret,theme:'dusk'}));
  assert.equal(s.remove('OPENAI_API_KEY').ok,true);assert.deepEqual(JSON.parse(f.files.get('settings')),{theme:'dusk'});
  f.files.set('vault','corrupt-after-startup');
  assert.equal(s.set('KEY','replacement').ok,false);assert.equal(f.files.get('vault'),'corrupt-after-startup');
});
test('key deletion uses only explicit provider aliases, not inherited object properties',()=>{
  const s=fixture().make();s.initialize();
  for(const name of ['toString','valueOf','hasOwnProperty']) {
    assert.equal(s.set(name,secret).ok,true);
    assert.equal(s.remove(name).ok,true);
    assert.equal(s.reveal(name).value,'');
  }
  for(const name of [null,undefined,{},[],{toString:null}]) {
    assert.equal(s.remove(name).ok,false);
  }
  assert.equal(s.status().ok,true);
});
test('completed startup validates without rewriting the vault or settings', () => {
  const f = fixture({ openaiKey: secret }), first = f.make();
  assert.equal(first.initialize().ok, true);
  const before = f.files.get('vault'), writes = f.writes.length;
  assert.equal(f.make().initialize().ok, true);
  assert.equal(f.files.get('vault'), before);
  assert.equal(f.writes.length, writes);
});
test('invalid encryption output cannot overwrite an existing valid vault', () => {
  const f = fixture(), store = f.make(); store.initialize(); store.set('KEY', secret);
  const before = f.files.get('vault');
  f.encryption.encryptString = () => Buffer.from('not decryptable');
  assert.equal(store.set('KEY', 'replacement').ok, false);
  assert.equal(f.files.get('vault'), before);
});
test('invalid legacy input is a validation error without locking a healthy store', () => {
  const store = fixture().make(); store.initialize();
  assert.equal(store.setLegacy({ openaiKey: { secret } }).ok, false);
  assert.equal(store.status().ok, true);
  assert.equal(store.set('KEY', secret).ok, true);
});
test('a key added during migration is retained for retry before plaintext cleanup', () => {
  const f = fixture({ envKeys: { FIRST: secret } }), original = f.io.write;
  let changed = false;
  f.io.write = (file, text) => {
    original(file, text);
    if (file === 'vault' && !changed) {
      changed = true;
      f.files.set('settings', JSON.stringify({ envKeys: { FIRST: secret, LATE: 'late-dummy-key' }, theme: 'dusk' }));
    }
  };
  const store = f.make();
  assert.equal(store.initialize().ok, false);
  assert.equal(JSON.parse(f.files.get('settings')).envKeys.LATE, 'late-dummy-key');
  assert.equal(store.initialize().ok, true);
  assert.equal(store.reveal('LATE').value, 'late-dummy-key');
  assert.deepEqual(JSON.parse(f.files.get('settings')), { theme: 'dusk' });
});
test('unknown Linux backends and unsupported platforms cannot create a vault', () => {
  const f = fixture({ openaiKey: secret });
  f.encryption.getSelectedStorageBackend = () => 'unknown';
  for (const platform of ['linux', 'unsupported']) assert.equal(f.make({ platform }).initialize().ok, false);
  assert.equal(f.writes.length, 0);
});
test('an unavailable store yields no saved keys and never throws on reads', () => {
  const f = fixture({ openaiKey: secret });
  f.encryption.isEncryptionAvailable = () => false;
  const store = f.make({ platform: 'darwin' });
  assert.deepEqual(store.context(), { envKeys: {} }); // before initialize
  assert.equal(store.initialize().ok, false);
  assert.deepEqual(store.context(), { envKeys: {} });
  assert.deepEqual(store.status(), { ok: false, error: ERROR, kind: 'storage' });
  assert.equal(store.list().ok, false);
  assert.equal(store.reveal('OPENAI_API_KEY').ok, false);
});
test('a failed save keeps the verified keys readable instead of locking the store', () => {
  const f = fixture(), store = f.make(); store.initialize(); store.set('KEY', secret);
  const before = f.files.get('vault'), write = f.io.write, encrypt = f.encryption.encryptString;
  // Fails before anything is written.
  f.encryption.encryptString = () => { throw new Error('encrypt'); };
  assert.deepEqual(store.set('OTHER', 'other-dummy-value'), { ok: false, error: ERROR });
  f.encryption.encryptString = encrypt;
  // Fails at the write itself: the atomic rename never happened.
  f.io.write = () => { throw new Error('disk full'); };
  assert.deepEqual(store.remove('KEY'), { ok: false, error: ERROR });
  f.io.write = write;
  assert.equal(f.files.get('vault'), before);
  assert.equal(store.status().ok, true);
  assert.equal(store.context().envKeys.KEY, secret);
  assert.equal(store.reveal('KEY').value, secret);
  assert.equal(store.set('OTHER', 'other-dummy-value').ok, true);
});
test('a save whose write committed before the error is reported as saved', () => {
  const f = fixture(), store = f.make(); store.initialize();
  const write = f.io.write;
  f.io.write = (file, text) => { write(file, text); throw new Error('interrupted after rename'); };
  assert.equal(store.set('KEY', secret).ok, true);
  f.io.write = write;
  const restarted = f.make(); restarted.initialize();
  assert.equal(restarted.reveal('KEY').value, secret);
});
test('encryption lost mid-run refuses writes but keeps serving keys already in memory', () => {
  const f = fixture(), store = f.make(); store.initialize(); store.set('KEY', secret);
  const before = f.files.get('vault');
  f.encryption.isEncryptionAvailable = () => false;
  assert.equal(store.set('KEY', 'replacement-dummy').ok, false);
  assert.equal(f.files.get('vault'), before);
  assert.equal(store.context().envKeys.KEY, secret);
  assert.equal(store.status().ok, true);
});
test('a vault damaged mid-run makes the store unavailable and is never overwritten', () => {
  const f = fixture(), store = f.make(); store.initialize(); store.set('KEY', secret);
  f.files.set('vault', 'damaged');
  assert.equal(store.set('KEY', 'replacement-dummy').ok, false);
  assert.equal(f.files.get('vault'), 'damaged');
  assert.deepEqual(store.context(), { envKeys: {} });
  assert.equal(store.status().kind, 'storage');
});
test('a migrated vault does not depend on settings.json being readable', () => {
  const f = fixture({ envKeys: { KEY: secret }, theme: 'dusk' }); f.make().initialize();
  f.files.set('settings', 'not json');
  const store = f.make();
  assert.equal(store.initialize().ok, true);
  assert.equal(store.context().envKeys.KEY, secret);
  assert.equal(store.set('SECOND', 'second-dummy-value').ok, true);
  assert.equal(store.status().ok, true);
  assert.equal(f.files.get('settings'), 'not json');
});
test('a pending migration with an unreadable or malformed source fails closed and says which file', () => {
  for (const source of ['not json', '[]', JSON.stringify({ envKeys: { 'bad-name': secret } }), JSON.stringify({ openaiKey: 12 })]) {
    const f = fixture(); f.files.set('settings', source);
    const store = f.make();
    assert.deepEqual(store.initialize(), { ok: false, error: SETTINGS_ERROR });
    assert.equal(store.status().kind, 'settings');
    assert.equal(store.list().kind, 'settings');
    assert.equal(f.files.get('settings'), source);
    assert.equal(f.files.has('vault'), false);
  }
});
test('settings cleanup failing after a committed save does not fail the save', () => {
  const f = fixture(), store = f.make(); store.initialize();
  f.files.set('settings', JSON.stringify({ envKeys: { STALE: secret }, theme: 'dusk' }));
  const write = f.io.write;
  f.io.write = (file, text) => { if (file === 'settings') throw new Error('read-only'); write(file, text); };
  assert.equal(store.set('KEY', secret).ok, true);
  assert.equal(store.status().ok, true);
  f.io.write = write;
  assert.equal(store.set('KEY2', secret).ok, true); // cleanup is retried
  assert.deepEqual(JSON.parse(f.files.get('settings')), { theme: 'dusk' });
});
