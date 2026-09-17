// Exercise actual main-process handlers against a real store without Electron/Keychain.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import * as settingsStore from '../src/main/settings.js';
import { stripInheritedClaude } from '../src/main/session-env.js';
import { sttConfig } from '../src/main/stt.js';
import { createCredentialStore, preferences, LEGACY, ERROR, SETTINGS_ERROR } from '../src/main/credential-store.js';
const envOnly='environment-only-dummy';
// Mirrors stt.js closely enough for main.js: a keyed provider is ready only when
// sttConfig finds a key in saved settings or the environment.
const keyed=settings=>settings.sttProvider==='openai';
const speech=async({settings,env})=>keyed(settings)&&!sttConfig(settings,env).openaiKey?{ok:false,error:'no API key'}:{ok:true};
const speechStub={sttConfig,resolveProvider:settings=>keyed(settings)?{needsKey:'openaiKey'}:{},transcribe:speech,prepare:speech,
  status:({settings,env})=>({ready:!keyed(settings)||!!sttConfig(settings,env).openaiKey,providers:[{needsKey:'openaiKey',ready:!!sttConfig(settings,env).openaiKey}]})};
const source=fs.readFileSync(new URL('../src/main/main.js',import.meta.url),'utf8');
function harness(t, available) {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'nami-ipc-')); t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const secret=['dummy','ipc','value','123456789'].join('-');
  fs.writeFileSync(path.join(dir,'settings.json'),JSON.stringify({envKeys:{OPENAI_API_KEY:secret},openaiKey:secret,theme:'paper'}));
  const key=crypto.randomBytes(32);
  const safeStorage={isEncryptionAvailable:()=>available,encryptString:s=>{const c=crypto.createCipheriv('aes-256-cbc',key,Buffer.alloc(16));return Buffer.concat([c.update(s),c.final()]);},decryptString:b=>{const d=crypto.createDecipheriv('aes-256-cbc',key,Buffer.alloc(16));return Buffer.concat([d.update(b),d.final()]).toString();}};
  const handlers=new Map();
  const ctx=vm.createContext({ fs,path,stripInheritedClaude,app:{getPath:()=>dir},settingsStore,createCredentialStore,preferences,LEGACY,safeStorage,ipcMain:{handle:(name,fn)=>handlers.set(name,fn)},REVIEW:false,CREDENTIAL_ERROR:ERROR,process:{env:{PATH:'/usr/bin',OPENAI_API_KEY:envOnly}},SETTINGS_ERROR,stt:speechStub,sendWc(){},agentStatus:async(id,{envKeys})=>({id,signedIn:null,label:'',rows:[],source:'',savedKeyCount:Object.keys(envKeys).length}),shell:{showItemInFolder(){}},refreshAppMenu(){} });
  vm.runInContext(source.slice(source.indexOf('function settingsFile()'),source.indexOf('function sendWc(')),ctx);
  vm.runInContext('credentialStore().initialize()',ctx);
  vm.runInContext(source.slice(source.indexOf('function sessionEnv('),source.indexOf('// ---- IPC: terminal / harness')),ctx);
  vm.runInContext(source.slice(source.indexOf('function sttEnv()'),source.indexOf('// Whisper weights live')),ctx);
  vm.runInContext(source.slice(source.indexOf('async function runSpeech('),source.indexOf('// Every session inherits')),ctx);
  vm.runInContext(source.slice(source.indexOf("ipcMain.handle('agents:status'"),source.indexOf("ipcMain.handle('agents:status'")+source.slice(source.indexOf("ipcMain.handle('agents:status'")).indexOf('\n});')+4),ctx);
  vm.runInContext(source.slice(source.indexOf("ipcMain.handle('theme:set'"),source.indexOf("ipcMain.handle('folder:pick'")),ctx);
  return {secret,dir,ctx,handlers};
}
for(const available of [true,false]) test(`IPC responses contain no secrets with storage ${available?'available':'blocked'}`, t=>{
  const h=harness(t,available);
  for(const [channel,arg] of [['settings:get'],['keys:get'],['theme:set','glass'],['view:set','split'],['settings:set',{openaiModel:'whisper-1'}]]) {
    const result=h.handlers.get(channel)({},arg);
    assert.ok(!JSON.stringify(result).includes(h.secret),channel);
  }
  const revealed=h.handlers.get('keys:reveal')({},{name:'OPENAI_API_KEY'});
  assert.equal(revealed.ok,available);
  if(available) assert.equal(revealed.value,h.secret);
  else assert.equal(JSON.parse(fs.readFileSync(path.join(h.dir,'settings.json'),'utf8')).openaiKey,h.secret);
});
test('legacy settings writes go to encrypted storage and malformed sources are preserved',t=>{
  const h=harness(t,true), handler=h.handlers.get('settings:set');
  assert.equal(handler({},{elevenKey:h.secret}).ok,true);
  assert.ok(!fs.readFileSync(path.join(h.dir,'settings.json'),'utf8').includes(h.secret));
  assert.equal(h.handlers.get('keys:reveal')({},{name:'legacy:elevenKey'}).value,h.secret);
  fs.writeFileSync(path.join(h.dir,'settings.json'),'invalid original');
  assert.equal(handler({},{theme:'paper'}).ok,false);
  assert.equal(fs.readFileSync(path.join(h.dir,'settings.json'),'utf8'),'invalid original');
});
test('malformed key IPC payloads return validation errors without disabling storage', t => {
  const h = harness(t, true);
  for (const args of [undefined, null, {}, [], 12, 'wrong']) {
    for (const channel of ['keys:set', 'keys:delete', 'keys:reveal']) assert.equal(h.handlers.get(channel)({}, args).ok, false);
  }
  assert.equal(h.handlers.get('keys:get')({}).ok, true);
});
test('unavailable storage disables only saved keys: sessions, agent status, shell keys and preferences still work', async t => {
  const h = harness(t, false), settingsFile = path.join(h.dir, 'settings.json');
  const source = JSON.parse(fs.readFileSync(settingsFile, 'utf8'));
  fs.writeFileSync(settingsFile, JSON.stringify({ ...source, sttProvider: 'openai' }));
  // A session still gets its environment, minus the saved keys.
  const env = vm.runInContext('sessionEnv("/fixture/bin")', h.ctx);
  assert.equal(env.PATH, '/fixture/bin');
  assert.equal(env.OPENAI_API_KEY, envOnly);
  assert.ok(!JSON.stringify(env).includes(h.secret));
  // Agent status keeps the shape the launcher renders.
  const agent = await h.handlers.get('agents:status')({}, { id: 'grok' });
  assert.equal(agent.signedIn, null);
  assert.equal(agent.savedKeyCount, 0);
  // A key exported in the shell still drives a keyed speech provider.
  let status = h.handlers.get('stt:status')({});
  assert.equal(status.providers[0].ready, true);
  assert.equal(status.credentialStorage.ok, false);
  assert.equal((await h.handlers.get('stt:transcribe')({}, {})).ok, true);
  // With no key anywhere, the error names secure storage rather than "no API key".
  vm.runInContext('delete process.env.OPENAI_API_KEY', h.ctx);
  status = h.handlers.get('stt:status')({});
  assert.equal(status.providers[0].ready, false);
  for (const channel of ['stt:transcribe', 'stt:prepare']) {
    const failed = await h.handlers.get(channel)({}, {});
    assert.equal(failed.ok, false); assert.equal(failed.error, ERROR); // vm realm: compare fields
  }
  // Preferences are unaffected, and the unmigrated plaintext source is kept.
  assert.equal(h.handlers.get('theme:set')({}, 'dusk').ok, true);
  const kept = JSON.parse(fs.readFileSync(settingsFile, 'utf8'));
  assert.equal(kept.theme, 'dusk');
  assert.equal(kept.openaiKey, h.secret);
  fs.writeFileSync(settingsFile, JSON.stringify({ ...kept, sttProvider: 'local' }));
  assert.equal((await h.handlers.get('stt:transcribe')({}, {})).ok, true);
});
test('an unreadable settings.json is reported as such and is never overwritten', t => {
  const h = harness(t, true), settingsFile = path.join(h.dir, 'settings.json');
  fs.writeFileSync(settingsFile, 'invalid original');
  const refused = h.handlers.get('theme:set')({}, 'dusk');
  assert.equal(refused.ok, false); assert.equal(refused.error, SETTINGS_ERROR);
  assert.equal(fs.readFileSync(settingsFile, 'utf8'), 'invalid original');
  // The migrated vault does not depend on it.
  assert.equal(h.handlers.get('keys:reveal')({}, { name: 'OPENAI_API_KEY' }).value, h.secret);
  assert.equal(h.handlers.get('keys:set')({}, { name: 'NEW_KEY', value: h.secret }).ok, true);
  assert.equal(fs.readFileSync(settingsFile, 'utf8'), 'invalid original');
});
test('production speech and agent lookup preserve precedence without persisting environment keys', t => {
  const h = harness(t, true);
  let env = vm.runInContext('sessionEnv("/fixture/bin")', h.ctx);
  assert.equal(env.OPENAI_API_KEY, h.secret);
  assert.equal(env.PATH, '/fixture/bin');
  let speech = vm.runInContext('sttEnv()', h.ctx);
  assert.equal(sttConfig(speech.settings, speech.env).openaiKey, h.secret);
  h.handlers.get('keys:delete')({}, { name: 'OPENAI_API_KEY' });
  h.handlers.get('settings:set')({}, { openaiKey: 'legacy-dummy' });
  speech = vm.runInContext('sttEnv()', h.ctx);
  assert.equal(sttConfig(speech.settings, speech.env).openaiKey, 'legacy-dummy');
  h.handlers.get('keys:delete')({}, { name: 'legacy:openaiKey' });
  speech = vm.runInContext('sttEnv()', h.ctx);
  assert.equal(sttConfig(speech.settings, speech.env).openaiKey, 'environment-only-dummy');
  env = vm.runInContext('sessionEnv("/fixture/bin")', h.ctx);
  assert.equal(env.OPENAI_API_KEY, 'environment-only-dummy');
  assert.equal(h.handlers.get('keys:reveal')({}, { name: 'OPENAI_API_KEY' }).value, '');
  for (const file of ['settings.json', 'credentials.json']) {
    assert.ok(!fs.readFileSync(path.join(h.dir, file), 'utf8').includes('environment-only-dummy'));
  }
});
