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
import { createCredentialStore, preferences, LEGACY, ERROR } from '../src/main/credential-store.js';
const source=fs.readFileSync(new URL('../src/main/main.js',import.meta.url),'utf8');
function harness(t, available) {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'nami-ipc-')); t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const secret='dummy-ipc-secret-123456789';
  fs.writeFileSync(path.join(dir,'settings.json'),JSON.stringify({envKeys:{OPENAI_API_KEY:secret},openaiKey:secret,theme:'paper'}));
  const key=crypto.randomBytes(32);
  const safeStorage={isEncryptionAvailable:()=>available,encryptString:s=>{const c=crypto.createCipheriv('aes-256-cbc',key,Buffer.alloc(16));return Buffer.concat([c.update(s),c.final()]);},decryptString:b=>{const d=crypto.createDecipheriv('aes-256-cbc',key,Buffer.alloc(16));return Buffer.concat([d.update(b),d.final()]).toString();}};
  const handlers=new Map();
  const ctx=vm.createContext({ fs,path,stripInheritedClaude,app:{getPath:()=>dir},settingsStore,createCredentialStore,preferences,LEGACY,safeStorage,ipcMain:{handle:(name,fn)=>handlers.set(name,fn)},REVIEW:false,CREDENTIAL_ERROR:ERROR,process:{env:{OPENAI_API_KEY:'environment-only-dummy'}},stt:{status:({settings,env})=>({ready:settings.sttProvider==='local',providers:[{needsKey:'openaiKey',ready:!!env.OPENAI_API_KEY}]}),transcribe:async()=>({ok:true}),prepare:async()=>({ok:true})},sendWc(){},agentStatus:async()=>({ok:true}),shell:{showItemInFolder(){}},refreshAppMenu(){} });
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
test('storage failures use structured speech/agent errors while local speech remains available', async t => {
  const h = harness(t, false), settingsFile = path.join(h.dir, 'settings.json');
  const source = JSON.parse(fs.readFileSync(settingsFile, 'utf8'));
  fs.writeFileSync(settingsFile, JSON.stringify({ ...source, sttProvider: 'openai' }));
  for (const channel of ['stt:transcribe', 'stt:prepare', 'agents:status']) {
    const result = await h.handlers.get(channel)({}, {});
    assert.equal(result.ok, false);
    assert.equal(result.error, ERROR);
  }
  const status = h.handlers.get('stt:status')({});
  assert.equal(status.providers[0].ready, false);
  assert.match(status.providers[0].reason, /Settings/);
  fs.writeFileSync(settingsFile, JSON.stringify({ ...source, sttProvider: 'local' }));
  assert.equal((await h.handlers.get('stt:transcribe')({}, {})).ok, true);
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
