import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import path from 'node:path';
import { createRequire } from 'node:module';
import * as agentLaunch from '../src/renderer/agent-launch.mjs';
import { shellQuote } from '../src/renderer/file-kinds.mjs';
const require = createRequire(import.meta.url);
const policy = require('../src/main/session-env');
const main = fs.readFileSync(new URL('../src/main/main.js', import.meta.url), 'utf8');
const renderer = fs.readFileSync(new URL('../src/renderer/app.js', import.meta.url), 'utf8');
const parentEnv = { PATH: '/bin', HOME: '/home/test', SHELL: '/bin/zsh', OPENAI_API_KEY: 'openai', ANTHROPIC_API_KEY: 'anthropic', UNLISTED_TOKEN: 'other' };
const settings = { envKeys: { OPENAI_API_KEY: 'saved', UNLISTED_TOKEN: 'saved-other' }, theme: 'paper' };

async function spawnBoundary(request, config = settings) {
  let handler, captured;
  const messages = [];
  const context = {
    ...policy, agentRunCommandAllowed: require('../src/main/agents-detect').agentRunCommandAllowed, process: { env: parentEnv, platform: 'darwin' }, readSettings: () => config,
    storedEnvKeys: () => config.envKeys, settingsStore: require('../src/main/settings'),
    ipcMain: { handle: (_channel, fn) => { handler = fn; } }, browserViews: { registerSession() {} },
    pty: { spawn: (file, args, opts) => { captured = { file, args, ...opts }; throw Error('saved-other'); } },
    sendWc: (_wc, _channel, message) => messages.push(message), userPath: async () => '/resolved/bin',
    resolveClaudeExecutable: () => '/bin/claude', path, os: { homedir: () => '/home/test' }, fs: { existsSync: () => true },
    claudeSpawnArgs: require('../src/main/claude-args').claudeSpawnArgs, projectSlug: () => 'test',
    shellQuote: (s) => s, resolveRunCommand: (s) => s, withSpawnFlags: (s) => s,
    agentForCommand: () => null, sessionExists: () => true, resumeCommand: () => null,
    oneShotArgs: () => ['-c', 'dummy-install'],
  };
  vm.runInNewContext(main.slice(main.indexOf('function sessionEnv('), main.indexOf('// ---- claude\'s own name for a session')), context);
  await handler({ sender: { id: 1 } }, { id: 'test', cwd: '/project', ...request });
  return { captured, messages };
}

test('actual PTY spawn filters keys for new and resumed sessions and redacts spawn errors', async () => {
  for (const cont of [false, true]) {
    for (const request of [
      { kind: 'run', command: 'codex', purpose: 'agent', agentId: 'codex', cont },
      { kind: 'shell', purpose: 'agent', agentId: 'codex', cont },
      { kind: 'run', command: 'install', purpose: 'agent', agentId: 'codex', watchDone: true, cont },
      { kind: 'run', command: 'codex', cont },
    ]) {
      const { captured, messages } = await spawnBoundary(request);
      assert.ok(captured);
      assert.equal(captured.env.PATH, '/resolved/bin');
      assert.equal(captured.env.TERM, 'xterm-256color');
      assert.equal(captured.env.UNLISTED_TOKEN, undefined);
      assert.equal(captured.env.ANTHROPIC_API_KEY, undefined);
      assert.equal(captured.env.OPENAI_API_KEY, request.kind === 'run' && request.purpose === 'agent' && !request.watchDone ? 'saved' : undefined);
      assert.equal(JSON.stringify(messages).includes('saved-other'), false);
    }
  }
});

test('launcher metadata survives snapshot and restore without storing secret values', async () => {
  assert.equal(typeof agentLaunch.terminalAgentOptions, 'function');
  const options = agentLaunch.terminalAgentOptions({ id: 'codex', kind: 'run', bin: 'codex' });
  assert.equal(options.agentId, 'codex');
  assert.equal(options.purpose, 'agent');
  const S = { panels: [{ ...options, id: 'before', acpSid: 'conversation' }] };
  const context = { S, isSessionPanel: () => true, DOC_STEPS: [], ownerIndexes: () => ({}),
    startPanel: (p) => S.panels.unshift({ ...p, id: 'restored' }),
    resolveOwners: () => {}, browsers: { restore() {} }, renderAll() {}, tileEls: new Map(), savePanels: () => {}, renderDesk: () => {}, renderRail: () => {} };
  vm.runInNewContext(renderer.slice(renderer.indexOf('function panelSnapshot()'), renderer.indexOf('function savePanels()')), context);
  const snapshots = JSON.parse(JSON.stringify(context.panelSnapshot()));
  S.panels = [];
  vm.runInNewContext(renderer.slice(renderer.indexOf('async function restorePanels('), renderer.indexOf('function seedTitleSource(')), context);
  await context.restorePanels(snapshots);
  assert.equal(S.panels[0].agentId, 'codex');
  assert.equal(S.panels[0].purpose, 'agent');
  assert.equal(S.panels[0].cont, true);
  const { captured } = await spawnBoundary(S.panels[0]);
  assert.equal(captured.env.OPENAI_API_KEY, 'saved');
  assert.equal(JSON.stringify(snapshots).includes('saved'), false);
});

test('renderer startProcess sends launch metadata to the real PTY boundary', async () => {
  let result;
  const context = { shouldPushName: () => false, api: { termCreate: async (request) => { result = await spawnBoundary(request); } } };
  vm.runInNewContext(renderer.slice(renderer.indexOf('async function startProcess('), renderer.indexOf('function setAttention(')), context);
  await context.startProcess({ kind: 'run', command: 'codex', agentId: 'codex', purpose: 'agent' }, 80, 24);
  assert.equal(result.captured.env.OPENAI_API_KEY, 'saved');
});

test('PTY launch preserves inherited allowed credentials without changing the parent', async () => {
  const before = JSON.stringify(parentEnv);
  const { captured } = await spawnBoundary({ kind: 'claude' });
  assert.equal(captured.env.ANTHROPIC_API_KEY, 'anthropic');
  assert.equal(captured.env.HOME, '/home/test');
  assert.equal(JSON.stringify(parentEnv), before);
});

test('custom profile grant is checked against the executable at the PTY boundary', async () => {
  const config = { ...settings, customAgentProfiles: { example: { program: '/opt/example', credentialKeys: ['UNLISTED_TOKEN'] } } };
  for (const program of ['/opt/example', '/opt/different']) {
    const { captured } = await spawnBoundary({ kind: 'harness', purpose: 'agent', agentId: 'example', program }, config);
    assert.equal(captured.file, program);
    assert.equal(captured.env.UNLISTED_TOKEN, program === '/opt/example' ? 'saved-other' : undefined);
    assert.equal(captured.env.OPENAI_API_KEY, undefined);
  }
});

test('an arbitrary harness cannot claim a built-in agent credential grant', async () => {
  const { captured } = await spawnBoundary({ kind: 'harness', purpose: 'agent', agentId: 'codex', program: '/opt/unrelated' });
  assert.equal(captured.env.OPENAI_API_KEY, undefined);
});

test('library-agent filenames remain one quoted shell argument', async () => {
  let launched;
  const context = {
    toolById: () => ({ id: 'opencode', kind: 'run', bin: 'opencode', found: true }),
    rememberTool() {}, ensureDelivered: async () => null, agentLaunch: agentLaunch.agentLaunch,
    terminalAgentOptions: agentLaunch.terminalAgentOptions,
    shellQuote,
    code2: () => 'OP', startPanel: (p) => { launched = p; return p; },
  };
  vm.runInNewContext(renderer.slice(renderer.indexOf('async function reallyLaunchAgent('), renderer.indexOf('async function openAgentPicker(')), context);
  await context.reallyLaunchAgent({ slug: 'helper; printf injected', name: 'test' }, 'opencode');
  assert.equal(launched.command, "opencode '--agent' 'helper; printf injected'");
});

test('run-session metadata cannot grant keys to a different or compound command', async () => {
  for (const command of ['claude', 'codex; echo extra', 'env', '', undefined]) {
    const { captured } = await spawnBoundary({ kind: 'run', purpose: 'agent', agentId: 'codex', command });
    assert.equal(captured.env.OPENAI_API_KEY, undefined);
  }
});
