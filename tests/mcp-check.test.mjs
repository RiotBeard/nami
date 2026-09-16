import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { checkServer } = require('../src/main/mcp-check.js');

function fakeChild(script) {
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.killed = false;
  child.kill = () => { child.killed = true; };
  child.stdin = { write: (line) => { const msg = JSON.parse(line); const reply = script(msg); if (reply) setImmediate(() => child.stdout.emit('data', Buffer.from(JSON.stringify(reply) + '\n'))); } };
  return child;
}

test('handshake then tools/list yields the tool count and kills the child', async () => {
  const child = fakeChild((msg) => {
    if (msg.method === 'initialize') return { jsonrpc: '2.0', id: msg.id, result: { capabilities: {} } };
    if (msg.method === 'tools/list') return { jsonrpc: '2.0', id: msg.id, result: { tools: [{ name: 'a' }, { name: 'b' }, { name: 'c' }] } };
    return null;
  });
  const out = await checkServer({ command: 'npx', args: ['x'], spawnFn: () => child });
  assert.deepEqual(out, { ok: true, tools: 3 });
  assert.ok(child.killed);
});

test('a server that never answers resolves ok:false at the timeout, not a hang', async () => {
  const child = fakeChild(() => null);
  const out = await checkServer({ command: 'npx', args: ['x'], spawnFn: () => child, timeoutMs: 50 });
  assert.equal(out.ok, false);
  assert.ok(child.killed);
});

test('spawn failure surfaces as a friendly error', async () => {
  const out = await checkServer({ command: 'nope', args: [], spawnFn: () => { throw new Error('ENOENT'); } });
  assert.equal(out.ok, false);
  assert.match(out.error, /ENOENT|could not start/i);
});

test('connector spawn receives only explicit keys; errors redact credentials', async () => {
  let actual;
  const out = await checkServer({ command: 'nope', parentEnv: { PATH: '/bin', OPENAI_API_KEY: 'ambient', PRIVATE_KEY: 'private' },
    settings: { envKeys: { PRIVATE_KEY: 'stored' } }, env: { SERVICE_TOKEN: 'explicit' },
    spawnFn: (_command, _args, opts) => { actual = opts.env; throw new Error('explicit private stored'); } });
  assert.deepEqual(actual, { PATH: '/bin', SERVICE_TOKEN: 'explicit' });
  assert.equal(out.error, 'could not start: [redacted] [redacted] [redacted]');
});
