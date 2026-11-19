process.env.PASSWORD_PEPPER = process.env.PASSWORD_PEPPER || 'test-pepper-for-tests-only';
const assert = require('assert');
const { createApp } = require('../server');
const { createMemoryStore } = require('../db');
const { call, listen, runFlows } = require('./flows');

(async () => {
  const store = createMemoryStore();
  const server = createApp(store);
  const base = await listen(server);
  await runFlows(base, store);

  // timing: unknown usernames should take about as long as wrong passwords
  await call(base, 'POST', '/api/signup', { username: 'dana', password: 'rock-tower-88' });
  const t0 = Date.now();
  for (let i = 0; i < 4; i++) await call(base, 'POST', '/api/login', { username: 'ghost' + i, password: 'whatever-1' });
  const unknownMs = (Date.now() - t0) / 4;
  const t1 = Date.now();
  for (let i = 0; i < 4; i++) await call(base, 'POST', '/api/login', { username: 'dana', password: 'wrong-guess' });
  const wrongMs = (Date.now() - t1) / 4;
  const ratio = unknownMs / wrongMs;
  console.log(`timing: unknown user ${unknownMs.toFixed(0)} ms, wrong password ${wrongMs.toFixed(0)} ms`);
  assert.ok(ratio > 0.5 && ratio < 2, 'unknown-user and wrong-password responses should take similar time');

  // concurrent logins all succeed
  const results = await Promise.all(Array.from({ length: 8 }, () => call(base, 'POST', '/api/login', { username: 'dana', password: 'rock-tower-88' })));
  assert.ok(results.every(r => r.status === 200), 'all concurrent logins should succeed');

  server.close();
  console.log('memory store: all flows and timing checks passed');
})().catch(e => { console.error('memory store FAILED:', e.message); process.exit(1); });
