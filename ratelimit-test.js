process.env.PASSWORD_PEPPER = process.env.PASSWORD_PEPPER || 'test-pepper-for-tests-only';
const assert = require('assert');
const { createApp } = require('../server');
const { createMemoryStore } = require('../db');
const { call, listen } = require('./flows');

(async () => {
  const store = createMemoryStore();
  const server = createApp(store);
  const base = await listen(server);

  // sign-ups: 100 per network per hour
  for (let i = 1; i <= 100; i++) {
    const r = await call(base, 'POST', '/api/signup', { username: 'user' + String(i).padStart(3, '0'), password: 'stone-river-' + i });
    assert.equal(r.status, 201, 'signup ' + i);
  }
  let r = await call(base, 'POST', '/api/signup', { username: 'user101', password: 'stone-river-101' });
  assert.equal(r.status, 429, 'signup 101 should be limited');

  // failed logins: 50 per network per 15 minutes, across different usernames
  for (let i = 1; i <= 50; i++) await call(base, 'POST', '/api/login', { username: 'nobody' + i, password: 'whatever-1' });
  r = await call(base, 'POST', '/api/login', { username: 'user001', password: 'stone-river-1' });
  assert.equal(r.status, 429, 'correct password should be refused once the network is over its limit');

  server.close();
  console.log('rate limits: sign-up and login network limits enforced');
})().catch(e => { console.error('rate limit test FAILED:', e.message); process.exit(1); });
