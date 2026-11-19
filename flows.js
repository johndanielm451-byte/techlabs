const assert = require('assert');
const crypto = require('crypto');

const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');

async function call(base, method, p, body, token) {
  const r = await fetch(base + p, {
    method,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) },
    body: body !== undefined && body !== null ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  let json = null; try { json = JSON.parse(text); } catch {}
  return { status: r.status, json, text };
}

function listen(server) {
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${server.address().port}`)));
}

// The same HTTP-level checks run against every store, so the database code path gets the same coverage.
async function runFlows(base, store) {
  let r;
  r = await call(base, 'GET', '/api/health'); assert.equal(r.status, 200);
  r = await call(base, 'GET', '/'); assert.equal(r.status, 200); assert.match(r.text, /<html|<!DOCTYPE/i);
  r = await call(base, 'GET', '/nope.txt'); assert.equal(r.status, 404);
  r = await call(base, 'GET', '/%2e%2e/server.js'); assert.ok(r.status !== 200 || !r.text.includes('createApp'), 'path traversal must not serve server code');
  r = await call(base, 'GET', '/api/unknown-route'); assert.equal(r.status, 401);

  // signup rules
  r = await call(base, 'POST', '/api/signup', { username: 'a!', password: 'correct-horse-9' }); assert.equal(r.status, 400);
  r = await call(base, 'POST', '/api/signup', { username: 'x'.repeat(25), password: 'correct-horse-9' }); assert.equal(r.status, 400);
  r = await call(base, 'POST', '/api/signup', { username: 'alice', password: '123' }); assert.equal(r.status, 400);
  r = await call(base, 'POST', '/api/signup', { username: 'alice', password: 'p'.repeat(129) }); assert.equal(r.status, 400);
  r = await call(base, 'POST', '/api/signup', { username: 'alice', password: 'password' }); assert.equal(r.status, 400);
  r = await call(base, 'POST', '/api/signup', { username: 'carol', password: 'carol-is-here' }); assert.equal(r.status, 400);
  r = await call(base, 'POST', '/api/signup', { username: 'alice', password: 12345678 }); assert.equal(r.status, 400);

  // signup, duplicates, stored hash shape
  r = await call(base, 'POST', '/api/signup', { username: 'alice', password: 'correct-horse-9' }); assert.equal(r.status, 201);
  const aliceToken = r.json.token;
  assert.match(aliceToken, /^[a-f0-9]{64}$/);
  r = await call(base, 'POST', '/api/signup', { username: 'ALICE', password: 'correct-horse-9' }); assert.equal(r.status, 409);
  const u = await store.userByName('alice');
  assert.equal(u.pass_hash.length, 128); assert.equal(u.pass_salt.length, 32); assert.ok(!u.pass_hash.includes('correct'));

  // login
  r = await call(base, 'POST', '/api/login', { username: 'alice', password: 'wrong-one' }); assert.equal(r.status, 401);
  r = await call(base, 'POST', '/api/login', { username: 'nobody', password: 'whatever-1' }); assert.equal(r.status, 401);
  r = await call(base, 'POST', '/api/login', { username: 'alice' }); assert.equal(r.status, 401);
  r = await call(base, 'POST', '/api/login', { username: 'alice', password: 12345 }); assert.equal(r.status, 401);
  r = await call(base, 'POST', '/api/login', { username: 'ALICE', password: 'correct-horse-9' }); assert.equal(r.status, 200);
  const aliceToken2 = r.json.token;
  r = await fetch(base + '/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{not json' });
  assert.equal(r.status, 400);

  // auth gate and session checks
  r = await call(base, 'GET', '/api/progress'); assert.equal(r.status, 401);
  r = await call(base, 'GET', '/api/me', null, 'bogus'); assert.equal(r.status, 401);
  r = await call(base, 'GET', '/api/me', null, aliceToken); assert.equal(r.json.username, 'alice');
  r = await call(base, 'GET', '/api/me', null, aliceToken2); assert.equal(r.json.username, 'alice');

  // progress
  r = await call(base, 'GET', '/api/progress', null, aliceToken); assert.equal(r.json.data, null);
  r = await call(base, 'PUT', '/api/progress', { data: { xp: 500 } }, aliceToken); assert.equal(r.status, 200);
  r = await call(base, 'PUT', '/api/progress', { data: [1, 2] }, aliceToken); assert.equal(r.status, 400);
  r = await call(base, 'PUT', '/api/progress', { nope: 1 }, aliceToken); assert.equal(r.status, 400);
  r = await call(base, 'GET', '/api/progress', null, aliceToken); assert.equal(r.json.data.xp, 500);
  r = await call(base, 'POST', '/api/signup', { username: 'bob', password: 'river-stone-7' }); assert.equal(r.status, 201);
  const bobToken = r.json.token;
  r = await call(base, 'GET', '/api/progress', null, bobToken); assert.equal(r.json.data, null);
  await call(base, 'PUT', '/api/progress', { data: { xp: 1 } }, bobToken);
  r = await call(base, 'GET', '/api/progress', null, aliceToken); assert.equal(r.json.data.xp, 500);

  // certificates
  r = await call(base, 'POST', '/api/certificates', { program: 'coc9' }, aliceToken); assert.equal(r.status, 400);
  r = await call(base, 'POST', '/api/certificates', { program: 'coc1' }, aliceToken); assert.equal(r.status, 403);
  await call(base, 'PUT', '/api/progress', { data: { coc1: { completed: [true, false] } } }, aliceToken);
  r = await call(base, 'POST', '/api/certificates', { program: 'coc1' }, aliceToken); assert.equal(r.status, 403);
  await call(base, 'PUT', '/api/progress', { data: { coc1: { completed: Array(11).fill(true) } } }, aliceToken);
  r = await call(base, 'POST', '/api/certificates', { program: 'coc1' }, aliceToken); assert.equal(r.status, 201);
  const certId = r.json.id;
  assert.match(certId, /^ICT-[A-F0-9]{12}$/);
  r = await call(base, 'POST', '/api/certificates', { program: 'coc1' }, aliceToken); assert.equal(r.json.id, certId);
  r = await call(base, 'GET', '/api/certificates/' + certId); assert.equal(r.status, 200);
  assert.equal(r.json.holder, 'alice'); assert.equal(r.json.program, 'coc1'); assert.equal(r.json.valid, true);
  r = await call(base, 'GET', '/api/certificates/' + certId.toLowerCase()); assert.equal(r.status, 200);
  r = await call(base, 'GET', '/api/certificates/ICT-000000000000'); assert.equal(r.status, 404);
  r = await call(base, 'POST', '/api/certificates', { program: 'coc1' }, bobToken); assert.equal(r.status, 403);

  // expired session is rejected
  const raw = crypto.randomBytes(32).toString('hex');
  const bobUser = await store.userByName('bob');
  await store.createSession(sha256(raw), bobUser.id, new Date(Date.now() - 1000));
  r = await call(base, 'GET', '/api/me', null, raw); assert.equal(r.status, 401);

  // oversized body does not crash the server
  let status = null;
  try {
    const big = await fetch(base + '/api/signup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'huge', password: 'x'.repeat(400 * 1024) }) });
    status = big.status;
  } catch {}
  assert.ok(status === null || status === 413, 'oversized body should get 413 or a dropped connection');
  r = await call(base, 'GET', '/api/health'); assert.equal(r.status, 200);

  // logout ends the session
  r = await call(base, 'POST', '/api/logout', null, aliceToken); assert.equal(r.status, 200);
  r = await call(base, 'GET', '/api/me', null, aliceToken); assert.equal(r.status, 401);
  r = await call(base, 'GET', '/api/me', null, aliceToken2); assert.equal(r.status, 200);
  r = await call(base, 'GET', '/api/unknown-route', null, bobToken); assert.equal(r.status, 404);

  // lockout for one user, then the correct password is refused until the window passes
  r = await call(base, 'POST', '/api/signup', { username: 'erin', password: 'stone-tower-42' }); assert.equal(r.status, 201);
  for (let i = 0; i < 10; i++) await call(base, 'POST', '/api/login', { username: 'erin', password: 'wrong-guess' });
  r = await call(base, 'POST', '/api/login', { username: 'erin', password: 'stone-tower-42' }); assert.equal(r.status, 429);
}

module.exports = { call, listen, runFlows, sha256 };
