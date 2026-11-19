// Starts the real server process and checks startup rules and basic HTTP behaviour.
const { spawn } = require('child_process');
const path = require('path');
const assert = require('assert');

const SERVER = path.join(__dirname, '..', 'server.js');
const BASE_ENV = { ...process.env };
delete BASE_ENV.PASSWORD_PEPPER; delete BASE_ENV.DATABASE_URL; delete BASE_ENV.ALLOW_MEMORY_STORE;

function run(env, waitFor, ms = 8000) {
  return new Promise(resolve => {
    const child = spawn(process.execPath, [SERVER], { env: { ...BASE_ENV, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    child.stdout.on('data', d => { out += d; if (waitFor && out.includes(waitFor)) resolve({ child, out, running: true }); });
    child.stderr.on('data', d => { out += d; });
    child.on('exit', code => resolve({ code, out, running: false }));
    setTimeout(() => { if (child.exitCode === null) { child.kill(); resolve({ out, timedOut: true, running: false }); } }, ms);
  });
}

(async () => {
  let r = await run({ ALLOW_MEMORY_STORE: '1' }, null, 4000);
  assert.equal(r.code, 1); assert.match(r.out, /PASSWORD_PEPPER is not set/, 'missing pepper must stop startup');

  r = await run({ PASSWORD_PEPPER: 'x' }, null, 4000);
  assert.equal(r.code, 1); assert.match(r.out, /DATABASE_URL is not set/, 'missing database must stop startup');

  const port = 4300 + Math.floor(Math.random() * 500);
  r = await run({ PASSWORD_PEPPER: 'smoke-pepper', ALLOW_MEMORY_STORE: '1', PORT: String(port) }, 'running');
  assert.equal(r.running, true, 'server should start: ' + r.out);
  try {
    const base = `http://127.0.0.1:${port}`;
    const health = await fetch(base + '/api/health'); assert.equal(health.status, 200);
    const home = await fetch(base + '/'); assert.equal(home.status, 200); assert.match(await home.text(), /<html|<!DOCTYPE/i);
    const signup = await fetch(base + '/api/signup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'smoke_user', password: 'smoke-river-1' }) });
    assert.equal(signup.status, 201);
    const cached = await fetch(base + '/api/me', { headers: { Authorization: 'Bearer ' + (await signup.json()).token } });
    assert.equal(cached.status, 200); assert.equal(cached.headers.get('cache-control'), 'no-store');
  } finally {
    r.child.kill();
  }

  // Unreachable database: startup must fail, not hang.
  r = await run({ PASSWORD_PEPPER: 'x', DATABASE_URL: 'postgres://u:p@127.0.0.1:1/db' }, null, 15000);
  assert.equal(r.code, 1, 'unreachable database must stop startup');

  console.log('smoke test: startup rules and live HTTP checks passed');
})().catch(e => { console.error('smoke test FAILED:', e.message); process.exit(1); });
