process.env.PASSWORD_PEPPER = process.env.PASSWORD_PEPPER || 'test-pepper-for-tests-only';
process.env.DATABASE_URL = 'postgres://test:test@localhost:5432/test';
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const Module = require('module');
const { FakePool, state } = require('./fake-pg');

// Route require('pg') to the fake driver.
const realLoad = Module._load;
Module._load = function (request, ...rest) {
  if (request === 'pg') return { Pool: FakePool };
  return realLoad.call(this, request, ...rest);
};

// Check schema.sql structure: every statement is CREATE, parentheses balance, all tables present.
const schema = fs.readFileSync(path.join(__dirname, '..', 'schema.sql'), 'utf8').replace(/--.*$/gm, '');
const statements = schema.split(';').map(x => x.trim()).filter(Boolean);
for (const st of statements) {
  assert.match(st, /^CREATE (TABLE|UNIQUE INDEX) IF NOT EXISTS /, 'bad statement: ' + st.slice(0, 40));
  assert.equal((st.match(/\(/g) || []).length, (st.match(/\)/g) || []).length, 'unbalanced parentheses in: ' + st.slice(0, 40));
}
for (const t of ['ict_users', 'ict_sessions', 'ict_progress', 'ict_certificates']) assert.ok(schema.includes('TABLE IF NOT EXISTS ' + t));

const { createStore } = require('../db');
const { createApp } = require('../server');
const { runFlows } = require('./flows');
const { listen } = require('./flows');

(async () => {
  const store = await createStore();
  assert.equal(state.schemaRuns >= 1, true, 'schema should run at startup');
  const server = createApp(store);
  const base = await listen(server);
  await runFlows(base, store);
  server.close();
  assert.deepEqual(state.unexpected, [], 'unexpected SQL reached the database layer');
  console.log(`postgres code path: ${statements.length} schema statements OK, all flows passed (fake driver, not real SQL)`);
})().catch(e => { console.error('postgres code path FAILED:', e.message); process.exit(1); });
