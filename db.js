const fs = require('fs');
const path = require('path');

const CERT_SQL = 'SELECT c.id, c.program, u.username AS holder, c.issued_at AS "issuedAt" FROM ict_certificates c JOIN ict_users u ON u.id = c.user_id';

function createMemoryStore() {
  // For tests and local runs only. Data is lost when the process stops.
  const users = new Map(), byName = new Map(), sessions = new Map(), progress = new Map(), certs = new Map();
  let nextId = 1;
  return {
    async createUser(username, pass_hash, pass_salt) {
      if (byName.has(username.toLowerCase())) return null;
      const u = { id: nextId++, username, pass_hash, pass_salt };
      users.set(u.id, u); byName.set(username.toLowerCase(), u);
      return u.id;
    },
    async userByName(name) { return byName.get(name.toLowerCase()) || null; },
    async createSession(tokenHash, userId, expiresAt) { sessions.set(tokenHash, { userId, expiresAt }); },
    async userForToken(tokenHash) {
      const s = sessions.get(tokenHash);
      if (!s || s.expiresAt < new Date()) return null;
      const u = users.get(s.userId);
      return { id: u.id, username: u.username };
    },
    async deleteSession(tokenHash) { sessions.delete(tokenHash); },
    async getProgress(userId) { return progress.get(userId) || null; },
    async saveProgress(userId, data) { progress.set(userId, data); },
    async findCert(userId, program) { return certs.get(userId + ':' + program) || null; },
    async createCert(userId, cert) {
      const key = userId + ':' + cert.program;
      if (!certs.has(key)) certs.set(key, { id: cert.id, program: cert.program, holder: cert.holder, issuedAt: cert.issuedAt });
      return certs.get(key);
    },
    async getCert(id) { for (const c of certs.values()) if (c.id === id) return c; return null; },
  };
}

async function createPgStore(url) {
  const { Pool } = require('pg');
  // Internal Render URLs need no SSL. For connections from outside Render, set PGSSL=require.
  const pool = new Pool({ connectionString: url, ssl: process.env.PGSSL === 'require' ? { rejectUnauthorized: false } : undefined });
  await pool.query(fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8'));
  const one = async (sql, params) => (await pool.query(sql, params)).rows[0] || null;
  const certFor = (uid, program) => one(CERT_SQL + ' WHERE c.user_id=$1 AND c.program=$2', [uid, program]);
  return {
    async createUser(username, hash, salt) {
      const r = await pool.query('INSERT INTO ict_users (username, pass_hash, pass_salt) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING RETURNING id', [username, hash, salt]);
      return r.rows[0] ? Number(r.rows[0].id) : null;
    },
    userByName: name => one('SELECT id, username, pass_hash, pass_salt FROM ict_users WHERE lower(username)=lower($1)', [name]),
    async createSession(tokenHash, userId, expiresAt) {
      await pool.query('INSERT INTO ict_sessions (token_hash, user_id, expires_at) VALUES ($1,$2,$3)', [tokenHash, userId, expiresAt]);
    },
    userForToken: h => one('SELECT u.id, u.username FROM ict_sessions s JOIN ict_users u ON u.id = s.user_id WHERE s.token_hash=$1 AND s.expires_at > now()', [h]),
    async deleteSession(tokenHash) { await pool.query('DELETE FROM ict_sessions WHERE token_hash=$1', [tokenHash]); },
    async getProgress(uid) { const r = await one('SELECT data FROM ict_progress WHERE user_id=$1', [uid]); return r ? r.data : null; },
    async saveProgress(uid, data) {
      await pool.query('INSERT INTO ict_progress (user_id, data, updated_at) VALUES ($1,$2,now()) ON CONFLICT (user_id) DO UPDATE SET data=EXCLUDED.data, updated_at=now()', [uid, JSON.stringify(data)]);
    },
    findCert: certFor,
    async createCert(uid, cert) {
      await pool.query('INSERT INTO ict_certificates (id, user_id, program, issued_at) VALUES ($1,$2,$3,$4) ON CONFLICT (user_id, program) DO NOTHING', [cert.id, uid, cert.program, cert.issuedAt]);
      return certFor(uid, cert.program);
    },
    getCert: id => one(CERT_SQL + ' WHERE c.id=$1', [id]),
  };
}

async function createStore() {
  if (process.env.DATABASE_URL) return createPgStore(process.env.DATABASE_URL);
  if (process.env.ALLOW_MEMORY_STORE === '1') { console.warn('Memory store in use: data is lost on restart'); return createMemoryStore(); }
  throw new Error('DATABASE_URL is not set');
}

module.exports = { createStore, createMemoryStore };
