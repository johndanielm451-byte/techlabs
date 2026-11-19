const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { createStore } = require('./db');

const PUBLIC = path.join(__dirname, 'public');
const MAX_BODY = 300 * 1024;
const SESSION_DAYS = 30;
const PROGRAMS = ['coc1', 'coc2', 'coc3', 'coc4'];
const USERNAME = /^[A-Za-z0-9_]{3,24}$/;
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.json': 'application/json' };

class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
// Passwords are keyed with a secret pepper (env var, not stored in the database), then hashed with scrypt.
const PEPPER = process.env.PASSWORD_PEPPER || '';
const SCRYPT = { N: 65536, r: 8, p: 1, maxmem: 128 * 1024 * 1024 };
const hashPassword = (pw, salt) => crypto.scryptSync(crypto.createHmac('sha256', PEPPER).update(pw).digest(), salt, 64, SCRYPT).toString('hex');
const DUMMY_SALT = crypto.randomBytes(16).toString('hex'); // used for unknown usernames so timing doesn't reveal accounts
const COMMON = new Set(['password', 'password1', '12345678', '123456789', 'qwerty123', 'letmein123', 'iloveyou', 'admin1234', 'welcome1', 'computer1']);
const WIN = 15 * 60 * 1000;
const hits = new Map();
function countOf(key, windowMs) { const h = hits.get(key); return !h || Date.now() - h.first > windowMs ? 0 : h.count; }
function bump(key, windowMs) {
  const h = hits.get(key);
  if (!h || Date.now() - h.first > windowMs) hits.set(key, { count: 1, first: Date.now() }); else h.count++;
}
setInterval(() => { for (const [k, h] of hits) if (Date.now() - h.first > 3600e3) hits.delete(k); }, 600e3).unref();
function clientIp(req) {
  // Render adds the real client address as the last X-Forwarded-For entry; earlier entries can be faked.
  const parts = String(req.headers['x-forwarded-for'] || '').split(',').map(x => x.trim()).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : req.socket.remoteAddress;
}
function passwordProblem(pw, username) {
  if (typeof pw !== 'string' || pw.length < 8) return 'Password must be at least 8 characters';
  if (pw.length > 128) return 'Password must be at most 128 characters';
  if (pw.toLowerCase().includes(username.toLowerCase())) return 'Password cannot contain your username';
  if (COMMON.has(pw.toLowerCase())) return 'That password is too common';
  return null;
}

function send(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(body));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', c => {
      size += c.length;
      if (size > MAX_BODY) { req.destroy(); return reject(new HttpError(413, 'Request too large')); }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(new HttpError(400, 'Invalid JSON')); }
    });
    req.on('error', reject);
  });
}

function bearer(req) {
  const m = /^Bearer ([a-f0-9]{64})$/.exec(req.headers.authorization || '');
  return m ? m[1] : null;
}

async function issueSession(store, userId, username) {
  const token = crypto.randomBytes(32).toString('hex');
  await store.createSession(sha256(token), userId, new Date(Date.now() + SESSION_DAYS * 864e5));
  return { token, username };
}

async function handleApi(req, res, url, store) {
  const route = `${req.method} ${url.pathname}`;
  const certId = /^\/api\/certificates\/(ICT-[A-Fa-f0-9]{12})$/i.exec(url.pathname);
  if (route === 'GET /api/health') return send(res, 200, { ok: true });
  if (req.method === 'GET' && certId) {
    const cert = await store.getCert(certId[1].toUpperCase());
    if (!cert) throw new HttpError(404, 'No certificate with that number');
    return send(res, 200, { ...cert, valid: true });
  }
  const body = req.method === 'POST' || req.method === 'PUT' ? await readJson(req) : {};

  if (route === 'POST /api/signup') {
    const { username = '', password = '' } = body;
    if (!USERNAME.test(username)) throw new HttpError(400, 'Username: 3–24 letters, numbers or _');
    const problem = passwordProblem(password, username);
    if (problem) throw new HttpError(400, problem);
    const ip = 'signup:' + clientIp(req);
    if (countOf(ip, 3600e3) >= 100) throw new HttpError(429, 'Too many sign-ups from this network. Try again later.');
    bump(ip, 3600e3);
    const salt = crypto.randomBytes(16).toString('hex');
    const id = await store.createUser(username, hashPassword(password, salt), salt);
    if (!id) throw new HttpError(409, 'That username is taken');
    return send(res, 201, await issueSession(store, id, username));
  }
  if (route === 'POST /api/login') {
    const name = String(body.username || '').slice(0, 64);
    const userKey = 'user:' + name.toLowerCase(), ipKey = 'ip:' + clientIp(req);
    if (countOf(userKey, WIN) >= 10 || countOf(ipKey, WIN) >= 50) throw new HttpError(429, 'Too many failed logins. Try again in 15 minutes.');
    const user = await store.userByName(name);
    const given = typeof body.password === 'string' ? body.password : '';
    const hash = hashPassword(given, user ? user.pass_salt : DUMMY_SALT); // same work for unknown usernames
    const ok = !!user && given.length > 0 && crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(user.pass_hash, 'hex'));
    if (!ok) { bump(userKey, WIN); bump(ipKey, WIN); throw new HttpError(401, 'Wrong username or password'); }
    hits.delete(userKey);
    return send(res, 200, await issueSession(store, user.id, user.username));
  }
  if (route === 'POST /api/logout') {
    const t = bearer(req);
    if (t) await store.deleteSession(sha256(t));
    return send(res, 200, { ok: true });
  }

  const t = bearer(req);
  const user = t ? await store.userForToken(sha256(t)) : null;
  if (!user) throw new HttpError(401, 'Please log in');
  if (route === 'GET /api/me') return send(res, 200, { username: user.username });
  if (route === 'GET /api/progress') return send(res, 200, { data: await store.getProgress(user.id) });
  if (route === 'PUT /api/progress') {
    if (!body.data || typeof body.data !== 'object' || Array.isArray(body.data)) throw new HttpError(400, 'Send {"data": {...}}');
    await store.saveProgress(user.id, body.data);
    return send(res, 200, { ok: true });
  }
  if (route === 'POST /api/certificates') {
    const program = String(body.program || '');
    if (!PROGRAMS.includes(program)) throw new HttpError(400, 'Unknown program');
    const existing = await store.findCert(user.id, program);
    if (existing) return send(res, 200, existing);
    const progress = (await store.getProgress(user.id)) || {};
    const completed = progress[program] && progress[program].completed;
    if (!Array.isArray(completed) || !completed.length || !completed.every(Boolean)) throw new HttpError(403, 'Finish every module first');
    const cert = { id: 'ICT-' + crypto.randomBytes(6).toString('hex').toUpperCase(), program, holder: user.username, issuedAt: new Date().toISOString() };
    return send(res, 201, await store.createCert(user.id, cert));
  }
  throw new HttpError(404, 'Not found');
}

function serveStatic(req, res, url) {
  let p = decodeURIComponent(url.pathname);
  if (p === '/') p = '/index.html';
  const file = path.normalize(path.join(PUBLIC, p));
  if (!file.startsWith(PUBLIC + path.sep)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  });
}

function createApp(store) {
  return http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    try {
      if (url.pathname.startsWith('/api/')) await handleApi(req, res, url, store);
      else serveStatic(req, res, url);
    } catch (err) {
      if (!(err instanceof HttpError)) console.error(err);
      if (!res.headersSent) send(res, err instanceof HttpError ? err.status : 500, { error: err instanceof HttpError ? err.message : 'Server error' });
    }
  });
}

if (require.main === module) {
  if (!PEPPER) { console.error('PASSWORD_PEPPER is not set'); process.exit(1); }
  createStore()
    .then(store => createApp(store).listen(process.env.PORT || 3000, () => console.log('ICT Tech Lab server is running')))
    .catch(err => { console.error(err.message); process.exit(1); });
}

module.exports = { createApp };
