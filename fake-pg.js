// Stand-in for the pg driver. It checks that each query db.js sends is one we expect,
// with the right parameters, and returns rows the way pg does (bigint ids as strings).
// It does NOT check real PostgreSQL syntax; only a real database can do that.
const eq = (a, b) => String(a) === String(b);
const state = { users: [], sessions: [], progress: [], certs: [], seq: 1, schemaRuns: 0, unexpected: [] };

class FakePool {
  async query(sql, params = []) {
    const s = sql.replace(/\s+/g, ' ').trim();
    if (params.length === 0 && /CREATE (TABLE|UNIQUE INDEX)/.test(s)) { state.schemaRuns++; return { rows: [] }; }
    if (s.startsWith('INSERT INTO ict_users')) {
      const [username, pass_hash, pass_salt] = params;
      if (state.users.some(u => u.username.toLowerCase() === username.toLowerCase())) return { rows: [] };
      const row = { id: state.seq++, username, pass_hash, pass_salt };
      state.users.push(row);
      return { rows: [{ id: String(row.id) }] };
    }
    if (s.startsWith('SELECT id, username, pass_hash, pass_salt FROM ict_users')) {
      const u = state.users.find(x => x.username.toLowerCase() === String(params[0]).toLowerCase());
      return { rows: u ? [{ id: String(u.id), username: u.username, pass_hash: u.pass_hash, pass_salt: u.pass_salt }] : [] };
    }
    if (s.startsWith('INSERT INTO ict_sessions')) {
      const [token_hash, user_id, expires_at] = params;
      state.sessions.push({ token_hash, user_id, expires_at: new Date(expires_at) });
      return { rows: [] };
    }
    if (s.startsWith('SELECT u.id, u.username FROM ict_sessions')) {
      const sess = state.sessions.find(x => x.token_hash === params[0] && x.expires_at > new Date());
      if (!sess) return { rows: [] };
      const u = state.users.find(x => eq(x.id, sess.user_id));
      return { rows: [{ id: String(u.id), username: u.username }] };
    }
    if (s.startsWith('DELETE FROM ict_sessions')) {
      state.sessions = state.sessions.filter(x => x.token_hash !== params[0]);
      return { rows: [] };
    }
    if (s.startsWith('SELECT data FROM ict_progress')) {
      const p = state.progress.find(x => eq(x.user_id, params[0]));
      return { rows: p ? [{ data: JSON.parse(JSON.stringify(p.data)) }] : [] };
    }
    if (s.startsWith('INSERT INTO ict_progress')) {
      const [uid, json] = params;
      const ex = state.progress.find(x => eq(x.user_id, uid));
      if (typeof json !== 'string') throw new Error('fake pg: progress must be sent as JSON text');
      const data = JSON.parse(json);
      if (ex) ex.data = data; else state.progress.push({ user_id: uid, data });
      return { rows: [] };
    }
    if (s.startsWith('SELECT c.id, c.program, u.username')) {
      const list = s.includes('c.id=$1')
        ? state.certs.filter(c => c.id === params[0])
        : state.certs.filter(c => eq(c.user_id, params[0]) && c.program === params[1]);
      return { rows: list.map(c => ({ id: c.id, program: c.program, holder: state.users.find(x => eq(x.id, c.user_id)).username, issuedAt: c.issued_at })) };
    }
    if (s.startsWith('INSERT INTO ict_certificates')) {
      const [id, uid, program, issued_at] = params;
      if (state.certs.some(c => eq(c.user_id, uid) && c.program === program)) return { rows: [] };
      state.certs.push({ id, user_id: uid, program, issued_at: new Date(issued_at) });
      return { rows: [] };
    }
    state.unexpected.push(s);
    throw new Error('fake pg: unexpected SQL: ' + s.slice(0, 90));
  }
}

module.exports = { FakePool, state };
