const Database = require('better-sqlite3');

let db;

function init(dbPath) {
  db = new Database(dbPath);
  db.pragma('journal_mode = WAL');

  db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      ip TEXT NOT NULL,
      first_seen TEXT NOT NULL,
      last_seen TEXT NOT NULL,
      user_agent TEXT,
      browser TEXT,
      os TEXT,
      device TEXT,
      ip_country TEXT,
      ip_region TEXT,
      ip_city TEXT,
      ip_lat REAL,
      ip_lon REAL,
      browser_lat REAL,
      browser_lon REAL,
      browser_accuracy REAL,
      geo_permission TEXT,
      fingerprint_hash TEXT,
      request_count INTEGER DEFAULT 0,
      risk_score INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL,
      ts TEXT NOT NULL,
      method TEXT,
      path TEXT,
      query TEXT,
      body TEXT,
      headers TEXT,
      aims TEXT,
      FOREIGN KEY(session_id) REFERENCES sessions(id)
    );

    CREATE TABLE IF NOT EXISTS credential_attempts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL,
      ts TEXT NOT NULL,
      username TEXT,
      password TEXT,
      FOREIGN KEY(session_id) REFERENCES sessions(id)
    );

    CREATE INDEX IF NOT EXISTS idx_requests_session ON requests(session_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(ip);

    CREATE TABLE IF NOT EXISTS alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts TEXT NOT NULL,
      message TEXT NOT NULL,
      sent_by TEXT
    );
  `);

  return db;
}

function upsertSession(session) {
  const existing = db.prepare('SELECT id FROM sessions WHERE id = ?').get(session.id);
  const now = new Date().toISOString();

  if (!existing) {
    db.prepare(`
      INSERT INTO sessions (id, ip, first_seen, last_seen, user_agent, browser, os, device,
        ip_country, ip_region, ip_city, ip_lat, ip_lon, request_count)
      VALUES (@id, @ip, @now, @now, @user_agent, @browser, @os, @device,
        @ip_country, @ip_region, @ip_city, @ip_lat, @ip_lon, 1)
    `).run({ ...session, now });
  } else {
    db.prepare(`
      UPDATE sessions SET last_seen = ?, request_count = request_count + 1 WHERE id = ?
    `).run(now, session.id);
  }
}

function addRequest(entry) {
  db.prepare(`
    INSERT INTO requests (session_id, ts, method, path, query, body, headers, aims)
    VALUES (@session_id, @ts, @method, @path, @query, @body, @headers, @aims)
  `).run(entry);

  bumpRisk(entry.session_id, JSON.parse(entry.aims).length);
}

function bumpRisk(sessionId, aimCount) {
  db.prepare('UPDATE sessions SET risk_score = risk_score + ? WHERE id = ?')
    .run(aimCount, sessionId);
}

function addCredentialAttempt(sessionId, username, password) {
  db.prepare(`
    INSERT INTO credential_attempts (session_id, ts, username, password)
    VALUES (?, ?, ?, ?)
  `).run(sessionId, new Date().toISOString(), username, password);
  db.prepare('UPDATE sessions SET risk_score = risk_score + 5 WHERE id = ?').run(sessionId);
}

function updateBrowserGeo(sessionId, { lat, lon, accuracy, permission, fingerprintHash }) {
  db.prepare(`
    UPDATE sessions
    SET browser_lat = ?, browser_lon = ?, browser_accuracy = ?, geo_permission = ?, fingerprint_hash = ?
    WHERE id = ?
  `).run(lat, lon, accuracy, permission, fingerprintHash, sessionId);
}

function listSessions() {
  return db.prepare('SELECT * FROM sessions ORDER BY last_seen DESC').all();
}

function getSession(id) {
  return db.prepare('SELECT * FROM sessions WHERE id = ?').get(id);
}

function getRequestsForSession(id) {
  return db.prepare('SELECT * FROM requests WHERE session_id = ? ORDER BY ts ASC').all(id);
}

function getCredentialsForSession(id) {
  return db.prepare('SELECT * FROM credential_attempts WHERE session_id = ? ORDER BY ts ASC').all(id);
}

function resetAll() {
  db.exec(`
    DELETE FROM credential_attempts;
    DELETE FROM requests;
    DELETE FROM sessions;
  `);
}

function getRequestsPerDay(days) {
  days = days || 14;
  const rows = db.prepare(`
    SELECT substr(ts, 1, 10) as day, COUNT(*) as count
    FROM requests
    WHERE ts >= datetime('now', '-' || ? || ' days')
    GROUP BY day ORDER BY day ASC
  `).all(days);

  // Fill in any missing days with 0 so the chart has a continuous axis
  const map = {};
  rows.forEach((r) => { map[r.day] = r.count; });
  const result = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const key = d.toISOString().substring(0, 10);
    result.push({ day: key, count: map[key] || 0 });
  }
  return result;
}

function getAimDistribution(limit) {
  limit = limit || 8;
  const rows = db.prepare('SELECT aims FROM requests').all();
  const counts = {};
  rows.forEach((r) => {
    let aims = [];
    try { aims = JSON.parse(r.aims || '[]'); } catch (e) { /* ignore */ }
    aims.forEach((a) => { counts[a] = (counts[a] || 0) + 1; });
  });
  return Object.entries(counts)
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

function getRiskBuckets() {
  const low = db.prepare('SELECT COUNT(*) c FROM sessions WHERE risk_score < 5').get().c;
  const med = db.prepare('SELECT COUNT(*) c FROM sessions WHERE risk_score >= 5 AND risk_score < 15').get().c;
  const high = db.prepare('SELECT COUNT(*) c FROM sessions WHERE risk_score >= 15').get().c;
  return { low, med, high, total: low + med + high };
}

function getStats() {
  const totalSessions = db.prepare('SELECT COUNT(*) c FROM sessions').get().c;
  const totalRequests = db.prepare('SELECT COUNT(*) c FROM requests').get().c;
  const totalCreds = db.prepare('SELECT COUNT(*) c FROM credential_attempts').get().c;
  const topCountries = db.prepare(`
    SELECT ip_country as country, COUNT(*) as count FROM sessions
    WHERE ip_country IS NOT NULL GROUP BY ip_country ORDER BY count DESC LIMIT 10
  `).all();
  const topPaths = db.prepare(`
    SELECT path, COUNT(*) as count FROM requests GROUP BY path ORDER BY count DESC LIMIT 10
  `).all();
  const topAttackers = db.prepare(`
    SELECT id, ip, ip_country, risk_score, request_count FROM sessions
    ORDER BY risk_score DESC LIMIT 10
  `).all();

  return { totalSessions, totalRequests, totalCreds, topCountries, topPaths, topAttackers };
}

function addAlert(message, sentBy) {
  db.prepare('INSERT INTO alerts (ts, message, sent_by) VALUES (?, ?, ?)')
    .run(new Date().toISOString(), message, sentBy || 'admin');
}

function listAlerts() {
  return db.prepare('SELECT * FROM alerts ORDER BY ts DESC').all();
}

module.exports = {
  init,
  upsertSession,
  addRequest,
  addCredentialAttempt,
  updateBrowserGeo,
  listSessions,
  getSession,
  getRequestsForSession,
  getCredentialsForSession,
  getStats,
  resetAll,
  getRequestsPerDay,
  getAimDistribution,
  getRiskBuckets,
  addAlert,
  listAlerts
};
