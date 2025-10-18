// Minimal secure backend: stores wishes in SQLite, session auth for admin
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 3000;

// CONFIG: set ADMIN_PASSWORD env var before starting (plaintext). For stronger security, store a bcrypt hash.
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change_me_now';

// Ensure DB folder
const DB_FILE = path.join(__dirname, 'wishes.db');
const db = new sqlite3.Database(DB_FILE);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS wishes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    text TEXT NOT NULL,
    ts INTEGER NOT NULL
  )`);
});

// Middleware
app.use(helmet());
app.use(express.json({ limit: '2kb' }));
app.use(express.urlencoded({ extended: false }));

// Rate limit sensitive endpoints
const limiter = rateLimit({ windowMs: 60*1000, max: 30 });
app.use('/api/', limiter);

// Session (in-memory for dev). In production use a proper session store and set cookie.secure=true with HTTPS.
app.use(session({
  name: 'bday_sid',
  secret: process.env.SESSION_SECRET || 'replace_session_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax' }
}));

// Serve static site (your index.html and assets)
app.use(express.static(path.join(__dirname)));

// API: submit a wish (open to visitors)
app.post('/api/wishes', (req, res) => {
  const { text } = req.body || {};
  if (!text || typeof text !== 'string' || text.trim().length === 0 || text.trim().length > 1000) {
    return res.status(400).json({ error: 'Invalid wish' });
  }
  const clean = text.trim();
  const ts = Date.now();
  db.run('INSERT INTO wishes (text, ts) VALUES (?, ?)', [clean, ts], function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    return res.json({ ok: true, id: this.lastID });
  });
});

// Admin login (creates session). POST { password }
app.post('/admin/login', (req, res) => {
  const pw = String(req.body.password || '');
  if (!pw) return res.status(400).json({ error: 'Missing' });

  // timing-safe check using bcrypt: hash provided pw with the stored salted hash
  // For simplicity we compare bcrypt hash of ADMIN_PASSWORD with provided password.
  // We'll store bcrypt hash derived from ADMIN_PASSWORD at runtime.
  if (!app.locals.ADMIN_HASH) {
    // create hash once from ADMIN_PASSWORD env (avoid storing plaintext permanently)
    const salt = bcrypt.genSaltSync(10);
    app.locals.ADMIN_HASH = bcrypt.hashSync(ADMIN_PASSWORD, salt);
  }

  const ok = bcrypt.compareSync(pw, app.locals.ADMIN_HASH);
  if (!ok) return res.status(401).json({ error: 'Invalid' });

  req.session.isAdmin = true;
  return res.json({ ok: true });
});

// Admin logout
app.post('/admin/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// Middleware to require admin
function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  res.status(401).json({ error: 'unauth' });
}

// Protected API: get wishes
app.get('/api/wishes', requireAdmin, (req, res) => {
  db.all('SELECT id, text, ts FROM wishes ORDER BY ts DESC LIMIT 1000', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB' });
    res.json(rows);
  });
});

// Protected API: clear wishes
app.post('/api/wishes/clear', requireAdmin, (req, res) => {
  db.run('DELETE FROM wishes', (err) => {
    if (err) return res.status(500).json({ error: 'DB' });
    res.json({ ok: true });
  });
});

// Serve admin assets (admin.html should be added)
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));