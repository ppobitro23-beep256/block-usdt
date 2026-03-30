const express = require('express');
const Database = require('better-sqlite3');
const cors = require('cors');
const crypto = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;
const BOT_TOKEN = process.env.BOT_TOKEN || "YOUR_BOT_TOKEN";

app.use(cors());
app.use(express.json());

// ─────────────────────────────────────────────
// DATABASE SETUP
// ─────────────────────────────────────────────
const db = new Database('cryptovault.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY,   -- Telegram user ID
    first_name  TEXT,
    last_name   TEXT,
    username    TEXT,
    language    TEXT,
    is_premium  INTEGER DEFAULT 0,
    balance     REAL    DEFAULT 0,
    total_earned REAL   DEFAULT 0,
    today_earned REAL   DEFAULT 0,
    ref_code    TEXT UNIQUE,
    referred_by INTEGER,
    created_at  TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS investments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER,
    plan_name   TEXT,
    amount      REAL,
    daily_pct   REAL,
    daily_earn  REAL,
    days_total  INTEGER,
    days_done   INTEGER DEFAULT 0,
    status      TEXT    DEFAULT 'active',
    started_at  TEXT    DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER,
    type        TEXT,    -- deposit | withdraw | earn | referral_bonus
    amount      REAL,
    status      TEXT    DEFAULT 'pending',
    network     TEXT,
    address     TEXT,
    txid        TEXT,
    note        TEXT,
    created_at  TEXT    DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS tasks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER,
    task_key    TEXT,
    completed   INTEGER DEFAULT 0,
    completed_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

// ─────────────────────────────────────────────
// TELEGRAM AUTH VERIFICATION
// ─────────────────────────────────────────────
function verifyTelegramData(initData) {
  try {
    const params = new URLSearchParams(initData);
    const hash = params.get('hash');
    params.delete('hash');
    const dataCheckArr = [];
    params.forEach((val, key) => dataCheckArr.push(`${key}=${val}`));
    dataCheckArr.sort();
    const dataCheckString = dataCheckArr.join('\n');
    const secretKey = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
    const hmac = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
    return hmac === hash;
  } catch { return false; }
}

// Middleware: verify Telegram user
function authMiddleware(req, res, next) {
  const initData = req.headers['x-telegram-init-data'] || req.body.initData;
  if (!initData) return res.status(401).json({ error: 'No auth data' });

  // In development, skip verification
  if (process.env.NODE_ENV !== 'production' || verifyTelegramData(initData)) {
    try {
      const params = new URLSearchParams(initData);
      const userStr = params.get('user');
      req.tgUser = userStr ? JSON.parse(userStr) : null;
    } catch { req.tgUser = null; }
    return next();
  }
  return res.status(403).json({ error: 'Invalid auth' });
}

// ─────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────

// POST /api/auth — register/login user
app.post('/api/auth', authMiddleware, (req, res) => {
  const u = req.tgUser;
  if (!u) return res.status(400).json({ error: 'No user data' });

  const refCode = 'REF' + u.id;
  const referredBy = req.body.ref || null;

  // Upsert user
  db.prepare(`
    INSERT INTO users (id, first_name, last_name, username, language, is_premium, ref_code, referred_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      first_name = excluded.first_name,
      last_name  = excluded.last_name,
      username   = excluded.username,
      language   = excluded.language,
      is_premium = excluded.is_premium
  `).run(u.id, u.first_name||'', u.last_name||'', u.username||'', u.language_code||'', u.is_premium?1:0, refCode, referredBy);

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(u.id);

  // Active investments
  const investments = db.prepare(`SELECT * FROM investments WHERE user_id = ? AND status = 'active'`).get(u.id);

  res.json({ success: true, user, investments });
});

// GET /api/user/:id — get full user data
app.get('/api/user/:id', (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const investments = db.prepare(`SELECT * FROM investments WHERE user_id = ? AND status = 'active'`).all(req.params.id);
  const transactions = db.prepare(`SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 20`).all(req.params.id);
  const tasks = db.prepare('SELECT task_key FROM tasks WHERE user_id = ? AND completed = 1').all(req.params.id).map(t => t.task_key);
  const referrals = db.prepare('SELECT id, first_name, username, created_at FROM users WHERE referred_by = ?').all(req.params.id);

  res.json({ user, investments, transactions, tasks, referrals });
});

// POST /api/invest — buy a plan
app.post('/api/invest', authMiddleware, (req, res) => {
  const u = req.tgUser;
  const { plan_name, amount, daily_pct } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(u.id);

  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.balance < amount) return res.status(400).json({ error: 'Insufficient balance' });

  const daily_earn = +(amount * daily_pct / 100).toFixed(4);

  db.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').run(amount, u.id);
  db.prepare(`INSERT INTO investments (user_id, plan_name, amount, daily_pct, daily_earn, days_total) VALUES (?,?,?,?,?,30)`)
    .run(u.id, plan_name, amount, daily_pct, daily_earn);
  db.prepare(`INSERT INTO transactions (user_id, type, amount, status, note) VALUES (?,?,?,?,?)`)
    .run(u.id, 'invest', amount, 'completed', `Invested in ${plan_name}`);

  res.json({ success: true, daily_earn });
});

// POST /api/deposit — submit deposit request
app.post('/api/deposit', authMiddleware, (req, res) => {
  const u = req.tgUser;
  const { amount, network, txid } = req.body;
  if (amount < 5) return res.status(400).json({ error: 'Min deposit $5' });

  db.prepare(`INSERT INTO transactions (user_id, type, amount, status, network, txid) VALUES (?,?,?,?,?,?)`)
    .run(u.id, 'deposit', amount, 'pending', network, txid);

  res.json({ success: true, message: 'Deposit submitted, pending review' });
});

// POST /api/withdraw — submit withdrawal request
app.post('/api/withdraw', authMiddleware, (req, res) => {
  const u = req.tgUser;
  const { amount, network, address } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(u.id);

  if (!user) return res.status(404).json({ error: 'User not found' });
  if (amount < 10) return res.status(400).json({ error: 'Min withdraw $10' });
  if (user.balance < amount) return res.status(400).json({ error: 'Insufficient balance' });

  db.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').run(amount, u.id);
  db.prepare(`INSERT INTO transactions (user_id, type, amount, status, network, address) VALUES (?,?,?,?,?,?)`)
    .run(u.id, 'withdraw', amount, 'pending', network, address);

  res.json({ success: true, message: 'Withdrawal submitted, processing 1-24hrs' });
});

// POST /api/task/complete — complete a task
app.post('/api/task/complete', authMiddleware, (req, res) => {
  const u = req.tgUser;
  const { task_key, reward } = req.body;

  const existing = db.prepare('SELECT * FROM tasks WHERE user_id = ? AND task_key = ?').get(u.id, task_key);
  if (existing && existing.completed) return res.status(400).json({ error: 'Task already completed' });

  db.prepare(`INSERT OR REPLACE INTO tasks (user_id, task_key, completed, completed_at) VALUES (?,?,1,datetime('now'))`).run(u.id, task_key);
  db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(reward, u.id);
  db.prepare(`INSERT INTO transactions (user_id, type, amount, status, note) VALUES (?,?,?,?,?)`)
    .run(u.id, 'earn', reward, 'completed', `Task: ${task_key}`);

  res.json({ success: true });
});

// ─────────────────────────────────────────────
// CRON: distribute daily returns every hour
// ─────────────────────────────────────────────
function distributeReturns() {
  const activeInvestments = db.prepare(`
    SELECT * FROM investments WHERE status = 'active' AND days_done < days_total
  `).all();

  const hourlyEarn = activeInvestments.reduce((acc, inv) => {
    const earn = +(inv.daily_earn / 24).toFixed(6);
    acc[inv.user_id] = (acc[inv.user_id] || 0) + earn;
    return acc;
  }, {});

  for (const [userId, earn] of Object.entries(hourlyEarn)) {
    db.prepare('UPDATE users SET balance = balance + ?, total_earned = total_earned + ?, today_earned = today_earned + ? WHERE id = ?')
      .run(earn, earn, earn, userId);
  }

  // Complete investments that finished
  db.prepare(`UPDATE investments SET status='completed', days_done=days_total WHERE days_done >= days_total`).run();

  console.log(`[CRON] Distributed returns to ${Object.keys(hourlyEarn).length} users`);
}

// Reset today_earned daily at midnight
function resetDailyEarnings() {
  db.prepare('UPDATE users SET today_earned = 0').run();
  console.log('[CRON] Daily earnings reset');
}

// Run every hour
setInterval(distributeReturns, 60 * 60 * 1000);

// Reset daily at midnight
const now = new Date();
const msToMidnight = new Date(now.getFullYear(), now.getMonth(), now.getDate()+1) - now;
setTimeout(() => {
  resetDailyEarnings();
  setInterval(resetDailyEarnings, 24 * 60 * 60 * 1000);
}, msToMidnight);

// ─────────────────────────────────────────────
app.listen(PORT, () => console.log(`✅ Backend running on port ${PORT}`));
