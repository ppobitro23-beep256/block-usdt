const express  = require('express');
const cors     = require('cors');
const crypto   = require('crypto');
const https    = require('https');
const { Pool } = require('pg');

// ══════════════════════════════════════════
// RATE LIMITING (no extra library needed)
// ══════════════════════════════════════════
const ipHits = new Map(); // ip -> { count, resetAt }

function rateLimit(maxReq, windowMs) {
  return (req, res, next) => {
    const ip  = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
    const now = Date.now();
    let   rec = ipHits.get(ip);
    if (!rec || now > rec.resetAt) {
      rec = { count: 0, resetAt: now + windowMs };
      ipHits.set(ip, rec);
    }
    rec.count++;
    if (rec.count > maxReq) {
      return res.status(429).json({ error: 'Too many requests, try again later' });
    }
    next();
  };
}

// Clean stale IP records every 5 minutes (memory safety)
setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of ipHits) {
    if (now > rec.resetAt) ipHits.delete(ip);
  }
}, 5 * 60 * 1000);

const globalLimit   = rateLimit(100, 60_000);   // 100/min per IP
const authLimit     = rateLimit(20,  60_000);   // 20/min per IP
const depositLimit  = rateLimit(30,  60_000);   // 30/min

// ══════════════════════════════════════════
// DEPOSIT CONFIG
// ══════════════════════════════════════════
const DEPOSIT_WALLET      = (process.env.DEPOSIT_WALLET || '0x2abdcF2FB8D7088396b69801A3f7294BaF2d8148').toLowerCase();
const USDT_CONTRACT       = (process.env.USDT_CONTRACT  || '0x55d398326f99059fF775485246999027B3197955').toLowerCase();
const BEP20_WALLET        = DEPOSIT_WALLET;
const BEP20_USDT_CONTRACT = USDT_CONTRACT;
const WITHDRAWAL_WALLET   = (process.env.WITHDRAWAL_WALLET || '').toLowerCase();

// Simple HTTPS GET helper
function httpsGet(url, headers) {
  return new Promise((resolve) => {
    const opts = new URL(url);
    const options = {
      hostname: opts.hostname,
      path: opts.pathname + opts.search,
      method: 'GET',
      headers: Object.assign({ 'User-Agent': 'BlockUSDT/1.0' }, headers || {}),
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch(_) { resolve({}); }
      });
    });
    req.on('error', () => resolve({}));
    req.setTimeout(10000, () => { req.destroy(); resolve({}); });
    req.end();
  });
}

const app  = express();
const PORT = process.env.PORT || 3000;
const fs   = require('fs');
const path = require('path');

// ── Simple File Logger ──────────────────────────────
const LOG_FILE = path.join('/tmp', 'blockusdt.log');
function log(tag, msg) {
  const line = `[${new Date().toISOString()}] [${tag}] ${msg}\n`;
  console.log(line.trim());
  try {
    // [LOG ROTATION] Cap at 500KB
    const stats = fs.existsSync(LOG_FILE) ? fs.statSync(LOG_FILE) : null;
    if (stats && stats.size > 500 * 1024) {
      const old = fs.readFileSync(LOG_FILE, 'utf8').split('\n');
      fs.writeFileSync(LOG_FILE, old.slice(-200).join('\n') + '\n');
    }
    fs.appendFileSync(LOG_FILE, line);
  } catch(_) {}
}

// ── Security Event Logger (money flow) ──────────────
function logSecurity(event, data) {
  const payload = typeof data === 'object' ? JSON.stringify(data) : data;
  log('SECURITY', `[${event}] ${payload}`);
}

// ── Fraud Block Helpers ─────────────────────────────
const FRAUD_WINDOW_MS  = 2 * 60 * 60 * 1000; // 2 hours
const FRAUD_MAX        = 15;                   // max failed attempts
const BLOCK_DURATION   = 25 * 60 * 1000;       // 25 min block

async function getFraudState(userId) {
  const row = await db.one(`SELECT fraud_attempts, blocked_until FROM users WHERE id=$1`, [userId]);
  if (!row) return { attempts: [], blockedUntil: null };
  let attempts = [];
  try { attempts = JSON.parse(row.fraud_attempts || '[]'); } catch(_) {}
  // Remove attempts older than window
  const now = Date.now();
  attempts = attempts.filter(t => now - t < FRAUD_WINDOW_MS);
  return { attempts, blockedUntil: row.blocked_until ? new Date(row.blocked_until) : null };
}

async function checkBlocked(userId) {
  const { blockedUntil } = await getFraudState(userId);
  if (blockedUntil && new Date() < blockedUntil) {
    const mins = Math.ceil((blockedUntil - new Date()) / 60000);
    return `Too many failed attempts. Try again in ${mins} minute(s).`;
  }
  return null;
}

async function recordFraud(userId, reason) {
  const { attempts } = await getFraudState(userId);
  attempts.push(Date.now());
  let blockedUntil = null;
  if (attempts.length >= FRAUD_MAX) {
    blockedUntil = new Date(Date.now() + BLOCK_DURATION);
    log('FRAUD', `User ${userId} BLOCKED until ${blockedUntil.toISOString()} — ${reason}`);
  } else {
    log('FRAUD', `User ${userId} attempt ${attempts.length}/${FRAUD_MAX} — ${reason}`);
  }
  await db.run(
    `UPDATE users SET fraud_attempts=$1, blocked_until=$2 WHERE id=$3`,
    [JSON.stringify(attempts), blockedUntil, userId]
  );
  return attempts.length >= FRAUD_MAX;
}

async function clearFraud(userId) {
  await db.run(`UPDATE users SET fraud_attempts='[]', blocked_until=NULL WHERE id=$1`, [userId]);
  log('FRAUD', `User ${userId} fraud state cleared`);
}

const BOT_TOKEN    = process.env.BOT_TOKEN    || '';
const ADMIN_SECRET = process.env.ADMIN_SECRET || '';
const DATABASE_URL = process.env.DATABASE_URL || '';

// Safety check — crash early if critical env vars missing
if (!DATABASE_URL) { console.error('❌ DATABASE_URL env var missing'); process.exit(1); }
if (!ADMIN_SECRET) { console.error('❌ ADMIN_SECRET env var missing'); process.exit(1); }
if (!BOT_TOKEN)    { console.warn('⚠️ BOT_TOKEN env var missing — Telegram auth verification disabled'); }
if (!process.env.WEBAPP_URL) { console.warn('⚠️ WEBAPP_URL not set — using default https://myusdtapp.xyz/'); }

// ══════════════════════════════════════════
// TELEGRAM GROUP PROOF MODULE
// ══════════════════════════════════════════

// Low-level Telegram Bot API caller (server-side only, token never exposed)
async function tgBotApi(method, payload) {
  if (!BOT_TOKEN) return { ok: false, error: 'BOT_TOKEN missing' };
  return new Promise((resolve) => {
    const body = JSON.stringify(payload);
    const options = {
      hostname: 'api.telegram.org',
      path: `/bot${BOT_TOKEN}/${method}`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch(e) { resolve({ ok: false, error: 'parse_error' }); }
      });
    });
    req.on('error', (e) => resolve({ ok: false, error: e.message }));
    req.setTimeout(10000, () => { req.destroy(); resolve({ ok: false, error: 'timeout' }); });
    req.write(body);
    req.end();
  });
}

// Get tg group settings from DB
async function getTgGroupSettings() {
  try {
    const rows = await db.all(`SELECT key, value FROM settings WHERE key IN ('tg_group_chat_id','tg_group_topic_id','tg_group_enabled')`);
    const s = {};
    rows.forEach(r => { s[r.key] = r.value; });
    return {
      chatId:   s.tg_group_chat_id  || '',
      topicId:  s.tg_group_topic_id || '',
      enabled:  s.tg_group_enabled  === '1'
    };
  } catch(e) { return { chatId:'', topicId:'', enabled:false }; }
}

// Send withdrawal proof to Telegram group topic (non-blocking — never fails the main flow)
// Escape HTML special chars to prevent broken parse_mode=HTML messages
function tgEscape(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

async function sendWithdrawProof(txData) {
  try {
    const cfg = await getTgGroupSettings();
    log('TG_PROOF', `cfg: enabled=${cfg.enabled} chatId=${cfg.chatId} topicId=${cfg.topicId} wd=${txData.withdraw_id}`);
    if (!cfg.enabled || !cfg.chatId) {
      log('TG_PROOF', `SKIP: enabled=${cfg.enabled} chatId="${cfg.chatId}"`);
      return;
    }

    const { withdraw_id, username, first_name, user_id, amount, address, bsc_tx_hash } = txData;

    // Duplicate guard — if already sent successfully, skip (unless this call has a tx_hash and previous didn't)
    const existing = await db.all(
      `SELECT sent_status, error_msg FROM tg_proof_logs WHERE withdraw_id=$1 ORDER BY id DESC LIMIT 1`,
      [withdraw_id]
    );
    if (existing.length > 0 && existing[0].sent_status === 'sent') {
      // Already sent successfully — only re-send if now we have a tx_hash that wasn't there before
      if (!bsc_tx_hash || !bsc_tx_hash.trim()) return;
      // Check if previously sent version had no tx_hash (error_msg stores context)
      // We allow one re-send with tx_hash for better proof
      const alreadyHasTx = await db.all(
        `SELECT id FROM tg_proof_logs WHERE withdraw_id=$1 AND sent_status='sent' AND error_msg LIKE '%has_tx%'`,
        [withdraw_id]
      );
      if (alreadyHasTx.length > 0) return; // already sent with tx_hash
    }
    // HTML-escape user-supplied strings to prevent broken Telegram HTML
    const safeName    = username ? '@' + tgEscape(username) : tgEscape(first_name || 'No Username');
    const safeAddr    = address ? address.slice(0,8) + '...' + address.slice(-6) : 'N/A';
    const now         = new Date().toLocaleString('en-GB', { timeZone: 'Asia/Dhaka', hour12: false });

    let msg =
      `💸 <b>Withdrawal Paid</b>\n` +
      `👤 Username: <b>${safeName}</b>\n` +
      `🆔 User ID: <code>${user_id}</code>\n` +
      `💰 Amount: <b>${parseFloat(amount).toFixed(2)} USDT</b>\n` +
      `🌐 Network: BEP20 (BSC)\n` +
      `🏦 Wallet: <code>${safeAddr}</code>\n` +
      `⏰ Time: ${now}`;

    if (bsc_tx_hash && bsc_tx_hash.trim()) {
      msg += `\n🔗 Verify on BscScan:\nhttps://bscscan.com/tx/${bsc_tx_hash.trim()}`;
    }
    msg += `\n\n✅ Successfully Sent`;

    const payload = {
      chat_id:    cfg.chatId,
      text:       msg,
      parse_mode: 'HTML'
    };
    // FIX: parseInt('') = NaN — guard with parsedId check before assigning
    const parsedTopicId = cfg.topicId ? parseInt(cfg.topicId, 10) : NaN;
    if (!isNaN(parsedTopicId) && parsedTopicId > 0) payload.message_thread_id = parsedTopicId;

    const result = await tgBotApi('sendMessage', payload);

    // Log result to DB — use simple INSERT (no ON CONFLICT needed, each proof gets own row)
    const status  = result.ok ? 'sent' : 'failed';
    const errMsg  = result.ok
      ? (bsc_tx_hash && bsc_tx_hash.trim() ? 'has_tx' : null)
      : (result.description || result.error || 'unknown');
    await db.run(
      `INSERT INTO tg_proof_logs (withdraw_id, sent_status, error_msg) VALUES ($1,$2,$3)`,
      [withdraw_id, status, errMsg]
    );
    if (!result.ok) log('TG_PROOF', `Failed to send proof for tx=${withdraw_id}: ${errMsg}`);
  } catch(e) {
    log('TG_PROOF', `sendWithdrawProof error: ${e.message}`);
  }
}

// ── CORS — allow Cloudflare Pages frontend + all Telegram origins ──────
const ALLOWED_ORIGIN = process.env.FRONTEND_URL || 'https://block-usdt.pages.dev';
const TELEGRAM_ORIGINS = [
  'https://web.telegram.org',
  'https://k.web.telegram.org',
  'https://z.web.telegram.org',
  'https://a.web.telegram.org',
];
const corsConfig = {
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (!ALLOWED_ORIGIN) return cb(null, true);
    if (origin === ALLOWED_ORIGIN) return cb(null, true);
    if (TELEGRAM_ORIGINS.indexOf(origin) > -1) return cb(null, true);
    if (origin.endsWith('.telegram.org')) return cb(null, true);
    cb(new Error('CORS not allowed'));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-telegram-init-data', 'x-admin-secret', 'Accept'],
  credentials: false,
};
app.use(cors(corsConfig));
app.options('*', cors(corsConfig));

// ── Security headers ─────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

// ── Global rate limit ─────────────────────────────
app.use(globalLimit);

// ── Request timeout (10s) ─────────────────────────
app.use((req, res, next) => {
  res.setTimeout(10000, () => {
    if (!res.headersSent) res.status(503).json({ error: 'Request timeout' });
  });
  next();
});

// ── Body size limit ───────────────────────────────
app.use(express.json({ limit: '50kb' }));

// ══════════════════════════════════════════
// PostgreSQL CONNECTION
// ══════════════════════════════════════════
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10,                  // max connections
  idleTimeoutMillis: 30000, // close idle after 30s
  connectionTimeoutMillis: 5000, // fail fast if DB unreachable
});
pool.on('error', (err) => {
  console.error('[PG POOL ERROR]', err.message);
});

const db = {
  query: (text, params) => pool.query(text, params),
  one:   async (text, params) => { const r = await pool.query(text, params); return r.rows[0] || null; },
  all:   async (text, params) => { const r = await pool.query(text, params); return r.rows; },
  run:   async (text, params) => { await pool.query(text, params); },
};

// ══════════════════════════════════════════
// DATABASE SETUP
// ══════════════════════════════════════════
async function setupDB() {
  await db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id           BIGINT PRIMARY KEY,
      first_name   TEXT, last_name TEXT, username TEXT, language TEXT,
      is_premium   INTEGER DEFAULT 0,
      balance      REAL DEFAULT 0,
      total_earned REAL DEFAULT 0,
      today_earned REAL DEFAULT 0,
      last_earn_date TEXT DEFAULT '',
      ref_code     TEXT UNIQUE,
      referred_by  BIGINT,
      is_banned    INTEGER DEFAULT 0,
      ban_reason   TEXT,
      created_at   TIMESTAMP DEFAULT NOW()
    )
  `);

  await db.run(`
    CREATE TABLE IF NOT EXISTS plans (
      id          SERIAL PRIMARY KEY,
      name        TEXT, emoji TEXT,
      daily_pct   REAL, min_amt REAL, max_amt REAL,
      duration    INTEGER DEFAULT 50,
      daily_limit INTEGER DEFAULT 0,
      is_active   INTEGER DEFAULT 1,
      created_at  TIMESTAMP DEFAULT NOW()
    )
  `);

  await db.run(`
    CREATE TABLE IF NOT EXISTS investments (
      id           SERIAL PRIMARY KEY,
      user_id      BIGINT, plan_name TEXT,
      amount       REAL, daily_pct REAL, daily_earn REAL,
      days_total   INTEGER DEFAULT 50,
      days_done    INTEGER DEFAULT 0,
      pending_earn REAL DEFAULT 0,
      last_collect TIMESTAMP,
      status       TEXT DEFAULT 'active',
      started_at   TIMESTAMP DEFAULT NOW()
    )
  `);

  await db.run(`
    CREATE TABLE IF NOT EXISTS transactions (
      id         SERIAL PRIMARY KEY,
      user_id    BIGINT, type TEXT, amount REAL,
      status     TEXT DEFAULT 'pending',
      network    TEXT, address TEXT, txid TEXT,
      fee        REAL DEFAULT 0, note TEXT,
      admin_note TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await db.run(`
    CREATE TABLE IF NOT EXISTS tasks (
      id           SERIAL PRIMARY KEY,
      user_id      BIGINT, task_key TEXT,
      completed    INTEGER DEFAULT 0,
      completed_at TIMESTAMP,
      UNIQUE(user_id, task_key)
    )
  `);

  await db.run(`
    CREATE TABLE IF NOT EXISTS story_tasks (
      id           SERIAL PRIMARY KEY,
      user_id      BIGINT NOT NULL,
      claim_date   DATE NOT NULL DEFAULT CURRENT_DATE,
      attempts     INTEGER DEFAULT 0,
      claimed      INTEGER DEFAULT 0,
      last_attempt TIMESTAMP,
      claimed_at   TIMESTAMP,
      UNIQUE(user_id, claim_date)
    )
  `);

  await db.run(`
    CREATE TABLE IF NOT EXISTS settings (
      key   TEXT PRIMARY KEY,
      value TEXT
    )
  `);

  await db.run(`
    CREATE TABLE IF NOT EXISTS auto_deposits (
      id         SERIAL PRIMARY KEY,
      user_id    BIGINT NOT NULL,
      amount     REAL NOT NULL,
      unique_amt REAL NOT NULL,
      network    TEXT NOT NULL,
      status     TEXT DEFAULT 'pending',
      tx_hash    TEXT,
      created_at TIMESTAMP DEFAULT NOW(),
      expires_at TIMESTAMP DEFAULT (NOW() + INTERVAL '30 minutes')
    )
  `);
  await db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_auto_dep_txhash ON auto_deposits (tx_hash) WHERE tx_hash IS NOT NULL`);
  await db.run(`CREATE INDEX IF NOT EXISTS idx_auto_dep_user   ON auto_deposits (user_id)`);
  await db.run(`CREATE INDEX IF NOT EXISTS idx_auto_dep_status ON auto_deposits (status, expires_at)`);
  await db.run(`CREATE INDEX IF NOT EXISTS idx_tx_user_type    ON transactions (user_id, type, status)`);

  // Default settings
  const defaults = {
    withdraw_fee_pct: '0', withdraw_min: '2', withdraw_max: '10000',
    deposit_min: '5',
    trc20_address: 'TVo9famfMAmvN9DnbtQ2fNLh6DwYJ698cZ',
    erc20_address: '0x4878d34e544b79801249d36303b321ca8e634bdd',
    bep20_address: '0x2abdcF2FB8D7088396b69801A3f7294BaF2d8148',
    ref_lvl1_pct: '8', ref_lvl2_pct: '3', ref_lvl3_pct: '1',
    maintenance: '0',
  };
  await Promise.all(Object.entries(defaults).map(([k,v]) =>
    db.run(`INSERT INTO settings (key,value) VALUES ($1,$2) ON CONFLICT (key) DO NOTHING`, [k,v])
  ));

  // Default plans
  const planCount = await db.one(`SELECT COUNT(*) as c FROM plans`);
  if (parseInt(planCount.c) === 0) {
    const defaultPlans = [
      {name:'Bronze Plan', emoji:'🥉', daily_pct:2.5, min_amt:10,  max_amt:20,   duration:50},
      {name:'Silver Plan', emoji:'🥈', daily_pct:2.8, min_amt:20,  max_amt:50,   duration:50},
      {name:'Golden Plan', emoji:'🥇', daily_pct:3.0, min_amt:50,  max_amt:100,  duration:50},
      {name:'Diamond Plan',emoji:'💎', daily_pct:4.0, min_amt:100, max_amt:1000, duration:50},
    ];
    for (const p of defaultPlans) {
      await db.run(
        `INSERT INTO plans (name,emoji,daily_pct,min_amt,max_amt,duration) VALUES ($1,$2,$3,$4,$5,$6)`,
        [p.name,p.emoji,p.daily_pct,p.min_amt,p.max_amt,p.duration]
      );
    }
  }

  // Pending referral table
  await db.run(`
    CREATE TABLE IF NOT EXISTS pending_refs (
      user_id    BIGINT PRIMARY KEY,
      ref_code   TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  // Admin-managed tasks config
  await db.run(`
    CREATE TABLE IF NOT EXISTS tasks_config (
      id         SERIAL PRIMARY KEY,
      task_key   TEXT UNIQUE,
      icon       TEXT DEFAULT '⚡',
      name       TEXT,
      reward     REAL DEFAULT 1,
      is_active  INTEGER DEFAULT 1,
      sort_order INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  // Default tasks if empty
  const taskCount = await db.one('SELECT COUNT(*) as c FROM tasks_config');
  if (parseInt(taskCount.c) === 0) {
    const defaultTasks = [
      {key:'join_channel',   icon:'📢', name:'Join our Telegram Channel',  reward:2,   sort:1},
      {key:'join_group',     icon:'👥', name:'Join our Telegram Group',     reward:2,   sort:2},
      {key:'follow_twitter', icon:'🐦', name:'Follow us on Twitter',         reward:2,   sort:3},
      {key:'first_deposit',  icon:'💰', name:'Make your first deposit',     reward:0,   sort:4},
      {key:'first_invest',   icon:'📊', name:'Purchase any plan',           reward:5,   sort:5},
      {key:'invite_friend',  icon:'🤝', name:'Invite 1 friend',             reward:5,   sort:6},
      {key:'daily_checkin',  icon:'🔄', name:'Daily check-in',              reward:0.5, sort:7},
    ];
    for (const t of defaultTasks) {
      await db.run(
        'INSERT INTO tasks_config (task_key,icon,name,reward,sort_order) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (task_key) DO NOTHING',
        [t.key, t.icon, t.name, t.reward, t.sort]
      );
    }
  }

  // Commission table
  await db.run(`
    CREATE TABLE IF NOT EXISTS commissions (
      id           SERIAL PRIMARY KEY,
      user_id      BIGINT,   -- who earns the commission
      from_user_id BIGINT,   -- who invested
      level        INTEGER,  -- 1, 2, or 3
      amount       REAL,
      status       TEXT DEFAULT 'pending',
      investment_id INTEGER,
      created_at   TIMESTAMP DEFAULT NOW()
    )
  `);

  // Run all migrations in parallel
  await Promise.all([
    db.run(`ALTER TABLE users ADD COLUMN IF NOT EXISTS pending_commission REAL DEFAULT 0`),
    db.run(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_earn_date TEXT DEFAULT ''`),
    db.run(`ALTER TABLE auto_deposits ADD COLUMN IF NOT EXISTS dep_type TEXT DEFAULT 'auto'`),
    db.run(`ALTER TABLE transactions ADD COLUMN IF NOT EXISTS approved_at TIMESTAMP`),
    db.run(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active_ref BOOLEAN DEFAULT FALSE`),
    db.run(`CREATE INDEX IF NOT EXISTS idx_auto_deposits_created ON auto_deposits(created_at)`),
    db.run(`CREATE INDEX IF NOT EXISTS idx_transactions_date ON transactions(created_at)`),
    db.run(`CREATE INDEX IF NOT EXISTS idx_transactions_type ON transactions(type, status)`),
    db.run(`ALTER TABLE users ADD COLUMN IF NOT EXISTS uid TEXT`),
    db.run(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_deposit_blocked INTEGER DEFAULT 0`),
    db.run(`ALTER TABLE auto_deposits ADD COLUMN IF NOT EXISTS fraud_flag INTEGER DEFAULT 0`),
    db.run(`ALTER TABLE users ADD COLUMN IF NOT EXISTS deposit_attempts INTEGER DEFAULT 0`),
    db.run(`ALTER TABLE users ADD COLUMN IF NOT EXISTS fraud_attempts TEXT DEFAULT '[]'`),
    db.run(`ALTER TABLE users ADD COLUMN IF NOT EXISTS blocked_until TIMESTAMP`),
    db.run(`ALTER TABLE users ADD COLUMN IF NOT EXISTS total_commission REAL DEFAULT 0`),
    db.run(`ALTER TABLE plans ADD COLUMN IF NOT EXISTS daily_limit INTEGER DEFAULT 0`),
    db.run(`ALTER TABLE plans ADD COLUMN IF NOT EXISTS today_count INTEGER DEFAULT 0`),
    db.run(`ALTER TABLE plans ADD COLUMN IF NOT EXISTS last_reset TIMESTAMP DEFAULT NOW()`),
    db.run(`ALTER TABLE plans ADD COLUMN IF NOT EXISTS reset_hours REAL DEFAULT 24`),
    db.run(`ALTER TABLE plans ADD COLUMN IF NOT EXISTS buy_count INT DEFAULT 0`),
    db.run(`ALTER TABLE tasks_config ADD COLUMN IF NOT EXISTS link TEXT DEFAULT ''`),
    db.run(`ALTER TABLE tasks_config ADD COLUMN IF NOT EXISTS chat_id TEXT DEFAULT ''`),
    db.run(`ALTER TABLE users ADD COLUMN IF NOT EXISTS app_language VARCHAR(10) DEFAULT ''`),
    db.run(`CREATE INDEX IF NOT EXISTS idx_pending_refs_user ON pending_refs (user_id)`),
    // Broadcast system
    db.run(`CREATE TABLE IF NOT EXISTS broadcasts (
      id           SERIAL PRIMARY KEY,
      title        TEXT NOT NULL,
      message      TEXT NOT NULL,
      emoji        TEXT DEFAULT '📢',
      btn_text     TEXT DEFAULT 'Open App',
      status       TEXT DEFAULT 'pending',
      schedule_at  TIMESTAMP DEFAULT NULL,
      started_at   TIMESTAMP DEFAULT NULL,
      finished_at  TIMESTAMP DEFAULT NULL,
      total        INT DEFAULT 0,
      sent         INT DEFAULT 0,
      failed       INT DEFAULT 0,
      created_at   TIMESTAMP DEFAULT NOW()
    )`),
    // Notice/Broadcast system
    db.run(`CREATE TABLE IF NOT EXISTS notices (
      id           SERIAL PRIMARY KEY,
      title        TEXT NOT NULL,
      message      TEXT NOT NULL,
      emoji        TEXT DEFAULT '📢',
      btn_text     TEXT DEFAULT '',
      btn_link     TEXT DEFAULT '',
      is_active    BOOLEAN DEFAULT FALSE,
      repeat_mode  TEXT DEFAULT 'once',
      schedule_at  TIMESTAMP DEFAULT NULL,
      expire_at    TIMESTAMP DEFAULT NULL,
      poster_image TEXT DEFAULT NULL,
      created_at   TIMESTAMP DEFAULT NOW(),
      updated_at   TIMESTAMP DEFAULT NOW()
    )`),
    db.run(`ALTER TABLE notices ADD COLUMN IF NOT EXISTS poster_image TEXT DEFAULT NULL`),
    db.run(`CREATE TABLE IF NOT EXISTS notice_stats (
      id          SERIAL PRIMARY KEY,
      notice_id   INT NOT NULL,
      user_id     BIGINT NOT NULL,
      action      TEXT NOT NULL,
      created_at  TIMESTAMP DEFAULT NOW(),
      UNIQUE(notice_id, user_id, action)
    )`),
    // Wallet address bind system
    db.run(`ALTER TABLE users ADD COLUMN IF NOT EXISTS withdraw_address TEXT DEFAULT NULL`),
    db.run(`ALTER TABLE users ADD COLUMN IF NOT EXISTS address_locked BOOLEAN DEFAULT FALSE`),
    db.run(`ALTER TABLE users ADD COLUMN IF NOT EXISTS address_updated_at TIMESTAMP DEFAULT NULL`),
    // Unique index: one address per account (NULL allowed for unbound users)
    db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_withdraw_address ON users (withdraw_address) WHERE withdraw_address IS NOT NULL`),
    // VIP system migrations
    db.run(`ALTER TABLE users ADD COLUMN IF NOT EXISTS vip_level TEXT DEFAULT 'Member'`),
    db.run(`ALTER TABLE users ADD COLUMN IF NOT EXISTS vip_updated_at TIMESTAMP DEFAULT NULL`),
    db.run(`CREATE INDEX IF NOT EXISTS idx_investments_user_status ON investments (user_id, status)`),
    db.run(`CREATE INDEX IF NOT EXISTS idx_users_referred_by ON users (referred_by)`),
    // ── Special Override System ──────────────────────────────────────────────
    db.run(`ALTER TABLE users ADD COLUMN IF NOT EXISTS manual_commission_enabled BOOLEAN DEFAULT FALSE`),
    db.run(`ALTER TABLE users ADD COLUMN IF NOT EXISTS manual_plan_tier TEXT DEFAULT NULL`),
    db.run(`ALTER TABLE users ADD COLUMN IF NOT EXISTS manual_vip_level TEXT DEFAULT NULL`),
    db.run(`ALTER TABLE users ADD COLUMN IF NOT EXISTS manual_override_expiry TIMESTAMP DEFAULT NULL`),
    db.run(`ALTER TABLE users ADD COLUMN IF NOT EXISTS manual_badge_label TEXT DEFAULT NULL`),
    db.run(`CREATE TABLE IF NOT EXISTS override_logs (
      id           SERIAL PRIMARY KEY,
      admin_action TEXT NOT NULL,
      target_user  BIGINT NOT NULL,
      field        TEXT,
      old_value    TEXT,
      new_value    TEXT,
      note         TEXT,
      created_at   TIMESTAMP DEFAULT NOW()
    )`),
  ]);

  // Audit log table for address changes
  await db.run(`
    CREATE TABLE IF NOT EXISTS address_change_logs (
      id           SERIAL PRIMARY KEY,
      admin_id     TEXT,
      user_id      BIGINT NOT NULL,
      old_address  TEXT,
      new_address  TEXT,
      action       TEXT DEFAULT 'change',
      created_at   TIMESTAMP DEFAULT NOW()
    )
  `);

  // Telegram Group proof log table
  await db.run(`
    CREATE TABLE IF NOT EXISTS tg_proof_logs (
      id          SERIAL PRIMARY KEY,
      withdraw_id INTEGER NOT NULL,
      sent_status TEXT    DEFAULT 'pending',
      error_msg   TEXT    DEFAULT NULL,
      retry_count INTEGER DEFAULT 0,
      created_at  TIMESTAMP DEFAULT NOW(),
      updated_at  TIMESTAMP DEFAULT NOW()
    )
  `);
  await db.run(`ALTER TABLE transactions ADD COLUMN IF NOT EXISTS bsc_tx_hash TEXT DEFAULT NULL`);

  // Mark all pre-existing approved withdrawals as 'skipped' in proof logs
  // so fallback scanner never re-posts old withdrawals after deploy
  await db.run(`
    INSERT INTO tg_proof_logs (withdraw_id, sent_status, error_msg)
    SELECT t.id, 'skipped', 'pre-existing before TG proof feature'
    FROM transactions t
    WHERE t.type = 'withdraw'
      AND t.status = 'approved'
      AND NOT EXISTS (SELECT 1 FROM tg_proof_logs pl WHERE pl.withdraw_id = t.id)
  `);

  console.log('✅ Database ready (Neon PostgreSQL)');
}

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  console.error('[unhandledRejection]', err?.message || err);
});
process.on('uncaughtException', (err) => {
  console.error('[uncaughtException]', err?.message || err);
  // Don't exit — log and keep running (Render will restart on crash anyway)
});

async function getSetting(key) {
  const r = await db.one(`SELECT value FROM settings WHERE key=$1`, [key]);
  return r ? r.value : null;
}


// ── Rank + UID helpers ────────────────────

// Plan tier order (lowest → highest)
const PLAN_TIER_ORDER = ['bronze','silver','gold','platinum','diamond','titanium','quantum'];

function getPlanTier(planName) {
  const n = (planName || '').toLowerCase();
  for (const tier of [...PLAN_TIER_ORDER].reverse()) {
    if (n.includes(tier)) return tier;
  }
  return 'bronze';
}

function planTierIndex(planName) {
  return PLAN_TIER_ORDER.indexOf(getPlanTier(planName));
}

// VIP REQUIREMENTS
const VIP_LEVELS = [
  // Member (base — no VIP)
  { name: 'Member',          minPlanTier: null,       minRefs: 0,  minTeamDep: 0,    maxLevels: 3,
    rates: [3, 2, 1, 0, 0, 0, 0] }, // fallback = Bronze rates
  // Bronze plan active
  { name: 'Bronze',          minPlanTier: 'bronze',   minRefs: 0,  minTeamDep: 0,    maxLevels: 3,
    rates: [3, 2, 1, 0, 0, 0, 0] },
  // Silver plan active
  { name: 'Silver',          minPlanTier: 'silver',   minRefs: 0,  minTeamDep: 0,    maxLevels: 3,
    rates: [4, 2, 1, 0, 0, 0, 0] },
  // Gold plan active
  { name: 'Gold',            minPlanTier: 'gold',     minRefs: 0,  minTeamDep: 0,    maxLevels: 3,
    rates: [5, 3, 1, 0, 0, 0, 0] },
  // VIP 1 — Platinum
  { name: 'VIP 1',           minPlanTier: 'platinum', minRefs: 2,  minTeamDep: 100,  maxLevels: 4,
    rates: [8, 3, 1, 1, 0, 0, 0] },
  // VIP 2 — Diamond
  { name: 'VIP 2',           minPlanTier: 'diamond',  minRefs: 5,  minTeamDep: 500,  maxLevels: 5,
    rates: [8, 3, 1, 1, 1, 0, 0] },
  // VIP 3 — Titanium
  { name: 'VIP 3',           minPlanTier: 'titanium', minRefs: 10, minTeamDep: 1000, maxLevels: 6,
    rates: [8, 3, 1, 1, 1, 1, 0] },
  // VIP 4 — Quantum
  { name: 'VIP 4',           minPlanTier: 'quantum',  minRefs: 20, minTeamDep: 2000, maxLevels: 7,
    rates: [8, 3, 1, 1, 1, 1, 1] },
];

// Compute user's VIP level given their stats
function computeVipLevel(highestPlanTier, activeRefs, teamDeposit) {
  const tierIdx = highestPlanTier ? PLAN_TIER_ORDER.indexOf(highestPlanTier) : -1;
  let bestLevel = VIP_LEVELS[0]; // Member default

  for (const vip of VIP_LEVELS) {
    if (!vip.minPlanTier) continue; // skip Member entry
    const reqTierIdx = PLAN_TIER_ORDER.indexOf(vip.minPlanTier);
    if (tierIdx < reqTierIdx) continue;
    if (activeRefs < vip.minRefs) continue;
    if (teamDeposit < vip.minTeamDep) continue;
    bestLevel = vip;
  }
  return bestLevel;
}

// Get highest active plan tier for a user (server-side)
async function getHighestActivePlanTier(userId) {
  const rows = await db.all(
    `SELECT plan_name FROM investments WHERE user_id=$1 AND status='active'`,
    [userId]
  );
  if (!rows || !rows.length) return null;
  let best = -1;
  for (const r of rows) {
    const idx = planTierIndex(r.plan_name);
    if (idx > best) best = idx;
  }
  return best >= 0 ? PLAN_TIER_ORDER[best] : null;
}

// Get team deposit total for N levels deep
async function getTeamDeposit(userId, maxLevels) {
  // BFS across referral tree up to maxLevels
  // Always use numeric bigint-safe id
  let currentIds = [parseInt(userId)];
  let allDownlineIds = [];
  for (let lvl = 0; lvl < maxLevels; lvl++) {
    if (!currentIds.length) break;
    const rows = await db.all(
      `SELECT id FROM users WHERE referred_by = ANY($1::bigint[])`,
      [currentIds]
    );
    const nextIds = rows.map(r => r.id);
    allDownlineIds = allDownlineIds.concat(nextIds);
    currentIds = nextIds;
  }
  if (!allDownlineIds.length) return 0;
  const r = await db.one(
    `SELECT COALESCE(SUM(i.amount), 0) as total
     FROM investments i
     WHERE i.user_id = ANY($1::bigint[]) AND i.status IN ('active','completed')`,
    [allDownlineIds]
  );
  return parseFloat(r.total) || 0;
}

// Get active referral count (direct L1 only for VIP gate)
async function getActiveReferralCount(userId) {
  const r = await db.one(
    `SELECT COUNT(DISTINCT u.id) as cnt
     FROM users u
     JOIN investments i ON u.id = i.user_id
     WHERE u.referred_by = $1 AND i.status = 'active'`,
    [userId]
  );
  return parseInt(r.cnt) || 0;
}

// Full VIP status for a user — used in /api/vip-status and commission calc
// Strategy: first compute candidate VIP from plan+refs only (no team dep),
// then scan teamDep using that candidate's maxLevels for consistency.
// reqMaxLevels: hard cap for commission calc to limit DB queries.
async function getUserVipStatus(userId, reqMaxLevels) {
  // ── Check manual override FIRST ──────────────────────────────────────
  const overrideRow = await db.one(
    `SELECT manual_commission_enabled, manual_plan_tier, manual_vip_level,
            manual_override_expiry, manual_badge_label
     FROM users WHERE id=$1`, [userId]
  );

  // Check if override is still valid (not expired)
  const overrideActive = overrideRow && (
    !overrideRow.manual_override_expiry ||
    new Date() < new Date(overrideRow.manual_override_expiry)
  );

  if (overrideActive && overrideRow.manual_vip_level && overrideRow.manual_vip_level !== 'none') {
    // Find the VIP level definition matching the manual assignment
    const overrideVip = VIP_LEVELS.find(v => v.name === overrideRow.manual_vip_level);
    if (overrideVip) {
      // Also apply manual plan tier override for commission rates
      let effectiveVip = { ...overrideVip };
      if (overrideRow.manual_plan_tier && overrideRow.manual_plan_tier !== 'none') {
        // Find plan-tier-based rates from VIP_LEVELS equivalent tier
        const planVip = VIP_LEVELS.find(v => v.minPlanTier === overrideRow.manual_plan_tier);
        if (planVip && planTierIndex(planVip.minPlanTier) > planTierIndex(overrideVip.minPlanTier || 'bronze')) {
          // If manual plan tier gives higher rates, use those rates but keep VIP levels
          effectiveVip = { ...overrideVip, rates: planVip.rates };
        }
      }
      const teamDep = await getTeamDeposit(userId, effectiveVip.maxLevels).catch(() => 0);
      return {
        vip: effectiveVip,
        highestTier: overrideRow.manual_plan_tier || null,
        activeRefs: 0,
        teamDep,
        isManualOverride: true,
        badgeLabel: overrideRow.manual_badge_label || null,
      };
    }
  }

  // If manual_commission_enabled but no VIP override — use manual_plan_tier for rates
  if (overrideActive && overrideRow.manual_commission_enabled && overrideRow.manual_plan_tier && overrideRow.manual_plan_tier !== 'none') {
    const planVip = VIP_LEVELS.find(v => v.minPlanTier === overrideRow.manual_plan_tier);
    if (planVip) {
      const teamDep = await getTeamDeposit(userId, planVip.maxLevels).catch(() => 0);
      return {
        vip: planVip,
        highestTier: overrideRow.manual_plan_tier,
        activeRefs: 0,
        teamDep,
        isManualOverride: true,
        badgeLabel: overrideRow.manual_badge_label || null,
      };
    }
  }

  // ── Normal automatic VIP calculation ────────────────────────────────
  const [highestTier, activeRefs] = await Promise.all([
    getHighestActivePlanTier(userId),
    getActiveReferralCount(userId),
  ]);

  // Step 1: find highest VIP tier user COULD reach based on plan+refs only
  const tierIdx = highestTier ? PLAN_TIER_ORDER.indexOf(highestTier) : -1;

  // If manual_commission_enabled (no plan), treat as having a plan for commission purposes
  let effectiveTierIdx = tierIdx;
  if (overrideActive && overrideRow.manual_commission_enabled && tierIdx < 0) {
    effectiveTierIdx = 0; // treat as bronze for commission eligibility
  }

  let candidateMaxLevels = 3;
  for (const v of VIP_LEVELS) {
    if (!v.minPlanTier) continue;
    const reqTierIdx = PLAN_TIER_ORDER.indexOf(v.minPlanTier);
    if (effectiveTierIdx < reqTierIdx) continue;
    if (activeRefs < v.minRefs) continue;
    candidateMaxLevels = v.maxLevels;
  }

  const scanDepth = reqMaxLevels
    ? Math.min(reqMaxLevels, candidateMaxLevels)
    : candidateMaxLevels;

  const teamDep = await getTeamDeposit(userId, scanDepth);
  const vip = computeVipLevel(highestTier, activeRefs, teamDep);
  return { vip, highestTier, activeRefs, teamDep, isManualOverride: false };
}

// Legacy rank name (kept for leaderboard badge compatibility)
function getUserRank(activeRefs) {
  const n = parseInt(activeRefs) || 0;
  if (n >= 20) return 'VIP 4';
  if (n >= 10) return 'VIP 3';
  if (n >= 5)  return 'VIP 2';
  if (n >= 1)  return 'VIP 1';
  return 'Member';
}
function maskName(name) {
  if (!name || name.length === 0) return 'User****';
  if (name.length <= 2) return name + '****';
  return name.substring(0, 2) + '****';
}
function generateUID() {
  return 'U' + Math.floor(100000 + Math.random() * 900000);
}

// ── Plan unlock: active referral requirements ──
function getPlanReferralReq(planName) {
  // Must match VIP_LEVELS requirements exactly
  const n = (planName || '').toLowerCase();
  if (n.includes('quantum'))  return 20;
  if (n.includes('titanium')) return 10;
  if (n.includes('diamond'))  return 5;
  if (n.includes('platinum')) return 2;
  return 0; // bronze, silver, gold — always open
}

// ── Input validators ─────────────────────────────
function isValidAmount(v, max = 100000) {
  const n = parseFloat(v);
  return !isNaN(n) && n > 0 && n <= max && isFinite(n);
}
function isValidTxHash(h) {
  return typeof h === 'string' && /^0x[a-fA-F0-9]{64}$/.test(h.trim());
}
function isValidBEP20Address(a) {
  return typeof a === 'string' && /^0x[a-fA-F0-9]{40}$/.test(a.trim());
}

// ══════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════
function verifyTg(initData, logContext) {
  try {
    const p = new URLSearchParams(initData);
    const hash = p.get('hash');
    if (!hash) {
      if (logContext) log('AUTH', `[${logContext}] No hash in initData`);
      return false;
    }
    p.delete('hash');

    // Check auth_date expiry (24 hours)
    // Telegram initData stays same for entire session — 5min is too short
    const authDate = parseInt(p.get('auth_date') || '0');
    const now      = Math.floor(Date.now() / 1000);
    const age      = now - authDate;
    if (authDate && age > 86400) {
      if (logContext) log('AUTH', `[${logContext}] initData expired: age=${age}s (>24h)`);
      return false;
    }

    const arr = []; p.forEach((v,k) => arr.push(`${k}=${v}`)); arr.sort();
    const secret = crypto.createHmac('sha256','WebAppData').update(BOT_TOKEN).digest();
    const computed = crypto.createHmac('sha256',secret).update(arr.join('\n')).digest('hex');
    const valid = computed === hash;
    if (!valid && logContext) log('AUTH', `[${logContext}] Hash mismatch`);
    return valid;
  } catch(e) {
    if (logContext) log('AUTH', `[${logContext}] verifyTg exception: ${e.message}`);
    return false;
  }
}

function userAuth(req, res, next) {
  const initData = req.headers['x-telegram-init-data'] || req.body?.initData;
  if (!initData) {
    if (process.env.NODE_ENV === 'development') {
      req.tgUser = { id: req.body.user_id || 123456 };
      return next();
    }
    return res.status(401).json({ error: 'Auth required' });
  }

  // Verify Telegram initData signature
  if (BOT_TOKEN && process.env.NODE_ENV !== 'development') {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
    if (!verifyTg(initData, `${req.method} ${req.path} ip=${ip}`)) {
      return res.status(401).json({ error: 'Invalid session' });
    }
  }

  try {
    const p = new URLSearchParams(initData);
    const userStr = p.get('user');
    req.tgUser = userStr ? JSON.parse(userStr) : null;
    if (!req.tgUser || !req.tgUser.id) {
      log('AUTH', `No user in initData path=${req.path}`);
      return res.status(401).json({ error: 'Invalid session' });
    }
    // Auth OK — no log here to avoid noise (failures are logged above)
  } catch(e) {
    log('AUTH', `Parse error path=${req.path}: ${e.message}`);
    return res.status(401).json({ error: 'Invalid session' });
  }
  return next();
}

function adminAuth(req, res, next) {
  const secret = req.headers['x-admin-secret'] || req.body?.adminSecret || '';
  // Timing-safe compare prevents timing attacks on admin secret
  try {
    const a = Buffer.from(secret.padEnd(64));
    const b = Buffer.from(ADMIN_SECRET.padEnd(64));
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return res.status(403).json({error:'Unauthorized'});
    }
  } catch { return res.status(403).json({error:'Unauthorized'}); }
  next();
}

// ══════════════════════════════════════════
// USER ROUTES
// ══════════════════════════════════════════
app.post('/api/auth', authLimit, async (req, res) => {
  try {
    // ✅ SECURITY FIX: Verify initData on auth too
    const raw = req.headers['x-telegram-init-data'] || req.body?.initData || '';
    if (BOT_TOKEN && raw && raw.length > 10 && process.env.NODE_ENV !== 'development') {
      const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
      if (!verifyTg(raw, `POST /api/auth ip=${ip}`)) {
        return res.status(401).json({error: 'Invalid session'});
      }
    }
    let u = null;
    if (raw && raw.length > 10) {
      try {
        const p = new URLSearchParams(raw);
        const us = p.get('user');
        if (us) u = JSON.parse(us);
      } catch(e) {}
    }
    // Fallback: accept tgUser from body only if initData was already verified above
    // OR if initData is present in body (frontend sends both)
    if (!u || !u.id) {
      const bodyInitData = req.body?.initData || '';
      if (bodyInitData && bodyInitData.length > 10) {
        try {
          const bp = new URLSearchParams(bodyInitData);
          const bus = bp.get('user');
          if (bus) u = JSON.parse(bus);
        } catch(e) {}
      }
      // Last resort: tgUser from body (only safe because initData is also sent)
      if (!u || !u.id) u = req.body?.tgUser || null;
    }
    if (!u || !u.id) return res.status(400).json({error:'No user data'});

    const uid      = u.id;
    const refCode  = 'REF' + uid;
    const ref      = req.body?.ref || null;
    const refById  = ref && String(ref).startsWith('REF') ? parseInt(String(ref).replace('REF','')) || null : null;
    const finalRef = (refById && refById !== uid) ? refById : null;

    if (finalRef) log('REF', `Auth uid=${uid} ref=${ref} finalRef=${finalRef}`);

    // Check pending ref
    let pendingRef = finalRef;
    if (!pendingRef) {
      const pr = await db.one('SELECT ref_code FROM pending_refs WHERE user_id=$1', [uid]);
      if (pr) {
        const prid = parseInt(String(pr.ref_code).replace('REF',''));
        if (prid && prid !== uid) pendingRef = prid;
        log('REF', `Pending ref found for uid=${uid} referrer=${prid}`);
      }
    }

    // Upsert user
    await db.run(`
      INSERT INTO users (id,first_name,last_name,username,language,is_premium,ref_code,referred_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      ON CONFLICT (id) DO UPDATE SET
        first_name=CASE WHEN EXCLUDED.first_name != '' THEN EXCLUDED.first_name ELSE users.first_name END,
        last_name=CASE WHEN EXCLUDED.last_name != '' THEN EXCLUDED.last_name ELSE users.last_name END,
        username=CASE WHEN EXCLUDED.username != '' THEN EXCLUDED.username ELSE users.username END,
        language=EXCLUDED.language,
        is_premium=EXCLUDED.is_premium,
        referred_by=CASE WHEN users.referred_by IS NULL AND $8::BIGINT IS NOT NULL THEN $8::BIGINT ELSE users.referred_by END
    `, [uid, u.first_name||'', u.last_name||'', u.username||'', u.language_code||'', u.is_premium?1:0, refCode, pendingRef]);

    // Log referral save result
    if (pendingRef) {
      log('REF', `referred_by saved: uid=${uid} referrer=${pendingRef}`);
    }

    // Clean pending ref
    await db.run('DELETE FROM pending_refs WHERE user_id=$1', [uid]).catch(()=>{});

    let user = await db.one('SELECT * FROM users WHERE id=$1', [uid]);
    // Assign UID if missing
    if (user && !user.uid) {
      const newUID = generateUID();
      await db.run('UPDATE users SET uid=$1 WHERE id=$2', [newUID, uid]);
      user.uid = newUID;
    }
    if (user && user.is_banned) return res.status(403).json({error:'banned', reason: user.ban_reason||''});

    res.json({success: true});
  } catch(e) {
    log('ERROR', 'Auth error: ' + e.message);
    res.status(500).json({error: 'Server error. Please try again.'});
  }
});

app.get('/api/user/:id', async (req, res) => {
  // IDOR guard: if initData header is present, verify it and ensure user matches
  // Frontend intentionally omits header on this GET to avoid CORS preflight (Telegram WebView quirk)
  // Security: user_id in URL is only useful if attacker knows the ID, and response
  // contains no sensitive financial actions — just read-only data display
  const _initData = req.headers['x-telegram-init-data'];
  if (_initData) {
    // Verify signature if BOT_TOKEN set
    if (BOT_TOKEN && process.env.NODE_ENV !== 'development' && !verifyTg(_initData)) {
      log('SECURITY', `Invalid initData on /api/user from IP: ${req.headers['x-forwarded-for'] || req.ip}`);
      return res.status(401).json({ error: 'Invalid session' });
    }
    try {
      const _p = new URLSearchParams(_initData);
      const _userStr = _p.get('user');
      const _tgU = _userStr ? JSON.parse(_userStr) : null;
      if (!_tgU || String(_tgU.id) !== String(req.params.id)) {
        return res.status(403).json({ error: 'Forbidden' });
      }
    } catch(e) { return res.status(401).json({ error: 'Invalid session' }); }
  }
  // Note: no-header requests allowed for Telegram WebView CORS compatibility
  // All money actions (withdraw, invest, collect) still require full auth via userAuth middleware
  try {
    let user = await db.one(`SELECT * FROM users WHERE id=$1`, [req.params.id]);
    // Auto-create user if not exists — only when called with valid initData (not ghost creation)
    if (!user) {
      const hasAuth = !!req.headers['x-telegram-init-data'];
      if (!hasAuth) return res.status(404).json({error:'Not found'});
      const uid = String(parseInt(req.params.id)); // sanitize to integer string
      if (!uid || uid === 'NaN') return res.status(400).json({error:'Invalid user id'});
      const refCode = 'REF' + uid;
      await db.run(`
        INSERT INTO users (id,first_name,ref_code) VALUES ($1,$2,$3)
        ON CONFLICT (id) DO NOTHING
      `, [uid, 'User'+uid, refCode]).catch(()=>{});
      user = await db.one(`SELECT * FROM users WHERE id=$1`, [uid]);
      if (!user) return res.status(404).json({error:'Not found'});
    }

    // Run all queries in parallel for speed
    const [investments, transactions, taskRows, referrals, plans, settingRows, activeRefRow] = await Promise.all([
      db.all(`SELECT *, EXTRACT(EPOCH FROM (NOW() - last_collect)) as secs_since_collect FROM investments WHERE user_id=$1 AND status='active'`, [req.params.id]),
      db.all(`SELECT * FROM transactions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 20`, [req.params.id]),
      db.all(`SELECT task_key FROM tasks WHERE user_id=$1 AND completed=1`, [req.params.id]),
      db.all(`SELECT u.id, u.first_name, u.username, u.created_at,
        COALESCE((SELECT SUM(c.amount) FROM commissions c WHERE c.user_id=$1 AND c.from_user_id=u.id AND c.status='collected'), 0) as earned
        FROM users u WHERE u.referred_by=$1 ORDER BY u.created_at DESC`, [req.params.id]),
      db.all(`SELECT * FROM plans WHERE is_active=1 ORDER BY id`),
      db.all(`SELECT * FROM settings`),
      db.one(`SELECT COUNT(DISTINCT u.id) as cnt FROM users u JOIN investments i ON u.id=i.user_id WHERE u.referred_by=$1 AND i.status='active'`, [req.params.id]),
    ]);
    const tasks    = taskRows.map(t => t.task_key);
    const settings = settingRows.reduce((a,r) => ({...a,[r.key]:r.value}), {});
    const activeReferrals = parseInt(activeRefRow.cnt) || 0;

    // Reset today_count display if past reset_hours
    const nowTime = new Date();
    plans.forEach(function(p) {
      if (p.daily_limit > 0 && p.last_reset) {
        const hoursPassed = (nowTime - new Date(p.last_reset)) / (1000*60*60);
        if (hoursPassed >= (p.reset_hours || 24)) p.today_count = 0;
      }
    });

    // Auto-reset today_earned if it's a new UTC day
    const todayUTC = new Date().toISOString().slice(0, 10); // 'YYYY-MM-DD'
    if (user.last_earn_date !== todayUTC && parseFloat(user.today_earned || 0) > 0) {
      await db.run(`UPDATE users SET today_earned=0, last_earn_date=$1 WHERE id=$2`, [todayUTC, user.id]);
      user.today_earned = 0;
      user.last_earn_date = todayUTC;
      console.log(`[RESET] today_earned auto-reset for user ${user.id}`);
    }

    // Add commission data to user
    const userWithComm = {
      ...user,
      pending_commission:  parseFloat(user.pending_commission || 0),
      total_commission:    parseFloat(user.total_commission   || 0),
      is_deposit_blocked:  user.blocked_until && new Date() < new Date(user.blocked_until) ? 1 : 0,
      withdraw_address:    user.withdraw_address || null,
      address_locked:      !!user.address_locked,
      address_updated_at:  user.address_updated_at || null,
    };
    userWithComm.rank   = getUserRank(activeReferrals);
    userWithComm.active_referrals = activeReferrals;

    // Compute VIP status (lightweight — uses cached highest plan query)
    let vipData = null;
    try {
      const vs = await getUserVipStatus(req.params.id);
      vipData = {
        vip_name:     vs.vip.name,
        vip_rates:    vs.vip.rates,
        max_levels:   vs.vip.maxLevels,
        highest_tier: vs.highestTier || null,
        team_deposit: +vs.teamDep.toFixed(2),
      };
      // Cache vip_level on user row (async, non-blocking)
      db.run(`UPDATE users SET vip_level=$1, vip_updated_at=NOW() WHERE id=$2`, [vs.vip.name, req.params.id]).catch(()=>{});
    } catch(e) { log('WARN', 'VIP calc skipped: ' + e.message); }

    res.json({user: userWithComm, investments, transactions, tasks, referrals, plans, settings, active_referrals: activeReferrals, vip: vipData});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

// ── Save user language preference ──────────────────────────
app.post('/api/user/language', userAuth, async (req, res) => {
  try {
    const u = req.tgUser;
    const { language } = req.body;
    if (!language) return res.status(400).json({ error: 'Missing language' });
    const SUPPORTED = ['en','ru','es','pt','vi','ar','fa'];
    if (!SUPPORTED.includes(language)) return res.status(400).json({ error: 'Unsupported language' });
    await db.run(`UPDATE users SET app_language=$1 WHERE id=$2`, [language, u.id]);
    res.json({ ok: true });
  } catch(e) { log("ERROR", e.message); res.status(500).json({ error: "Server error. Please try again." }); }
});

app.post('/api/invest', userAuth, async (req, res) => {
  try {
    const u = req.tgUser;
    const {plan_id} = req.body;
    const amount = parseFloat(req.body.amount);
    if (!isValidAmount(amount)) return res.status(400).json({error:'Invalid amount'});
    const user = await db.one(`SELECT * FROM users WHERE id=$1`, [u.id]);
    if (!user) return res.status(404).json({error:'Not found'});
    if (user.is_banned) return res.status(403).json({error:'banned'});

    const plan = await db.one(`SELECT * FROM plans WHERE id=$1 AND is_active=1`, [plan_id]);
    if (!plan) return res.status(404).json({error:'Plan not found'});
    if (amount < plan.min_amt) return res.status(400).json({error:`Min $${plan.min_amt}`});
    if (amount > plan.max_amt) return res.status(400).json({error:`Max $${plan.max_amt}`});
    if (user.balance < amount) return res.status(400).json({error:'Insufficient balance'});
    // Prevent duplicate active investment in same plan
    const dupInv = await db.one(
      `SELECT id FROM investments WHERE user_id=$1 AND plan_name=$2 AND status='active'`,
      [u.id, ((plan.emoji||'')+' '+plan.name).trim()]
    );
    if (dupInv) return res.status(400).json({error:'You already have an active investment in this plan'});

    // [PLAN UNLOCK] Check active referral requirement (backend safety — cannot bypass)
    const refReq = getPlanReferralReq(plan.name);
    if (refReq > 0) {
      const activeRefs = await db.one(
        `SELECT COUNT(DISTINCT u.id) as cnt FROM users u JOIN investments i ON u.id=i.user_id WHERE u.referred_by=$1 AND i.status='active'`,
        [u.id]
      );
      const activeCount = parseInt(activeRefs?.cnt || 0);
      if (activeCount < refReq) {
        return res.status(403).json({
          error: `This plan requires ${refReq} active referral${refReq>1?'s':''} (you have ${activeCount})`
        });
      }
    }

    // Check daily limit
    if (plan.daily_limit > 0) {
      const resetHours = parseFloat(plan.reset_hours || 24);
      const lastReset  = plan.last_reset ? new Date(plan.last_reset) : null;
      const now        = new Date();
      const hoursPassed = lastReset ? (now - lastReset) / (1000 * 60 * 60) : resetHours + 1;

      if (hoursPassed >= resetHours) {
        await db.run(`UPDATE plans SET today_count=0, last_reset=NOW() WHERE id=$1`, [plan_id]);
        plan.today_count = 0;
      }
      const remaining = plan.daily_limit - (plan.today_count || 0);
      if (remaining <= 0) {
        const nextReset = lastReset ? new Date(lastReset.getTime() + resetHours * 60 * 60 * 1000) : null;
        const hoursLeft = nextReset ? Math.ceil((nextReset - now) / (1000 * 60 * 60)) : resetHours;
        return res.status(400).json({error:`Limit reached! Resets in ${hoursLeft}h.`, limitReached: true, hoursLeft});
      }
    }

    const daily = +(amount * plan.daily_pct / 100).toFixed(4);
    // [DB-LEVEL GUARD] Conditional deduct — prevents negative balance under race condition
    const deductResult = await pool.query(
      `UPDATE users SET balance=balance-$1 WHERE id=$2 AND balance>=$1 RETURNING id`,
      [amount, u.id]
    );
    if (deductResult.rowCount === 0) return res.status(400).json({error:'Insufficient balance'});
    await db.run(
      `INSERT INTO investments (user_id,plan_name,amount,daily_pct,daily_earn,days_total) VALUES ($1,$2,$3,$4,$5,$6)`,
      [u.id, ((plan.emoji||'')+' '+plan.name).trim(), amount, plan.daily_pct, daily, plan.duration]
    );
    // Increment daily count
    if (plan.daily_limit > 0) {
      await db.run(`UPDATE plans SET today_count=today_count+1 WHERE id=$1`, [plan_id]);
    }
    await db.run(
      `INSERT INTO transactions (user_id,type,amount,status,note) VALUES ($1,$2,$3,$4,$5)`,
      [u.id,'invest',amount,'completed',`Invested in ${plan.name}`]
    );
    // Increment total buy count
    await db.run(`UPDATE plans SET buy_count = buy_count + 1 WHERE id = $1`, [plan_id]);

    // [ACTIVE REF] Mark user as active referral on first investment
    if (!user.is_active_ref && user.referred_by && user.id !== user.referred_by) {
      await db.run(`UPDATE users SET is_active_ref=TRUE WHERE id=$1`, [user.id]);
      log('REF', `User ${user.id} marked as active referral of ${user.referred_by}`);
    }

    // Distribute referral commissions — VIP-based dynamic rates
    try {
      let currentId = u.id;
      const vipCache = new Map(); // per-invest cache: referrerId → vip object
      for (let lvl = 0; lvl < 7; lvl++) {
        const row = await db.one(`SELECT referred_by, is_banned FROM users WHERE id=$1`, [currentId]);
        if (!row || !row.referred_by) break;
        const referrerId = row.referred_by;

        // Referrer must not be banned (already fetched above)
        if (row.is_banned) { currentId = referrerId; continue; }

        // Compute referrer VIP — use cache to avoid repeat DB calls
        let refVip;
        if (vipCache.has(referrerId)) {
          refVip = vipCache.get(referrerId);
        } else {
          // Use scanDepth = 4 max for commission calc (VIP 4 needs L7 but teamDep is pre-qualified)
          const refVipData = await getUserVipStatus(referrerId, 4);
          refVip = refVipData.vip;
          vipCache.set(referrerId, refVip);
        }

        // Stop if this level is beyond referrer's unlocked levels
        if (lvl >= refVip.maxLevels) { currentId = referrerId; continue; }

        const pct = (refVip.rates[lvl] || 0) / 100;
        if (pct <= 0) { currentId = referrerId; continue; }

        const comm = +(amount * pct).toFixed(4);
        await db.run(
          `UPDATE users SET pending_commission=pending_commission+$1, total_commission=total_commission+$1 WHERE id=$2`,
          [comm, referrerId]
        );
        await db.run(
          `INSERT INTO commissions (user_id,from_user_id,level,amount) VALUES ($1,$2,$3,$4)`,
          [referrerId, u.id, lvl+1, comm]
        );
        log('COMM', `L${lvl+1} ${refVip.name} ${pct*100}% $${comm} → user ${referrerId}`);
        currentId = referrerId;
      }
    } catch(e) { console.log('Commission error:', e.message); }

    res.json({success:true, daily_earn:daily});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});


// ══════════════════════════════════════════
// WALLET ADDRESS BIND SYSTEM
// ══════════════════════════════════════════

// GET current bound address
app.get('/api/withdraw/address', userAuth, async (req, res) => {
  try {
    const u = req.tgUser;
    const user = await db.one(`SELECT withdraw_address, address_locked, address_updated_at FROM users WHERE id=$1`, [u.id]);
    if (!user) return res.status(404).json({error:'Not found'});
    res.json({
      address: user.withdraw_address || null,
      locked: !!user.address_locked,
      updated_at: user.address_updated_at || null
    });
  } catch(e) { log('ERROR', e.message); res.status(500).json({error:'Server error. Please try again.'}); }
});

// POST bind address (first time only — user cannot change after)
app.post('/api/withdraw/bind-address', userAuth, async (req, res) => {
  try {
    const u = req.tgUser;
    const { address } = req.body;

    if (!address || !isValidBEP20Address(address)) {
      return res.status(400).json({error:'Invalid BEP20 wallet address (must start with 0x, 42 chars)'});
    }

    // Check blocked addresses
    const blockedRow = await getSetting('blocked_addresses');
    if (blockedRow) {
      const blockedList = blockedRow.split(',').map(a => a.trim().toLowerCase()).filter(Boolean);
      if (blockedList.includes(address.trim().toLowerCase())) {
        log('SECURITY', `Blocked address bind attempt by user ${u.id}: ${address}`);
        return res.status(400).json({error:'Invalid wallet address'});
      }
    }

    const user = await db.one(`SELECT withdraw_address, address_locked FROM users WHERE id=$1`, [u.id]);
    if (!user) return res.status(404).json({error:'Not found'});

    // ✅ SECURITY: If already locked, user cannot change
    if (user.address_locked && user.withdraw_address) {
      log('SECURITY', `User ${u.id} attempted to self-change locked address`);
      return res.status(403).json({error:'Address is locked. Contact support to change.'});
    }

    // Save and lock immediately — store lowercase for consistent uniqueness
    const cleanAddr = address.trim().toLowerCase();

    // ✅ UNIQUE CHECK: Address must not belong to another account
    const existing = await db.one(
      `SELECT id FROM users WHERE LOWER(withdraw_address)=$1 AND id!=$2`,
      [cleanAddr, u.id]
    );
    if (existing) {
      const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
      log('SECURITY', `Duplicate address attempt user=${u.id} addr=${cleanAddr.slice(0,16)}... ip=${ip}`);
      await db.run(
        `INSERT INTO address_change_logs (admin_id, user_id, old_address, new_address, action) VALUES ($1,$2,$3,$4,$5)`,
        ['system', u.id, null, cleanAddr, 'duplicate_attempt']
      );
      return res.status(400).json({
        error:'This wallet address is already linked to another account. Please use your own wallet.'
      });
    }
    await db.run(
      `UPDATE users SET withdraw_address=$1, address_locked=TRUE, address_updated_at=NOW() WHERE id=$2`,
      [cleanAddr, u.id]
    );
    log('ADDRESS', `User ${u.id} bound address: ${cleanAddr.slice(0,16)}...`);
    res.json({success:true, message:'Address bound and locked successfully.'});
  } catch(e) { log('ERROR', e.message); res.status(500).json({error:'Server error. Please try again.'}); }
});

// /api/deposit (old manual route) removed — all deposits go through /api/deposit/create

app.post('/api/withdraw', userAuth, async (req, res) => {
  try {
    const u = req.tgUser;
    const { amount } = req.body; // ✅ address comes from DB only — not from user input
    const network = 'BEP20';

    const user = await db.one(`SELECT * FROM users WHERE id=$1`, [u.id]);
    if (!user) return res.status(404).json({error:'Not found'});
    if (user.is_banned) return res.status(403).json({error:'banned'});

    // ✅ BOUND ADDRESS CHECK — must have bound address before withdrawing
    if (!user.withdraw_address || !user.address_locked) {
      return res.status(400).json({error:'No withdrawal address bound. Please bind your address first.'});
    }
    const address = user.withdraw_address; // use DB address, never trust user input

    // Block check
    const blockMsg = await checkBlocked(u.id);
    if (blockMsg) return res.status(429).json({error: blockMsg});

    // Validations
    const [wMinRow, wMaxRow, wFeeRow] = await Promise.all([
      getSetting('withdraw_min'), getSetting('withdraw_max'), getSetting('withdraw_fee_pct')
    ]);
    const minW   = parseFloat(wMinRow   || 2);
    const maxW   = parseFloat(wMaxRow   || 10000);
    const feePct = parseFloat(wFeeRow   || 0);
    const amt    = parseFloat(amount);

    if (!amt || amt < minW) {
      log('WITHDRAW', `User ${u.id} rejected: amount too low (${amt})`);
      return res.status(400).json({error:`Minimum withdrawal is $${minW} USDT`});
    }
    if (amt > maxW) return res.status(400).json({error:`Maximum withdrawal is $${maxW}`});

    // ✅ SECURITY: Block known attacker addresses (double-check even from DB)
    const blockedAddrsRow = await getSetting('blocked_addresses');
    if (blockedAddrsRow) {
      const blockedList = blockedAddrsRow.split(',').map(a => a.trim().toLowerCase()).filter(Boolean);
      if (blockedList.includes(address.trim().toLowerCase())) {
        log('SECURITY', `BLOCKED address in DB for user ${u.id}: ${address}`);
        return res.status(400).json({error:'Withdrawal address is blocked. Contact support.'});
      }
    }
    if (user.balance < amt) {
      log('WITHDRAW', `User ${u.id} rejected: insufficient balance (bal=${user.balance} req=${amt})`);
      return res.status(400).json({error:'Insufficient balance'});
    }

    // [NEW] One pending withdrawal per user
    const existing = await db.one(
      `SELECT id, created_at FROM transactions WHERE user_id=$1 AND type='withdraw' AND status='pending'`,
      [u.id]
    );
    if (existing) {
      return res.status(400).json({error:'You already have a pending withdrawal request'});
    }
    // [DAILY LIMIT] Max 2 withdrawals per day
    const todayCount = await db.one(
      `SELECT COUNT(*) as cnt FROM transactions WHERE user_id=$1 AND type='withdraw'
       AND created_at >= CURRENT_DATE AT TIME ZONE 'UTC'`,
      [u.id]
    );
    if (parseInt(todayCount.cnt) >= 2) {
      return res.status(400).json({error:'Daily withdrawal limit reached (max 2 per day). Try again tomorrow.'});
    }

    const fee = +(amt * feePct / 100).toFixed(2);
    // [DB-LEVEL GUARD] Conditional deduct — prevents negative balance under race condition
    const deductResult = await pool.query(
      `UPDATE users SET balance=balance-$1 WHERE id=$2 AND balance>=$1 RETURNING id`,
      [amt, u.id]
    );
    if (deductResult.rowCount === 0) return res.status(400).json({error:'Insufficient balance'});
    await db.run(
      `INSERT INTO transactions (user_id,type,amount,network,address,fee,note) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [u.id,'withdraw',amt,network,address.trim(),fee,'Processing time: 0–24 hours']
    );
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
    const ua = (req.headers['user-agent'] || '').slice(0, 80);
    log('WITHDRAW', `User ${u.id} requested $${amt} to ${address.trim().slice(0,16)}... fee=$${fee} ip=${ip}`);
    logSecurity('WITHDRAW_SUBMITTED', {user_id: u.id, amount: amt, address: address.slice(0,20), ip, ua});
    res.json({success:true, fee, message:'Withdrawal submitted. Processing time: 0–24 hours.'});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

app.post('/api/collect-daily', userAuth, async (req, res) => {
  try {
    const u = req.tgUser;
    const {investment_id} = req.body;
    const inv = await db.one(
      `SELECT * FROM investments WHERE id=$1 AND user_id=$2 AND status='active'`,
      [investment_id, u.id]
    );
    if (!inv) return res.status(404).json({error:'Investment not found'});

    const now = new Date();
    if (inv.last_collect) {
      const diff = now - new Date(inv.last_collect);
      const hoursLeft = Math.ceil((24*60*60*1000 - diff) / (1000*60*60));
      const secsLeft  = Math.ceil((24*60*60*1000 - diff) / 1000);
      if (diff < 24*60*60*1000) return res.status(400).json({
        error: 'Already collected. Next collect in ' + hoursLeft + 'h',
        secondsLeft: secsLeft
      });
    }

    const earn = parseFloat(inv.daily_earn);
    // [ATOMIC RACE GUARD] Single atomic UPDATE that checks 24h window simultaneously
    // This prevents double-collect: if two requests race, only one will pass the WHERE clause
    const collectResult = await pool.query(
      `UPDATE investments SET last_collect=NOW(), days_done=days_done+1
       WHERE id=$1 AND user_id=$2 AND status='active'
       AND (last_collect IS NULL OR NOW() - last_collect >= INTERVAL '24 hours')
       RETURNING id`,
      [inv.id, u.id]
    );
    if (collectResult.rowCount === 0) {
      // Another request already collected, or 24h not passed yet
      const fresh = await db.one(`SELECT last_collect FROM investments WHERE id=$1`, [inv.id]);
      const secsLeft = fresh && fresh.last_collect
        ? Math.max(0, Math.ceil((86400000 - (Date.now() - new Date(fresh.last_collect).getTime())) / 1000))
        : 86400;
      return res.status(400).json({ error: 'Already collected. Please wait 24 hours.', secondsLeft: secsLeft });
    }
    await db.run(
      `UPDATE users SET balance=balance+$1, total_earned=total_earned+$1, today_earned=today_earned+$1, last_earn_date=TO_CHAR(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD') WHERE id=$2`,
      [earn, u.id]
    );
    await db.run(
      `INSERT INTO transactions (user_id,type,amount,status,note) VALUES ($1,$2,$3,$4,$5)`,
      [u.id,'earn',earn,'completed',`Daily: ${inv.plan_name}`]
    );
    // Use days_total from inv — days_done already incremented in atomic UPDATE above
    const newDaysDone = (inv.days_done || 0) + 1;
    if (newDaysDone >= inv.days_total) {
      await db.run(`UPDATE investments SET status='completed' WHERE id=$1`, [inv.id]);
    }
    res.json({success:true, earned:earn, days_done: newDaysDone, completed: newDaysDone >= inv.days_total});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

app.post('/api/task/complete', userAuth, async (req, res) => {
  try {
    const u = req.tgUser;
    const {task_key} = req.body; // reward from CLIENT ignored — always use server-side value
    // [SECURITY] Get reward from DB first, not from client
    const taskCfg = await db.one(`SELECT * FROM tasks_config WHERE task_key=$1 AND is_active=1`, [task_key]);
    if (!taskCfg) return res.status(404).json({error:'Task not found'});
    const reward = parseFloat(taskCfg.reward) || 0;

    // For invite tasks — verify actual active referral count
    if (task_key && task_key.indexOf('invite') !== -1) {
      const numMatch = task_key.match(/(\d+)/);
      const required = numMatch ? parseInt(numMatch[1]) : 1;
      const countRow = await db.one(
        `SELECT COUNT(DISTINCT i.user_id) as cnt FROM investments i
         JOIN users us ON us.id=i.user_id
         WHERE us.is_active_ref=TRUE AND us.referred_by=$1 AND i.status='active'`,
        [u.id]
      );
      const activeCount = parseInt(countRow.cnt) || 0;
      if (activeCount < required) {
        return res.status(400).json({error:`Need ${required} active referral(s). You have ${activeCount}.`});
      }
    }

    // ✅ ATOMIC: INSERT only if not already completed — race condition safe
    const taskResult = await pool.query(
      `INSERT INTO tasks (user_id,task_key,completed,completed_at) VALUES ($1,$2,1,NOW())
       ON CONFLICT (user_id,task_key) DO UPDATE SET completed=1
       WHERE tasks.completed=0
       RETURNING id`,
      [u.id, task_key]
    );
    if (taskResult.rowCount === 0) return res.status(400).json({error:'Already done'});
    await db.run(`UPDATE users SET balance=balance+$1, total_earned=total_earned+$1 WHERE id=$2`, [reward, u.id]);
    await db.run(
      `INSERT INTO transactions (user_id,type,amount,status,note) VALUES ($1,$2,$3,$4,$5)`,
      [u.id, 'task_reward', reward, 'completed', 'Task: ' + task_key]
    );
    res.json({success:true});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

// Verify task (checks Telegram membership for channel/group tasks)
app.post('/api/verify-task', userAuth, async (req, res) => {
  try {
    const u = req.tgUser;
    if (!u || !u.id) return res.status(400).json({error:'No user'});
    const { task_key } = req.body;
    const taskCfg = await db.one('SELECT * FROM tasks_config WHERE task_key=$1 AND is_active=1', [task_key]);
    if (!taskCfg) return res.status(404).json({error:'Task not found'});

    // If task has a chat_id, verify via Telegram Bot API
    if (taskCfg.chat_id && taskCfg.chat_id.trim()) {
      try {
        const tgRes = await fetch(
          `https://api.telegram.org/bot${BOT_TOKEN}/getChatMember?chat_id=${encodeURIComponent(taskCfg.chat_id.trim())}&user_id=${u.id}`
        );
        const tgData = await tgRes.json();
        if (tgData.ok) {
          const status = tgData.result.status;
          const isMember = ['member','administrator','creator'].includes(status);
          return res.json({ verified: isMember });
        }
      } catch(e) { console.log('TG verify error:', e.message); }
    }

    // No chat_id set — just trust the user
    res.json({ verified: true });
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});


// ── GET /api/story-task/status ────────────────────
app.get('/api/story-task/status', userAuth, async (req, res) => {
  try {
    const u    = req.tgUser;
    const today = new Date().toISOString().slice(0, 10);
    const row  = await db.one(
      `SELECT attempts, claimed FROM story_tasks WHERE user_id=$1 AND claim_date=$2`,
      [u.id, today]
    );
    res.json({
      claimedToday: row ? !!row.claimed : false,
      attempts:     row ? (row.attempts || 0) : 0
    });
  } catch(e) { log("ERROR", e.message); res.status(500).json({error: "Server error. Please try again."}); }
});

// ── POST /api/story-task/claim ────────────────────
app.post('/api/story-task/claim', userAuth, async (req, res) => {
  try {
    const u     = req.tgUser;
    const today = new Date().toISOString().slice(0, 10);
    const REWARD = 0.04;

    // [ORDER FIX] Check existing row BEFORE incrementing attempts
    const existingRow = await db.one(
      `SELECT attempts, claimed FROM story_tasks WHERE user_id=$1 AND claim_date=$2`,
      [u.id, today]
    );

    // Already claimed today — reject immediately, don't increment counter
    if (existingRow && existingRow.claimed) {
      return res.status(400).json({ error: 'Already claimed today. Come back in 24 hours.' });
    }

    // Attempt limit — reject before incrementing
    if (existingRow && existingRow.attempts >= 3) {
      return res.status(400).json({ error: 'Max attempts reached. Try again tomorrow.' });
    }

    // Safe to upsert and increment now
    await db.run(
      `INSERT INTO story_tasks (user_id, claim_date, attempts, claimed, last_attempt)
       VALUES ($1, $2, 1, 0, NOW())
       ON CONFLICT (user_id, claim_date) DO UPDATE
       SET attempts = story_tasks.attempts + 1, last_attempt = NOW()`,
      [u.id, today]
    );

    // ✅ FIX: Atomic claim — prevent race condition double-credit
    const claimResult = await pool.query(
      `UPDATE story_tasks SET claimed=1, claimed_at=NOW()
       WHERE user_id=$1 AND claim_date=$2 AND claimed=0
       RETURNING id`,
      [u.id, today]
    );
    if (claimResult.rowCount === 0) {
      return res.status(400).json({ error: 'Already claimed today. Come back in 24 hours.' });
    }
    await db.run(
      `UPDATE users SET balance=balance+$1, total_earned=total_earned+$1 WHERE id=$2`,
      [REWARD, u.id]
    );
    await db.run(
      `INSERT INTO transactions (user_id,type,amount,status,note) VALUES ($1,$2,$3,$4,$5)`,
      [u.id, 'task_reward', REWARD, 'completed', 'Story task reward']
    );

    res.json({ success: true, amount: REWARD });
  } catch(e) { log('ERROR', e.message); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

// ══════════════════════════════════════════
// PUBLIC ROUTES
// ══════════════════════════════════════════

// Health check
app.get('/health', (req, res) => {
  res.json({status: 'ok', time: new Date().toISOString()});
});

// Public tasks endpoint
app.get('/api/tasks', async (req, res) => {
  try {
    const tasks = await db.all('SELECT * FROM tasks_config WHERE is_active=1 ORDER BY sort_order');
    res.json({tasks});
  } catch(e) { res.json({tasks:[]}); }
});

// Bot calls this when user uses referral link
app.post('/api/set-pending-ref', async (req, res) => {
  try {
    const {user_id, ref_code, secret} = req.body;
    // Bot-only endpoint — require admin secret to prevent referral hijacking
    if (secret !== ADMIN_SECRET) return res.status(403).json({success:false, error:'Unauthorized'});
    if (!user_id || !ref_code) return res.json({success:false});
    // Validate ref_code format (REF + digits only)
    if (!/^REF\d+$/.test(String(ref_code))) return res.json({success:false, error:'Invalid ref_code'});
    await db.run(`
      INSERT INTO pending_refs (user_id, ref_code) VALUES ($1,$2)
      ON CONFLICT (user_id) DO UPDATE SET ref_code=$2, created_at=NOW()
    `, [user_id, ref_code]);
    res.json({success:true});
  } catch(e) { res.json({success:false}); }
});
// ── Activity cache (reduces DB load) ──
var activityCache = [];
var activityLastFetch = 0;

app.get('/api/activity', async (req, res) => {
  try {
    const now = Date.now();
    if (now - activityLastFetch < 10000 && activityCache.length > 0) {
      return res.json(activityCache);
    }
    const rows = await db.all(`
      SELECT type, amount, created_at
      FROM transactions
      WHERE type IN ('deposit','withdraw') AND status='approved'
      ORDER BY created_at DESC LIMIT 10
    `);
    const activity = rows.map(function(r) {
      const diff = Math.floor((now - new Date(r.created_at).getTime()) / 1000);
      let time;
      if      (diff < 60)    time = diff + 's ago';
      else if (diff < 3600)  time = Math.floor(diff/60) + 'm ago';
      else if (diff < 86400) time = Math.floor(diff/3600) + 'h ago';
      else                   time = Math.floor(diff/86400) + 'd ago';
      return { type: r.type, amount: parseFloat(r.amount), time };
    });
    activityCache = activity;
    activityLastFetch = now;
    res.json(activity);
  } catch(e) {
    console.error('Activity API error:', e);
    res.json(activityCache.length ? activityCache : []);
  }
});

app.get('/api/plans', async (req, res) => {
  try {
    await db.run(`
      UPDATE plans SET today_count=0, last_reset=NOW()
      WHERE daily_limit > 0
        AND last_reset IS NOT NULL
        AND EXTRACT(EPOCH FROM (NOW() - last_reset))/3600 >= reset_hours
    `);
    const plans = await db.all(`SELECT * FROM plans WHERE is_active=1 ORDER BY id`);
    res.json({plans});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

// ══════════════════════════════════════════
// ADMIN ROUTES
// ══════════════════════════════════════════
app.get('/admin/stats', adminAuth, async (req, res) => {
  try {
    const [
      totalUsersRow, activeInvestsRow, totalDepositRow, totalWithdrawRow,
      pendingDepRow, pendingWithRow, bannedUsersRow, totalBalanceRow,
      todayDepRow, autoDepRow, fraudRow
    ] = await Promise.all([
      db.one(`SELECT COUNT(*) as c FROM users`),
      db.one(`SELECT COUNT(*) as c FROM investments WHERE status='active'`),
      db.one(`SELECT COALESCE(SUM(amount),0) as s FROM transactions WHERE type='deposit' AND status='approved'`),
      db.one(`SELECT COALESCE(SUM(amount),0) as s FROM transactions WHERE type='withdraw' AND status='approved'`),
      db.one(`SELECT COUNT(*) as c FROM transactions WHERE type='deposit' AND status='pending'`),
      db.one(`SELECT COUNT(*) as c FROM transactions WHERE type='withdraw' AND status='pending'`),
      db.one(`SELECT COUNT(*) as c FROM users WHERE is_banned=1`),
      db.one(`SELECT COALESCE(SUM(balance),0) as s FROM users`),
      // [NEW] Today's deposits
      db.one(`SELECT COALESCE(SUM(amount),0) as s, COUNT(*) as c FROM transactions WHERE type='deposit' AND status='approved' AND created_at >= NOW() - INTERVAL '24 hours'`),
      // [NEW] Auto vs semi counts
      db.one(`SELECT COUNT(*) as c FROM auto_deposits WHERE dep_type='auto' AND status='completed'`),
      db.one(`SELECT COUNT(*) as c FROM auto_deposits WHERE fraud_flag=1`),
    ]);
    res.json({
      totalUsers: totalUsersRow.c,
      activeInvests: activeInvestsRow.c,
      totalDeposit: totalDepositRow.s,
      totalWithdraw: totalWithdrawRow.s,
      pendingDep: pendingDepRow.c,
      pendingWith: pendingWithRow.c,
      bannedUsers: bannedUsersRow.c,
      totalBalance: totalBalanceRow.s,
      // [NEW]
      todayDepAmount: todayDepRow.s,
      todayDepCount: todayDepRow.c,
      autoDepCount: autoDepRow.c,
      fraudCount: fraudRow.c,
    });
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

// ══════════════════════════════════════════
// ADMIN DASHBOARD DETAIL ENDPOINTS
// ══════════════════════════════════════════

// Deposit history (clickable stat)
app.get('/admin/stat/deposits', adminAuth, async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, parseInt(req.query.limit) || 20);
    const offset = (page - 1) * limit;
    const [rows, totalRow] = await Promise.all([
      db.all(`
        SELECT ad.user_id, u.username, u.first_name, ad.amount, ad.network, ad.status, ad.created_at
        FROM auto_deposits ad LEFT JOIN users u ON u.id=ad.user_id
        WHERE ad.status='completed'
        ORDER BY ad.created_at DESC LIMIT $1 OFFSET $2
      `, [limit, offset]),
      db.one(`SELECT COUNT(*) as c FROM auto_deposits WHERE status='completed'`)
    ]);
    const total = parseInt(totalRow.c);
    res.json({ rows, total, currentPage: page, totalPages: Math.ceil(total/limit), limit });
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

// Withdrawal history (clickable stat)
app.get('/admin/stat/withdrawals', adminAuth, async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, parseInt(req.query.limit) || 20);
    const offset = (page - 1) * limit;
    const [rows, totalRow] = await Promise.all([
      db.all(`
        SELECT t.user_id, u.username, u.first_name, t.amount, t.address, t.status, t.created_at
        FROM transactions t LEFT JOIN users u ON u.id=t.user_id
        WHERE t.type='withdraw'
        ORDER BY t.created_at DESC LIMIT $1 OFFSET $2
      `, [limit, offset]),
      db.one(`SELECT COUNT(*) as c FROM transactions WHERE type='withdraw'`)
    ]);
    const total = parseInt(totalRow.c);
    res.json({ rows, total, currentPage: page, totalPages: Math.ceil(total/limit), limit });
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

// All users by balance (clickable stat)
app.get('/admin/stat/balances', adminAuth, async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, parseInt(req.query.limit) || 20);
    const offset = (page - 1) * limit;
    const [rows, totalRow] = await Promise.all([
      db.all(`SELECT id, username, first_name, balance FROM users ORDER BY balance DESC LIMIT $1 OFFSET $2`, [limit, offset]),
      db.one(`SELECT COUNT(*) as c FROM users`)
    ]);
    const total = parseInt(totalRow.c);
    res.json({ rows, total, currentPage: page, totalPages: Math.ceil(total/limit), limit });
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

// Daily income total + per-user breakdown
app.get('/admin/stat/daily-income', adminAuth, async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, parseInt(req.query.limit) || 20);
    const offset = (page - 1) * limit;
    const [totalRow, rows, countRow] = await Promise.all([
      db.one(`SELECT COALESCE(SUM(amount),0) as total FROM transactions WHERE type='earn' AND created_at >= CURRENT_DATE`),
      db.all(`
        SELECT u.username, u.first_name, t.user_id, SUM(t.amount) as daily_income
        FROM transactions t LEFT JOIN users u ON u.id=t.user_id
        WHERE t.type='earn' AND t.created_at >= CURRENT_DATE
        GROUP BY t.user_id, u.username, u.first_name
        ORDER BY daily_income DESC LIMIT $1 OFFSET $2
      `, [limit, offset]),
      db.one(`SELECT COUNT(DISTINCT user_id) as c FROM transactions WHERE type='earn' AND created_at >= CURRENT_DATE`)
    ]);
    const total = parseFloat(totalRow.total);
    const totalUsers = parseInt(countRow.c);
    res.json({ total, rows, totalUsers, currentPage: page, totalPages: Math.ceil(totalUsers/limit), limit });
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});


// [NEW] Admin deposit history with filters
app.get('/admin/deposits', adminAuth, async (req, res) => {
  try {
    const { status, dep_type, date_from, date_to, limit=50 } = req.query;
    let q = `SELECT d.*, u.first_name, u.username FROM auto_deposits d LEFT JOIN users u ON d.user_id=u.id WHERE 1=1`;
    const params = [];
    if (status)   { params.push(status);   q += ` AND d.status=$${params.length}`; }
    if (dep_type) { params.push(dep_type); q += ` AND d.dep_type=$${params.length}`; }
    if (date_from){ params.push(date_from); q += ` AND d.created_at >= $${params.length}::date`; }
    if (date_to)  { params.push(date_to);   q += ` AND d.created_at < ($${params.length}::date + INTERVAL '1 day')`; }
    params.push(limit); q += ` ORDER BY d.created_at DESC LIMIT $${params.length}`;
    const rows = await db.all(q, params);
    res.json({ deposits: rows });
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

app.get('/admin/users', adminAuth, async (req, res) => {
  try {
    const {search, limit=20, page=1} = req.query;
    const offset = (page-1)*limit;
    let q, params;
    if (search) {
      q = `SELECT * FROM users WHERE first_name ILIKE $1 OR username ILIKE $1 OR CAST(id AS TEXT) LIKE $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`;
      params = [`%${search}%`, limit, offset];
    } else {
      q = `SELECT * FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`;
      params = [limit, offset];
    }
    const users = await db.all(q, params);
    const total = (await db.one(`SELECT COUNT(*) as c FROM users`)).c;

    // Enrich all users in ONE query instead of N*4 queries
    const userIds = users.map(u => u.id);
    const enrichRows = userIds.length > 0 ? await db.all(`
      SELECT
        user_id,
        SUM(CASE WHEN type='deposit'  AND status='approved' THEN amount ELSE 0 END) as dep_total,
        SUM(CASE WHEN type='withdraw' AND status='approved' THEN amount ELSE 0 END) as with_total,
        COUNT(CASE WHEN type='deposit'  AND status='approved' THEN 1 END) as dep_cnt,
        COUNT(CASE WHEN type='withdraw' AND status='approved' THEN 1 END) as with_cnt,
        MAX(CASE WHEN type='deposit'  AND status='approved' THEN created_at END) as last_dep,
        MAX(CASE WHEN type='withdraw' AND status='approved' THEN created_at END) as last_with
      FROM transactions
      WHERE user_id = ANY($1::bigint[])
      GROUP BY user_id
    `, [userIds]) : [];

    const enrichMap = {};
    enrichRows.forEach(r => { enrichMap[r.user_id] = r; });

    const enriched = users.map(u => {
      const r = enrichMap[u.id] || {};
      const totalDeposit  = parseFloat(r.dep_total  || 0);
      const totalWithdraw = parseFloat(r.with_total || 0);
      const depositCount  = parseInt(r.dep_cnt  || 0);
      const withdrawCount = parseInt(r.with_cnt || 0);
      const netProfit     = totalDeposit - totalWithdraw;
      const isSuspicious  = (totalWithdraw > totalDeposit * 1.5) || (withdrawCount > depositCount * 2);
      return {
        ...u,
        totalDeposit, totalWithdraw, depositCount, withdrawCount,
        netProfit, isSuspicious,
        lastDepositAt:  r.last_dep  || null,
        lastWithdrawAt: r.last_with || null,
      };
    });

    res.json({users: enriched, total});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

// User transaction details with optional status filter
app.get('/admin/user/:id/details', adminAuth, async (req, res) => {
  try {
    const uid    = req.params.id;
    const status = req.query.status || '';
    const depQ   = status
      ? `SELECT 'deposit' as type, amount, status, created_at, network FROM transactions WHERE user_id=$1 AND type='deposit' AND status=$2 ORDER BY created_at DESC LIMIT 50`
      : `SELECT 'deposit' as type, amount, status, created_at, network FROM transactions WHERE user_id=$1 AND type='deposit' ORDER BY created_at DESC LIMIT 50`;
    const withQ  = status
      ? `SELECT 'withdraw' as type, amount, status, created_at, address as network FROM transactions WHERE user_id=$1 AND type='withdraw' AND status=$2 ORDER BY created_at DESC LIMIT 50`
      : `SELECT 'withdraw' as type, amount, status, created_at, address as network FROM transactions WHERE user_id=$1 AND type='withdraw' ORDER BY created_at DESC LIMIT 50`;
    const depParams  = status ? [uid, status] : [uid];
    const withParams = status ? [uid, status] : [uid];
    const [deps, withs] = await Promise.all([
      db.all(depQ, depParams),
      db.all(withQ, withParams),
    ]);
    const txs = [...deps, ...withs].sort((a,b) => new Date(b.created_at) - new Date(a.created_at));
    res.json({transactions: txs});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

app.post('/admin/user/ban', adminAuth, async (req, res) => {
  try {
    const {user_id, reason} = req.body;
    await db.run(`UPDATE users SET is_banned=1, ban_reason=$1 WHERE id=$2`, [reason||'Violated terms', user_id]);
    res.json({success:true});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

app.post('/admin/user/unban', adminAuth, async (req, res) => {
  try {
    await db.run(`UPDATE users SET is_banned=0, ban_reason=NULL WHERE id=$1`, [req.body.user_id]);
    log('ADMIN', `User ${req.body.user_id} unbanned`);
    res.json({success:true});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

// [NEW] Block user from deposits (fraud block)
app.post('/admin/user/deposit-block', adminAuth, async (req, res) => {
  try {
    const { user_id, minutes } = req.body;
    const dur = parseInt(minutes || 30);
    const until = new Date(Date.now() + dur * 60000);
    await db.run(`UPDATE users SET blocked_until=$1 WHERE id=$2`, [until, user_id]);
    log('ADMIN', `User ${user_id} deposit-blocked for ${dur}min by admin`);
    res.json({success:true, blocked_until: until});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

// [NEW] Unblock user deposits
app.post('/admin/user/deposit-unblock', adminAuth, async (req, res) => {
  try {
    await clearFraud(req.body.user_id);
    log('ADMIN', `User ${req.body.user_id} deposit-unblocked by admin`);
    res.json({success:true});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

// [NEW] View logs
app.get('/admin/logs', adminAuth, async (req, res) => {
  try {
    if (!fs.existsSync(LOG_FILE)) return res.json({logs:''});
    const lines = fs.readFileSync(LOG_FILE, 'utf8').split('\n').filter(Boolean);
    const last100 = lines.slice(-100).reverse().join('\n');
    res.json({logs: last100});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

app.post('/admin/user/balance', adminAuth, async (req, res) => {
  try {
    const {user_id, type} = req.body;
    const amount = parseFloat(req.body.amount);
    if (!user_id || isNaN(amount) || amount <= 0) return res.status(400).json({error:'Invalid user_id or amount'});
    const change = type==='deduct' ? -Math.abs(amount) : Math.abs(amount);
    // Guard: prevent deduct below zero
    if (type === 'deduct') {
      const r = await pool.query(`UPDATE users SET balance=balance+$1 WHERE id=$2 AND balance>=$3 RETURNING id`, [change, user_id, Math.abs(amount)]);
      if (r.rowCount === 0) return res.status(400).json({error:'Insufficient balance for deduction'});
    } else {
      await db.run(`UPDATE users SET balance=balance+$1 WHERE id=$2`, [change, user_id]);
    }
    await db.run(
      `INSERT INTO transactions (user_id,type,amount,status,note) VALUES ($1,$2,$3,$4,$5)`,
      [user_id, type==='deduct'?'admin_deduct':'admin_add', Math.abs(amount), 'completed', 'Admin adjustment']
    );
    res.json({success:true});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

app.get('/admin/transactions', adminAuth, async (req, res) => {
  try {
    const {type, status, limit=50} = req.query;
    let q = `SELECT t.*, u.first_name, u.username FROM transactions t LEFT JOIN users u ON t.user_id=u.id WHERE 1=1`;
    const params = [];
    if (type)   { params.push(type);   q += ` AND t.type=$${params.length}`; }
    if (status) { params.push(status); q += ` AND t.status=$${params.length}`; }
    params.push(limit); q += ` ORDER BY t.created_at DESC LIMIT $${params.length}`;
    const txs = await db.all(q, params);
    res.json({transactions: txs});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

app.post('/admin/deposit/approve', adminAuth, async (req, res) => {
  try {
    const {tx_id, admin_note} = req.body;
    if (!tx_id || isNaN(parseInt(tx_id))) return res.status(400).json({error:'Invalid tx_id'});

    const tx = await db.one(`SELECT * FROM transactions WHERE id=$1 AND type='deposit'`, [tx_id]);
    if (!tx) return res.status(404).json({error:'Not found'});
    if (parseFloat(tx.amount) <= 0) return res.status(400).json({error:'Invalid amount'});

    // [DOUBLE-CREDIT GUARD] If tx was already auto-credited (has txid + status approved in auto_deposits), block approval
    if (tx.txid) {
      const alreadyAuto = await db.one(
        `SELECT id FROM auto_deposits WHERE tx_hash=$1 AND status='completed'`,
        [tx.txid]
      );
      if (alreadyAuto) {
        log('ADMIN', `Blocked double-credit attempt: tx=${tx_id} txhash=${tx.txid} already auto-credited`);
        return res.status(400).json({error:'This deposit was already auto-credited to the user. Do not approve again.'});
      }
    }

    // [ATOMIC] Only update if still pending — prevents double approval under race
    const result = await pool.query(
      `UPDATE transactions SET status='approved', admin_note=$1 WHERE id=$2 AND status='pending' RETURNING id`,
      [admin_note||'', tx_id]
    );
    if (result.rowCount === 0) return res.status(400).json({error:'Already processed'});

    // Safe atomic balance credit
    await db.run(`UPDATE users SET balance=balance+$1 WHERE id=$2`, [tx.amount, tx.user_id]);
    log('ADMIN', `Deposit approved tx=${tx_id} user=${tx.user_id} amt=$${tx.amount}`);
    logSecurity('DEPOSIT_APPROVED', {tx_id, user_id: tx.user_id, amount: tx.amount});
    res.json({success:true});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

app.post('/admin/deposit/reject', adminAuth, async (req, res) => {
  try {
    const {tx_id, admin_note} = req.body;
    if (!tx_id || isNaN(parseInt(tx_id))) return res.status(400).json({error:'Invalid tx_id'});
    const tx = await db.one(`SELECT * FROM transactions WHERE id=$1 AND type='deposit'`, [tx_id]);
    if (!tx) return res.status(404).json({error:'Not found'});
    if (tx.status !== 'pending') return res.status(400).json({error:'Already processed'});
    await db.run(`UPDATE transactions SET status='rejected', admin_note=$1 WHERE id=$2`, [admin_note||'Rejected by admin', tx_id]);
    log('ADMIN', `Deposit rejected tx=${tx_id} user=${tx.user_id}`);
    res.json({success:true});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

app.post('/admin/withdraw/approve', adminAuth, async (req, res) => {
  try {
    const {tx_id, admin_note, bsc_tx_hash} = req.body;
    if (!tx_id || isNaN(parseInt(tx_id))) return res.status(400).json({error:'Invalid tx_id'});
    const tx = await db.one(`SELECT t.*, u.username, u.first_name FROM transactions t LEFT JOIN users u ON u.id=t.user_id WHERE t.id=$1 AND t.type='withdraw'`, [tx_id]);
    if (!tx) return res.status(404).json({error:'Not found'});

    // [ATOMIC] Only approve if still pending — rowCount=0 means already processed
    const result = await pool.query(
      `UPDATE transactions SET status='approved', admin_note=$1, approved_at=NOW() WHERE id=$2 AND status='pending' RETURNING id, user_id, amount`,
      [admin_note||'', tx_id]
    );
    if (result.rowCount === 0) return res.status(400).json({error:'Already processed'});

    // Save bsc_tx_hash AFTER atomic approval confirmed (not before — avoids saving on already-processed)
    if (bsc_tx_hash && bsc_tx_hash.trim()) {
      await db.run(`UPDATE transactions SET bsc_tx_hash=$1 WHERE id=$2`, [bsc_tx_hash.trim(), tx_id]);
    }

    const {user_id, amount} = result.rows[0];
    log('WITHDRAW', `APPROVED tx=${tx_id} user=${user_id} amt=$${amount} addr=${(tx.address||'').slice(0,16)}`);
    logSecurity('WITHDRAW_APPROVED', {tx_id, user_id, amount, address: (tx.address||'').slice(0,20)});
    res.json({success:true});

    // Fire Telegram proof immediately after approve (non-blocking)
    // Scanner will try to add TX hash separately if Moralis detects it
    setImmediate(() => sendWithdrawProof({
      withdraw_id: tx_id,
      username:    tx.username    || '',
      first_name:  tx.first_name  || '',
      user_id:     user_id,
      amount:      amount,
      address:     tx.address     || '',
      bsc_tx_hash: (bsc_tx_hash && bsc_tx_hash.trim()) ? bsc_tx_hash.trim() : ''
    }));
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

app.post('/admin/withdraw/reject', adminAuth, async (req, res) => {
  try {
    const {tx_id, admin_note} = req.body;
    if (!tx_id || isNaN(parseInt(tx_id))) return res.status(400).json({error:'Invalid tx_id'});

    // [ATOMIC] Reject only if still pending — prevents double refund on concurrent clicks
    const result = await pool.query(
      `UPDATE transactions SET status='rejected', admin_note=$1 WHERE id=$2 AND status='pending' RETURNING id, amount, user_id`,
      [admin_note||'Rejected by admin', tx_id]
    );
    if (result.rowCount === 0) return res.status(400).json({error:'Already processed'});

    const {amount, user_id} = result.rows[0];
    // Refund balance only after confirmed atomic status change
    await db.run(`UPDATE users SET balance=balance+$1 WHERE id=$2`, [amount, user_id]);
    log('WITHDRAW', `REJECTED tx=${tx_id} user=${user_id} amt=$${amount} — refunded`);
    logSecurity('WITHDRAW_REJECTED_REFUNDED', {tx_id, user_id, amount});
    res.json({success:true});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

// ── Admin Tasks ──
app.get('/admin/tasks', adminAuth, async (req, res) => {
  try {
    const tasks = await db.all('SELECT * FROM tasks_config ORDER BY sort_order');
    res.json({tasks});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

app.post('/admin/tasks/add', adminAuth, async (req, res) => {
  try {
    const {task_key, icon, name, reward, sort_order, link, chat_id} = req.body;
    await db.run(
      'INSERT INTO tasks_config (task_key,icon,name,reward,sort_order,link,chat_id) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [task_key, icon||'⚡', name, reward||1, sort_order||99, link||'', chat_id||'']
    );
    res.json({success:true});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

app.post('/admin/tasks/edit', adminAuth, async (req, res) => {
  try {
    const {id, icon, name, reward, is_active, sort_order, link, chat_id} = req.body;
    await db.run(
      'UPDATE tasks_config SET icon=$1,name=$2,reward=$3,is_active=$4,sort_order=$5,link=$6,chat_id=$7 WHERE id=$8',
      [icon, name, reward, is_active, sort_order, link||'', chat_id||'', id]
    );
    res.json({success:true});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

app.post('/admin/tasks/delete', adminAuth, async (req, res) => {
  try {
    await db.run('DELETE FROM tasks_config WHERE id=$1', [req.body.id]);
    res.json({success:true});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

app.get('/admin/plans', adminAuth, async (req, res) => {
  try {
    const plans = await db.all(`SELECT * FROM plans ORDER BY id`);
    res.json({plans});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

app.post('/admin/plans/add', adminAuth, async (req, res) => {
  try {
    const {name,emoji,daily_pct,min_amt,max_amt,duration,daily_limit=0,reset_hours=24} = req.body;
    await db.run(
      `INSERT INTO plans (name,emoji,daily_pct,min_amt,max_amt,duration,daily_limit,reset_hours) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [name,emoji,daily_pct,min_amt,max_amt,duration,daily_limit,reset_hours]
    );
    res.json({success:true});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

app.post('/admin/plans/edit', adminAuth, async (req, res) => {
  try {
    const {id,name,emoji,daily_pct,min_amt,max_amt,duration,is_active,daily_limit=0,reset_hours=24} = req.body;
    await db.run(
      `UPDATE plans SET name=$1,emoji=$2,daily_pct=$3,min_amt=$4,max_amt=$5,duration=$6,is_active=$7,daily_limit=$8,reset_hours=$9 WHERE id=$10`,
      [name,emoji,daily_pct,min_amt,max_amt,duration,is_active,daily_limit,reset_hours,id]
    );
    res.json({success:true});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

app.post('/admin/plans/delete', adminAuth, async (req, res) => {
  try {
    // Permanently delete the plan
    await db.run(`DELETE FROM plans WHERE id=$1`, [req.body.id]);
    res.json({success:true});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

app.post('/admin/plan/update-count', adminAuth, async (req, res) => {
  try {
    const { plan_id } = req.body;
    let count = parseInt(req.body.count) || 0;
    if (!plan_id || req.body.count === undefined) return res.status(400).json({error:'plan_id and count required'});
    if (count < 0)      count = 0;
    if (count > 100000) count = 100000;
    await db.run(`UPDATE plans SET buy_count = $1 WHERE id = $2`, [count, plan_id]);
    res.json({success:true, count});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

app.get('/admin/settings', adminAuth, async (req, res) => {
  try {
    const rows = await db.all(`SELECT * FROM settings`);
    res.json(rows.reduce((a,r) => ({...a,[r.key]:r.value}), {}));
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

app.post('/admin/settings', adminAuth, async (req, res) => {
  try {
    const {settings} = req.body;
    for (const [k,v] of Object.entries(settings)) {
      await db.run(`INSERT INTO settings (key,value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=$2`, [k,String(v)]);
    }
    res.json({success:true});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

app.post('/admin/maintenance', adminAuth, async (req, res) => {
  try {
    await db.run(`INSERT INTO settings (key,value) VALUES ('maintenance',$1) ON CONFLICT (key) DO UPDATE SET value=$1`, [req.body.on?'1':'0']);
    res.json({success:true});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

// ══════════════════════════════════════════
// TELEGRAM GROUP INTEGRATION — ADMIN ROUTES
// ══════════════════════════════════════════

// GET current tg group settings + bot status + today's sent count
app.get('/admin/tg-group/status', adminAuth, async (req, res) => {
  try {
    const cfg = await getTgGroupSettings();

    // Count today's sent proofs
    const todayRow = await db.one(
      `SELECT COUNT(*) as c FROM tg_proof_logs WHERE sent_status='sent' AND created_at >= NOW() - INTERVAL '24 hours'`
    );
    // Last log entry — use db.all + take first to avoid crash on empty table
    const lastLogs = await db.all(
      `SELECT sent_status, error_msg, updated_at FROM tg_proof_logs ORDER BY id DESC LIMIT 1`
    );
    const lastLog = lastLogs && lastLogs.length > 0 ? lastLogs[0] : null;

    // Check bot alive
    let botOk = false;
    let botUsername = '';
    if (BOT_TOKEN) {
      const me = await tgBotApi('getMe', {});
      botOk = !!me.ok;
      botUsername = me.result && me.result.username ? '@' + me.result.username : '';
    }

    res.json({
      bot_ok:        botOk,
      bot_username:  botUsername,
      chat_id:       cfg.chatId,
      topic_id:      cfg.topicId,
      enabled:       cfg.enabled,
      sent_today:    parseInt(todayRow.c || 0),
      last_status:   lastLog ? lastLog.sent_status  : null,
      last_error:    lastLog ? lastLog.error_msg     : null,
      last_time:     lastLog ? lastLog.updated_at    : null
    });
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

// Save tg group settings
app.post('/admin/tg-group/settings', adminAuth, async (req, res) => {
  try {
    const { chat_id, topic_id, enabled } = req.body;
    await db.run(`INSERT INTO settings (key,value) VALUES ('tg_group_chat_id',$1)  ON CONFLICT (key) DO UPDATE SET value=$1`, [String(chat_id||'')]);
    await db.run(`INSERT INTO settings (key,value) VALUES ('tg_group_topic_id',$1) ON CONFLICT (key) DO UPDATE SET value=$1`, [String(topic_id||'')]);
    await db.run(`INSERT INTO settings (key,value) VALUES ('tg_group_enabled',$1)  ON CONFLICT (key) DO UPDATE SET value=$1`, [enabled?'1':'0']);
    res.json({success:true});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

// Test connection — send test message to configured topic
app.post('/admin/tg-group/test', adminAuth, async (req, res) => {
  try {
    const cfg = await getTgGroupSettings();
    if (!BOT_TOKEN)   return res.status(400).json({error:'BOT_TOKEN not configured on server'});
    if (!cfg.chatId)  return res.status(400).json({error:'Group Chat ID not set'});

    const payload = {
      chat_id:    cfg.chatId,
      text:       '💸 <b>Block USDT Proof Feed Connected Successfully</b>',
      parse_mode: 'HTML'
    };
    if (cfg.topicId) {
      const tid = parseInt(cfg.topicId, 10);
      if (!isNaN(tid) && tid > 0) payload.message_thread_id = tid;
    }

    const result = await tgBotApi('sendMessage', payload);
    if (!result.ok) return res.status(400).json({error: result.description || 'Send failed — check Chat ID / Topic ID and bot admin permissions'});
    res.json({success:true, message_id: result.result && result.result.message_id});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

// Check bot permissions in group
app.post('/admin/tg-group/check-permissions', adminAuth, async (req, res) => {
  try {
    const cfg = await getTgGroupSettings();
    if (!BOT_TOKEN)  return res.status(400).json({error:'BOT_TOKEN not set'});
    if (!cfg.chatId) return res.status(400).json({error:'Chat ID not configured'});

    const me = await tgBotApi('getMe', {});
    if (!me.ok || !me.result || !me.result.id) return res.status(400).json({error:'Cannot reach Telegram API'});

    const member = await tgBotApi('getChatMember', { chat_id: cfg.chatId, user_id: me.result.id });
    if (!member.ok) return res.status(400).json({error: member.description || 'Bot is not in the group'});

    const status = member.result && member.result.status;
    const canPost = status === 'administrator' || status === 'creator';
    res.json({
      ok: canPost,
      status,
      can_send_messages: canPost,
      warning: canPost ? null : 'Bot is not an admin — cannot post messages'
    });
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});

// ══════════════════════════════════════════
// REFERRAL STATS (per-level breakdown)
// ══════════════════════════════════════════
app.get('/api/referral-stats/:id', async (req, res) => {
  // Auth: verify if initData present, user can only see own stats
  const _initData = req.headers['x-telegram-init-data'];
  if (_initData && _initData.length > 10) {
    if (BOT_TOKEN && process.env.NODE_ENV !== 'development' && !verifyTg(_initData)) {
      return res.status(401).json({ error: 'Invalid session' });
    }
    try {
      const _p = new URLSearchParams(_initData);
      const _u = _p.get('user') ? JSON.parse(_p.get('user')) : null;
      if (_u && String(_u.id) !== String(req.params.id)) {
        return res.status(403).json({ error: 'Forbidden' });
      }
    } catch(e) {}
  }
  try {
    const uid = parseInt(req.params.id);
    if (!uid) return res.status(400).json({ error: 'Invalid id' });

    // Get user VIP to know how many levels to scan
    const { vip } = await getUserVipStatus(uid, 4);
    const maxLvl = vip.maxLevels || 3;

    // BFS up to maxLvl levels
    const lvlIds = [];
    let currentIds = [uid];
    for (let lvl = 0; lvl < maxLvl; lvl++) {
      if (!currentIds.length) { lvlIds.push([]); continue; }
      const rows = await db.all(
        `SELECT id FROM users WHERE referred_by = ANY($1::bigint[])`,
        [currentIds]
      );
      const nextIds = rows.map(r => parseInt(r.id));
      lvlIds.push(nextIds);
      currentIds = nextIds;
    }

    // Count active per level
    const countActive = async (ids) => {
      if (!ids || !ids.length) return 0;
      const r = await db.one(
        `SELECT COUNT(DISTINCT user_id) as cnt FROM investments WHERE user_id = ANY($1::bigint[]) AND status='active'`,
        [ids]
      );
      return parseInt(r.cnt) || 0;
    };

    const activePerLvl = await Promise.all(lvlIds.map(function(ids) { return countActive(ids); }));

    const totalAll    = lvlIds.reduce(function(s, ids) { return s + ids.length; }, 0);
    const totalActive = activePerLvl.reduce(function(s, n) { return s + n; }, 0);

    const result = { total: totalAll, total_active: totalActive, max_levels: maxLvl };
    for (let i = 0; i < lvlIds.length; i++) {
      result['lvl' + (i + 1)] = { total: lvlIds[i].length, active: activePerLvl[i] };
    }

    res.json(result);
  } catch(e) { log("ERROR", e.message); res.status(500).json({error: "Server error. Please try again."}); }
});

// ══════════════════════════════════════════
// AUTO DEPOSIT — Generate unique amount
// ══════════════════════════════════════════
async function generateUniqueAmt(base) {
  // ✅ FIX: expanded from 5 → 99 possible suffix values (0.01–0.99)
  // This dramatically reduces collision chance when many deposits are pending
  for (let i = 0; i < 99; i++) {
    const dec  = (Math.floor(Math.random() * 99) + 1); // 1–99
    const uAmt = +(parseFloat(base) + dec / 100).toFixed(2);
    const ex   = await db.one(
      `SELECT id FROM auto_deposits WHERE unique_amt=$1 AND status='pending' AND expires_at > NOW()`,
      [uAmt]
    );
    if (!ex) return uAmt;
  }
  throw new Error('Cannot generate unique amount — try again');
}

// ── POST /api/deposit/create ──────────────
app.post('/api/deposit/create', depositLimit, userAuth, async (req, res) => {
  try {
    const u      = req.tgUser;
    const { amount } = req.body;
    if (!isValidAmount(amount, 50000)) return res.status(400).json({error:'Invalid amount'});
    const userCheck = await db.one(`SELECT is_banned, blocked_until FROM users WHERE id=$1`, [u.id]);
    if (userCheck && userCheck.is_banned) return res.status(403).json({error:'banned'});
    const minDep = parseFloat(await getSetting('deposit_min') || 5);
    const amt    = parseFloat(amount);
    if (amt < minDep) return res.status(400).json({error:`Minimum deposit: $${minDep}`});

    // [ANTI-FRAUD] Cancel any existing pending auto deposit for this user
    const existing = await db.one(
      `SELECT id FROM auto_deposits WHERE user_id=$1 AND dep_type='auto' AND status='pending' AND expires_at > NOW()`,
      [u.id]
    );
    if (existing) {
      await db.run(`UPDATE auto_deposits SET status='cancelled' WHERE id=$1`, [existing.id]);
    }

    // [ANTI-FRAUD] Check if user is blocked
    const blockMsg = await checkBlocked(u.id);
    if (blockMsg) return res.status(429).json({error: blockMsg});

    const uAmt = await generateUniqueAmt(amt);
    // Track attempts counter — only after successful unique amount generation
    await db.run(`UPDATE users SET deposit_attempts=deposit_attempts+1 WHERE id=$1`, [u.id]);
    const dep  = await db.one(
      `INSERT INTO auto_deposits (user_id, amount, unique_amt, network, dep_type)
       VALUES ($1,$2,$3,'BEP20','auto') RETURNING id, unique_amt, expires_at`,
      [u.id, amt, uAmt]
    );

    res.json({ id: dep.id, unique_amount: dep.unique_amt, address: DEPOSIT_WALLET, network: 'BEP20', expires_at: dep.expires_at });
  } catch(e) { log("ERROR", e.message); res.status(500).json({error: "Server error. Please try again."}); }
});

// Semi-auto deposit routes removed

// ── GET /api/deposit/status/:id ───────────
app.get('/api/deposit/status/:id', userAuth, async (req, res) => {
  try {
    const u   = req.tgUser;
    const dep = await db.one(
      `SELECT * FROM auto_deposits WHERE id=$1 AND user_id=$2`,
      [req.params.id, u.id]
    );
    if (!dep) return res.status(404).json({error:'Not found'});
    if (dep.status === 'pending' && new Date() > new Date(dep.expires_at)) {
      await db.run(`UPDATE auto_deposits SET status='expired' WHERE id=$1`, [dep.id]);
      return res.json({ status: 'expired' });
    }
    res.json({ status: dep.status, tx_hash: dep.tx_hash, amount: dep.unique_amt });
  } catch(e) { log("ERROR", e.message); res.status(500).json({error: "Server error. Please try again."}); }
});

// ══════════════════════════════════════════
// AUTO DEPOSIT — Credit helper
// ══════════════════════════════════════════
async function creditAutoDeposit(dep, txHash) {
  try {
    // [RACE GUARD] Only credit if this UPDATE actually changed a row
    // If another process already completed this deposit, rowCount = 0 → skip
    const result = await pool.query(
      `UPDATE auto_deposits SET status='completed', tx_hash=$1 WHERE id=$2 AND status='pending'`,
      [txHash, dep.id]
    );
    if (result.rowCount === 0) {
      console.log(`[SKIP] Deposit ${dep.id} already processed (race guard)`);
      return;
    }
    // Credit balance only after confirmed row lock
    await db.run(`UPDATE users SET balance=balance+$1 WHERE id=$2`, [dep.amount, dep.user_id]); // credit base amount, not unique_amt (which has suffix)
    // Transaction log
    await db.run(
      `INSERT INTO transactions (user_id,type,amount,network,txid,status,note)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [dep.user_id,'deposit',dep.amount,'BEP20',txHash,'approved','Auto-detected']
    );
    // Mark first_deposit task as completed (NO balance reward — exact deposit amount only)
    const taskDone = await db.one(
      `SELECT id FROM tasks WHERE user_id=$1 AND task_key='first_deposit'`, [dep.user_id]
    );
    if (!taskDone) {
      await db.run(
        `INSERT INTO tasks (user_id, task_key, completed, completed_at)
         VALUES ($1,'first_deposit',1,NOW()) ON CONFLICT DO NOTHING`,
        [dep.user_id]
      );
    }
    console.log(`✅ Auto deposit: user=${dep.user_id} base_amt=${dep.amount} unique_amt=${dep.unique_amt} ${dep.network} tx=${txHash}`);
  } catch(e) {
    // Gracefully handle unique constraint (tx_hash duplicate = already credited)
    if (e.message.includes('unique') || e.message.includes('duplicate') || e.message.includes('idx_auto_dep_txhash')) {
      console.log(`[SAFE] TX ${txHash.slice(0,16)} already processed — skipping`);
    } else {
      console.error('[creditAutoDeposit] error:', e.message);
    }
  }
}

// ══════════════════════════════════════════
// BEP20 AUTO DEPOSIT SCANNER
// Polls Moralis every 10s for incoming USDT
// transfers to the platform deposit wallet,
// matches by unique amount, credits balance.
// ══════════════════════════════════════════

let _scanRunning = false;

async function scanBEP20() {
  if (_scanRunning) return;
  _scanRunning = true;

  try {
    const MORALIS_KEY = process.env.MORALIS_API_KEY || '';
    if (!MORALIS_KEY) return;

    // Skip if no pending deposits
    const pending = await db.all(
      `SELECT * FROM auto_deposits
       WHERE dep_type='auto' AND status='pending' AND expires_at > NOW()`
    );
    if (!pending.length) return;

    // Fetch latest 50 BEP20 transfers to deposit wallet
    const url  = `https://deep-index.moralis.io/api/v2.2/${DEPOSIT_WALLET}/erc20/transfers?chain=bsc&limit=50&order=DESC`;
    const data = await httpsGet(url, { 'X-API-Key': MORALIS_KEY });

    if (!data || !Array.isArray(data.result)) {
      if (data && data.message) log('SCANNER', `Moralis error: ${data.message}`);
      return;
    }

    // Keep only incoming USDT transfers
    const transfers = data.result.filter(tx =>
      tx.to_address && tx.to_address.toLowerCase() === DEPOSIT_WALLET &&
      tx.token_address && tx.token_address.toLowerCase() === USDT_CONTRACT
    );

    if (transfers.length) {
      log('SCANNER', `Block: ${transfers[0].block_number} | ${transfers.length} incoming USDT transfer(s)`);
    }

    // Track which tx hashes we process this cycle to avoid double-credit
    const processedHashes = new Set();

    for (const dep of pending) {
      if (dep._matched) continue;

      // Only look at transfers that happened after this deposit was created (2 min buffer)
      const depCreatedMs = new Date(dep.created_at).getTime() - 120000;

      for (const tx of transfers) {
        // Guard: skip if no valid tx hash (Moralis can return null for pending txs)
        if (!tx.transaction_hash || typeof tx.transaction_hash !== 'string') continue;
        if (processedHashes.has(tx.transaction_hash)) continue;
        if (new Date(tx.block_timestamp).getTime() < depCreatedMs) continue;

        // Parse transfer amount (value_decimal preferred, fallback to raw/1e18)
        let txAmt;
        if (tx.value_decimal != null && tx.value_decimal !== '') {
          txAmt = parseFloat(tx.value_decimal);
        } else if (tx.value != null) {
          txAmt = parseFloat(tx.value) / 1e18;
        } else {
          continue;
        }
        if (isNaN(txAmt) || txAmt <= 0) continue;

        // Amount must match within ±$0.02 tolerance
        if (Math.abs(txAmt - dep.unique_amt) > 0.02) continue;

        log('SCANNER', `Deposit found tx: ${tx.transaction_hash.slice(0, 18)}... amt=${txAmt}`);

        // Check expiry before crediting
        if (new Date() > new Date(dep.expires_at)) {
          await db.run(`UPDATE auto_deposits SET status='expired' WHERE id=$1`, [dep.id]);
          log('SCANNER', `Deposit expired: dep=${dep.id} user=${dep.user_id}`);
          dep._matched = true;
          break;
        }

        // Credit the deposit
        log('SCANNER', `User matched: dep=${dep.id} user=${dep.user_id} amt=${dep.unique_amt}`);
        await creditAutoDeposit(dep, tx.transaction_hash);
        log('SCANNER', `Credited: user=${dep.user_id} amount=$${dep.amount}`);

        dep._matched = true;
        processedHashes.add(tx.transaction_hash);
        break;
      }
    }

  } catch(e) {
    log('SCANNER', `Error: ${e.message}`);
  } finally {
    _scanRunning = false;
  }
}

async function startScanners() {
  const MORALIS_KEY = process.env.MORALIS_API_KEY || '';

  if (!MORALIS_KEY) {
    console.warn('[SCANNER] MORALIS_API_KEY not set — auto deposit scanner disabled');
  } else {
    log('SCANNER', 'Auto deposit scanner started (10s interval)');
    setTimeout(scanBEP20, 5000);
    setInterval(scanBEP20, 10000);
  }

  // Withdrawal proof fallback (fires TG proof for approved withdrawals with no tx hash)
  setTimeout(scanWithdrawalFallback, 3 * 60 * 1000);
  setInterval(scanWithdrawalFallback, 2 * 60 * 1000);

  // Auto-expire stale pending deposits
  setInterval(async () => {
    try {
      await db.run(`UPDATE auto_deposits SET status='expired' WHERE status='pending' AND expires_at < NOW()`);
    } catch(e) {}
  }, 60 * 1000);
}

// ══════════════════════════════════════════
// START
// ══════════════════════════════════════════

// ══════════════════════════════════════════
// VIP STATUS API
// ══════════════════════════════════════════

// GET /api/vip-status — full VIP status + progress for current user
app.get('/api/vip-status', userAuth, async (req, res) => {
  try {
    const u = req.tgUser;
    // First pass: compute VIP (uses scanDepth=7 for gate check)
    const { vip, highestTier, activeRefs, isManualOverride, badgeLabel } = await getUserVipStatus(u.id);
    // Second pass: recompute teamDep using ONLY user's current unlocked levels
    const teamDep = await getTeamDeposit(u.id, vip.maxLevels);

    // Build next VIP target
    const currentIdx = VIP_LEVELS.indexOf(vip);
    let nextVip = null;
    let nextProgress = null;

    // If manual override active — skip next VIP progress (not applicable)
    if (!isManualOverride && currentIdx < VIP_LEVELS.length - 1) {
      for (let i = currentIdx + 1; i < VIP_LEVELS.length; i++) {
        if (VIP_LEVELS[i].name.startsWith('VIP')) {
          nextVip = VIP_LEVELS[i];
          break;
        }
      }
      if (nextVip) {
        const reqTier = nextVip.minPlanTier;
        const reqTierIdx = PLAN_TIER_ORDER.indexOf(reqTier);
        const curTierIdx = highestTier ? PLAN_TIER_ORDER.indexOf(highestTier) : -1;
        nextProgress = {
          plan:    { current: highestTier || 'none', required: reqTier, met: curTierIdx >= reqTierIdx },
          refs:    { current: activeRefs, required: nextVip.minRefs, met: activeRefs >= nextVip.minRefs },
          teamDep: { current: +teamDep.toFixed(2), required: nextVip.minTeamDep, met: teamDep >= nextVip.minTeamDep },
        };
      }
    }

    res.json({
      vip_name:          vip.name,
      vip_rates:         vip.rates,
      max_levels:        vip.maxLevels,
      highest_tier:      highestTier || null,
      active_refs:       activeRefs,
      team_deposit:      +teamDep.toFixed(2),
      next_vip:          nextVip ? { name: nextVip.name, minPlanTier: nextVip.minPlanTier, minRefs: nextVip.minRefs, minTeamDep: nextVip.minTeamDep, maxLevels: nextVip.maxLevels, rates: nextVip.rates } : null,
      next_progress:     nextProgress,
      is_manual_override: isManualOverride || false,
      badge_label:       badgeLabel || null,
    });
  } catch(e) { log('ERROR', e.message); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

// GET /api/team-deposit — paginated, searchable, level-filtered team deposit
// Query params: level (1-7), page (default 1), limit (default 15), search (username/name/uid)
app.get('/api/team-deposit', userAuth, async (req, res) => {
  try {
    const u       = req.tgUser;
    const { vip } = await getUserVipStatus(u.id);
    const maxLvl  = vip.maxLevels || 3;

    const filterLvl = parseInt(req.query.level) || 0;   // 0 = all
    const page      = Math.max(1, parseInt(req.query.page) || 1);
    const limit     = Math.min(50, parseInt(req.query.limit) || 15);
    const offset    = (page - 1) * limit;
    const search    = (req.query.search || '').trim().toLowerCase();

    // BFS to build level id maps
    const lvlIds = [];
    let currentIds = [parseInt(u.id)];
    for (let lvl = 0; lvl < maxLvl; lvl++) {
      if (!currentIds.length) { lvlIds.push([]); continue; }
      const rows = await db.all(
        `SELECT id FROM users WHERE referred_by = ANY($1::bigint[])`, [currentIds]
      );
      const nextIds = rows.map(r => parseInt(r.id));
      lvlIds.push(nextIds);
      currentIds = nextIds;
    }

    // Summary: totals per level
    const levelSummary = [];
    let grandTotal = 0;
    let grandMembers = 0;
    let grandActive = 0;

    for (let i = 0; i < lvlIds.length; i++) {
      const ids = lvlIds[i];
      if (!ids.length) {
        levelSummary.push({ level: i+1, count: 0, total: 0, active: 0 });
        continue;
      }
      const r = await db.one(
        `SELECT COALESCE(SUM(CASE WHEN i.status IN ('active','completed') THEN i.amount ELSE 0 END),0) as total,
                COUNT(DISTINCT CASE WHEN i.status='active' THEN i.user_id END) as active
         FROM investments i WHERE i.user_id = ANY($1::bigint[])`,
        [ids]
      );
      const total  = parseFloat(r.total) || 0;
      const active = parseInt(r.active) || 0;
      levelSummary.push({ level: i+1, count: ids.length, total: +total.toFixed(2), active });
      grandTotal   += total;
      grandMembers += ids.length;
      grandActive  += active;
    }

    // Determine which level(s) to fetch members for
    const fetchLevels = filterLvl > 0 && filterLvl <= maxLvl
      ? [filterLvl - 1]          // 0-indexed
      : lvlIds.map((_, i) => i); // all levels

    // Build combined member list with level tag
    let memberRows = [];
    for (const li of fetchLevels) {
      const ids = lvlIds[li];
      if (!ids || !ids.length) continue;

      // Build search filter
      let whereExtra = '';
      const params = [ids];
      if (search) {
        whereExtra = ` AND (LOWER(u.first_name) LIKE $2 OR LOWER(u.username) LIKE $2 OR CAST(u.uid AS TEXT) LIKE $2)`;
        params.push('%' + search + '%');
      }

      const rows = await db.all(
        `SELECT u.id, u.first_name, u.username, u.uid, u.created_at,
                COALESCE(SUM(CASE WHEN i.status IN ('active','completed') THEN i.amount ELSE 0 END),0) as invested,
                COUNT(CASE WHEN i.status='active' THEN 1 END) as active_plans,
                (SELECT plan_name FROM investments WHERE user_id=u.id AND status='active' ORDER BY id DESC LIMIT 1) as top_plan
         FROM users u
         LEFT JOIN investments i ON i.user_id=u.id
         WHERE u.id = ANY($1::bigint[])${whereExtra}
         GROUP BY u.id, u.first_name, u.username, u.uid, u.created_at
         ORDER BY invested DESC`,
        params
      );
      rows.forEach(r => { r._level = li + 1; memberRows.push(r); });
    }

    // Sort by invested desc across levels, then paginate
    memberRows.sort((a, b) => parseFloat(b.invested||0) - parseFloat(a.invested||0));
    const totalFiltered = memberRows.length;
    const paginatedRows = memberRows.slice(offset, offset + limit);

    res.json({
      summary: {
        total_deposit: +grandTotal.toFixed(2),
        total_members: grandMembers,
        active_investors: grandActive,
        max_levels: maxLvl,
        vip_name: vip.name,
      },
      level_summary: levelSummary,
      members: paginatedRows.map(m => ({
        id:          m.id,
        name:        m.first_name || 'User',
        username:    m.username   || null,
        uid:         m.uid        || null,
        level:       m._level,
        invested:    +parseFloat(m.invested||0).toFixed(2),
        active_plans: parseInt(m.active_plans)||0,
        top_plan:    m.top_plan   || null,
        joined:      m.created_at ? String(m.created_at).split('T')[0] : null,
      })),
      pagination: {
        page, limit,
        total: totalFiltered,
        pages: Math.ceil(totalFiltered / limit),
        has_more: offset + limit < totalFiltered,
      },
      filter_level: filterLvl,
    });
  } catch(e) { log('ERROR', e.message); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

// ══════════════════════════════════════════
// LEADERBOARD
// ══════════════════════════════════════════
app.get('/admin/deposit-stats', adminAuth, async (req, res) => {
  try {
    const rows = await db.all(`
      SELECT
        TO_CHAR(created_at, 'HH24') as time,
        SUM(amount) as total
      FROM transactions
      WHERE type='deposit' AND status='approved'
        AND created_at > NOW() - INTERVAL '24 hours'
      GROUP BY TO_CHAR(created_at, 'HH24')
      ORDER BY MIN(created_at) ASC
    `);
    res.json(rows.map(r => ({ time: r.time, total: parseFloat(r.total) })));
  } catch(e) { log("ERROR", e.message); res.status(500).json({ error: "Server error. Please try again." }); }
});

app.get('/leaderboard', async (req, res) => {
  try {
    const rows = await db.all(
      `SELECT first_name, uid, total_earned,
              (SELECT COUNT(DISTINCT i.user_id) FROM investments i JOIN users u2 ON u2.id=i.user_id WHERE u2.referred_by=u.id AND i.status='active') as active_refs
       FROM users u
       WHERE total_earned > 0
       ORDER BY total_earned DESC
       LIMIT 10`
    );
    const board = rows.map((u, i) => ({
      pos:          i + 1,
      name:         maskName(u.first_name),
      uid:          u.uid || '------',
      total_earned: parseFloat(u.total_earned || 0).toFixed(2),
      rank:         getUserRank(u.active_refs)
    }));
    res.json({ leaderboard: board });
  } catch(e) { log('ERROR', e.message); res.status(500).json({error: 'Server error. Please try again.'}); }
});

// ══ TOP EARNERS (top 20) ══
app.get('/api/top-earners', async (req, res) => {
  try {
    const rows = await db.all(`
      SELECT first_name, uid, total_earned,
        (SELECT COUNT(DISTINCT i.user_id) FROM investments i JOIN users u2 ON u2.id=i.user_id WHERE u2.referred_by=u.id AND i.status='active') as active_refs
      FROM users u
      WHERE total_earned > 0
      ORDER BY total_earned DESC
      LIMIT 20
    `);
    const earners = rows.map((u, i) => ({
      pos:          i + 1,
      name:         maskName(u.first_name),
      uid:          u.uid || '------',
      total_earned: parseFloat(u.total_earned || 0).toFixed(2),
      badge:        getUserRank(u.active_refs)
    }));
    res.json({ earners });
  } catch(e) { log('ERROR', e.message); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

// ══ REFERRALS BY LEVEL ══
app.get('/api/referrals/:userId', userAuth, async (req, res) => {
  if (String(req.tgUser.id) !== String(req.params.userId)) return res.status(403).json({ error: 'Forbidden' });
  try {
    const userId = req.params.userId;

    // Get user's real max levels (respects admin override)
    const { vip } = await getUserVipStatus(userId);
    const maxLevels = vip.maxLevels || 3;

    // Build level queries dynamically up to maxLevels
    // Level 1: direct referrals
    // Level N: users referred by level N-1 users
    const refQuery = `
      SELECT u.id, u.first_name as name, u.username, u.uid, u.created_at as joined_at,
        COALESCE((SELECT SUM(c.amount) FROM commissions c WHERE c.user_id=$1 AND c.from_user_id=u.id), 0) as earned,
        EXISTS(SELECT 1 FROM investments i WHERE i.user_id=u.id AND i.status='active') as is_active
      FROM users u WHERE u.referred_by = ANY($2::bigint[]) ORDER BY u.created_at DESC
    `;

    // Walk the tree level by level
    const result = { max_levels: maxLevels };
    let currentIds = [BigInt(userId)];

    for (let lvl = 1; lvl <= maxLevels; lvl++) {
      const rows = await db.all(refQuery, [userId, currentIds]);
      result['level' + lvl] = rows;
      currentIds = rows.map(r => BigInt(r.id));
      if (currentIds.length === 0) break;
    }

    res.json(result);
  } catch(e) { log('ERROR', e.message); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

// ══ ADMIN REFERRAL DETAILS ══
app.get('/admin/referral-details/:userId', adminAuth, async (req, res) => {
  try {
    const userId = req.params.userId;
    const search = (req.query.search || '').toLowerCase();

    const [user, uplineRow, level1, level2, level3] = await Promise.all([
      db.one(`SELECT id, first_name, last_name, username, balance, created_at,
        (SELECT COUNT(*) FROM investments WHERE user_id=$1 AND status='active') as active_plans,
        referred_by
        FROM users WHERE id=$1`, [userId]),
      db.one(`SELECT id, first_name, username FROM users WHERE id=(SELECT referred_by FROM users WHERE id=$1)`, [userId]),
      db.all(`SELECT u.id, u.first_name, u.username, u.balance, u.created_at,
        EXISTS(SELECT 1 FROM investments i WHERE i.user_id=u.id AND i.status='active') as has_plan
        FROM users u WHERE u.referred_by=$1 ORDER BY u.created_at DESC`, [userId]),
      db.all(`SELECT u.id, u.first_name, u.username, u.balance, u.created_at,
        EXISTS(SELECT 1 FROM investments i WHERE i.user_id=u.id AND i.status='active') as has_plan
        FROM users u WHERE u.referred_by IN (SELECT id FROM users WHERE referred_by=$1)
        ORDER BY u.created_at DESC`, [userId]),
      db.all(`SELECT u.id, u.first_name, u.username, u.balance, u.created_at,
        EXISTS(SELECT 1 FROM investments i WHERE i.user_id=u.id AND i.status='active') as has_plan
        FROM users u WHERE u.referred_by IN (
          SELECT id FROM users WHERE referred_by IN (SELECT id FROM users WHERE referred_by=$1)
        ) ORDER BY u.created_at DESC`, [userId]),
    ]);

    const filterFn = search ? (u => 
      (u.username||'').toLowerCase().includes(search) ||
      (u.first_name||'').toLowerCase().includes(search) ||
      String(u.id).includes(search)
    ) : () => true;

    res.json({
      user: user || null,
      upline: uplineRow || null,
      level1: level1.filter(filterFn),
      level2: level2.filter(filterFn),
      level3: level3.filter(filterFn),
    });
  } catch(e) { log('ERROR', e.message); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

// ══ COLLECT COMMISSION ══
app.post('/api/collect-commission', authLimit, userAuth, async (req, res) => {
  try {
    const u = req.tgUser;
    const user = await db.one(`SELECT * FROM users WHERE id=$1`, [u.id]);
    if (!user) return res.status(404).json({error:'Not found'});
    const pending = parseFloat(user.pending_commission || 0);
    if (pending <= 0) return res.status(400).json({error:'No pending commission'});
    // ✅ FIX: Atomic — only collect if pending_commission still > 0 (race condition guard)
    const commResult = await pool.query(
      `UPDATE users SET balance=balance+pending_commission, pending_commission=0
       WHERE id=$1 AND pending_commission > 0 RETURNING pending_commission as collected`,
      [u.id]
    );
    if (commResult.rowCount === 0) return res.status(400).json({error:'No pending commission'});
    const actualCollected = parseFloat(commResult.rows[0].collected || pending);
    // override pending with actual DB value
    const collectedAmt = actualCollected > 0 ? actualCollected : pending;
    await db.run(`UPDATE commissions SET status='collected' WHERE user_id=$1 AND status='pending'`, [u.id]);
    await db.run(`INSERT INTO transactions (user_id,type,amount,status,note) VALUES ($1,$2,$3,$4,$5)`, [u.id,'commission',collectedAmt,'completed','Referral commission collected']);
    res.json({success:true, collected:collectedAmt});
  } catch(e) { log("ERROR", e.message); res.status(500).json({error:"Server error. Please try again."}); }
});


// ── Admin: Get user withdraw address ──
app.get('/admin/user/:id/address', adminAuth, async (req, res) => {
  try {
    const user = await db.one(
      `SELECT id, first_name, username, withdraw_address, address_locked, address_updated_at FROM users WHERE id=$1`,
      [req.params.id]
    );
    if (!user) return res.status(404).json({error:'Not found'});
    res.json({
      user_id: user.id,
      first_name: user.first_name,
      username: user.username,
      address: user.withdraw_address || null,
      locked: !!user.address_locked,
      updated_at: user.address_updated_at || null
    });
  } catch(e) { log('ERROR', e.message); res.status(500).json({error:'Server error. Please try again.'}); }
});

// ── Admin: Change user withdraw address ──
app.post('/admin/user/change-address', adminAuth, async (req, res) => {
  try {
    const { user_id, new_address } = req.body;
    if (!user_id) return res.status(400).json({error:'user_id required'});
    if (!new_address || !isValidBEP20Address(new_address)) {
      return res.status(400).json({error:'Invalid BEP20 address'});
    }

    const user = await db.one(`SELECT withdraw_address FROM users WHERE id=$1`, [user_id]);
    if (!user) return res.status(404).json({error:'User not found'});

    const oldAddress = user.withdraw_address || null;
    const normalizedNew = new_address.trim().toLowerCase();
    const { force_override } = req.body; // admin can pass force_override:true to bypass

    // Check if address already belongs to another user
    const addrOwner = await db.one(
      `SELECT id, first_name, username FROM users WHERE LOWER(withdraw_address)=$1 AND id!=$2`,
      [normalizedNew, user_id]
    );
    if (addrOwner && !force_override) {
      return res.status(400).json({
        error: `Address already belongs to User ID ${addrOwner.id} (@${addrOwner.username || addrOwner.first_name}). Pass force_override:true to override.`,
        conflict_user_id: addrOwner.id,
        conflict_username: addrOwner.username || addrOwner.first_name
      });
    }
    if (addrOwner && force_override) {
      // Clear address from the other user first
      await db.run(
        `UPDATE users SET withdraw_address=NULL, address_locked=FALSE, address_updated_at=NOW() WHERE id=$1`,
        [addrOwner.id]
      );
      log('ADMIN', `Force override: cleared address from user ${addrOwner.id} to assign to ${user_id}`);
    }

    // Update address and keep locked — store lowercase for consistent uniqueness
    const cleanNewAddr = new_address.trim().toLowerCase();
    await db.run(
      `UPDATE users SET withdraw_address=$1, address_locked=TRUE, address_updated_at=NOW() WHERE id=$2`,
      [cleanNewAddr, user_id]
    );

    // Audit log
    await db.run(
      `INSERT INTO address_change_logs (admin_id, user_id, old_address, new_address, action) VALUES ($1,$2,$3,$4,$5)`,
      ['admin', user_id, oldAddress, cleanNewAddr, force_override ? 'force_change' : 'change']
    );

    log('ADMIN', `Address changed for user ${user_id}: ${(oldAddress||'none').slice(0,16)} → ${cleanNewAddr.slice(0,16)}`);
    logSecurity('ADMIN_ADDRESS_CHANGE', {user_id, old: oldAddress, new: cleanNewAddr.slice(0,20), force: !!force_override});
    res.json({success:true});
  } catch(e) { log('ERROR', e.message); res.status(500).json({error:'Server error. Please try again.'}); }
});

// ── Admin: Clear user withdraw address (unlock for re-bind) ──
app.post('/admin/user/clear-address', adminAuth, async (req, res) => {
  try {
    const { user_id } = req.body;
    if (!user_id) return res.status(400).json({error:'user_id required'});

    const user = await db.one(`SELECT withdraw_address FROM users WHERE id=$1`, [user_id]);
    if (!user) return res.status(404).json({error:'User not found'});

    const oldAddress = user.withdraw_address || null;

    await db.run(
      `UPDATE users SET withdraw_address=NULL, address_locked=FALSE, address_updated_at=NOW() WHERE id=$1`,
      [user_id]
    );

    // Audit log
    await db.run(
      `INSERT INTO address_change_logs (admin_id, user_id, old_address, new_address, action) VALUES ($1,$2,$3,$4,$5)`,
      ['admin', user_id, oldAddress, null, 'clear']
    );

    log('ADMIN', `Address cleared for user ${user_id} (old: ${(oldAddress||'none').slice(0,16)})`);
    res.json({success:true, message:'Address cleared. User can now re-bind.'});
  } catch(e) { log('ERROR', e.message); res.status(500).json({error:'Server error. Please try again.'}); }
});

// ── Admin: View address change logs ──
app.get('/admin/address-logs', adminAuth, async (req, res) => {
  try {
    const { user_id, limit=50 } = req.query;
    let q = `SELECT l.*, u.first_name, u.username FROM address_change_logs l LEFT JOIN users u ON u.id=l.user_id WHERE 1=1`;
    const params = [];
    if (user_id) { params.push(user_id); q += ` AND l.user_id=$${params.length}`; }
    params.push(limit); q += ` ORDER BY l.created_at DESC LIMIT $${params.length}`;
    const logs = await db.all(q, params);
    res.json({logs});
  } catch(e) { log('ERROR', e.message); res.status(500).json({error:'Server error. Please try again.'}); }
});



// ══════════════════════════════════════════
// TELEGRAM BOT BROADCAST SYSTEM
// ══════════════════════════════════════════

// GET all broadcasts
app.get('/admin/broadcasts', adminAuth, async (req, res) => {
  try {
    const rows = await db.all(`SELECT * FROM broadcasts ORDER BY created_at DESC LIMIT 20`);
    res.json({broadcasts: rows || []});
  } catch(e) { log('ERROR', e.message); res.status(500).json({error:'Server error. Please try again.'}); }
});

// POST create broadcast
app.post('/admin/broadcasts', adminAuth, async (req, res) => {
  try {
    const { title, message, emoji, btn_text, schedule_at } = req.body;
    if (!title || !message) return res.status(400).json({error:'Title and message required'});

    // Count total users
    const totalRow = await db.one(`SELECT COUNT(*) as cnt FROM users WHERE is_banned != 1 OR is_banned IS NULL`);
    const total = parseInt(totalRow?.cnt || 0);

    const r = await pool.query(
      `INSERT INTO broadcasts (title, message, emoji, btn_text, total, schedule_at, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
      [title, message, emoji||'📢', btn_text||'Open App', total,
       schedule_at || null, schedule_at ? 'scheduled' : 'pending']
    );
    const id = r.rows[0].id;
    log('ADMIN', `Broadcast created id=${id} total=${total}`);

    // If no schedule, send immediately
    if (!schedule_at) {
      sendBroadcastNow(id).catch(e => log('BROADCAST', 'Error: ' + e.message));
    }

    res.json({success:true, id, total});
  } catch(e) { log('ERROR', e.message); res.status(500).json({error:'Server error. Please try again.'}); }
});

// DELETE broadcast
app.delete('/admin/broadcasts/:id', adminAuth, async (req, res) => {
  try {
    await db.run(`DELETE FROM broadcasts WHERE id=$1`, [req.params.id]);
    res.json({success:true});
  } catch(e) { log('ERROR', e.message); res.status(500).json({error:'Server error. Please try again.'}); }
});

// POST send now (manual trigger)
app.post('/admin/broadcasts/:id/send', adminAuth, async (req, res) => {
  try {
    const bc = await db.one(`SELECT * FROM broadcasts WHERE id=$1`, [req.params.id]);
    if (!bc) return res.status(404).json({error:'Not found'});
    if (bc.status === 'sending') return res.status(400).json({error:'Already sending'});
    if (bc.status === 'done') return res.status(400).json({error:'Already sent'});
    res.json({success:true, message:'Broadcast started'});
    sendBroadcastNow(req.params.id).catch(e => log('BROADCAST', 'Error: ' + e.message));
  } catch(e) { log('ERROR', e.message); res.status(500).json({error:'Server error. Please try again.'}); }
});

// Background broadcast sender
async function sendBroadcastNow(broadcastId) {
  const bc = await db.one(`SELECT * FROM broadcasts WHERE id=$1`, [broadcastId]);
  if (!bc) return;

  // Mark as sending
  await db.run(`UPDATE broadcasts SET status='sending', started_at=NOW() WHERE id=$1`, [broadcastId]);
  log('BROADCAST', `Starting broadcast id=${broadcastId} title="${bc.title}"`);

  // Get all users
  const users = await db.all(`SELECT id FROM users WHERE is_banned != 1 OR is_banned IS NULL`);
  const total = users.length;

  let sent = 0, failed = 0;

  const WEBAPP_URL = process.env.WEBAPP_URL || 'https://myusdtapp.xyz/';

  for (const user of users) {
    try {
      const keyboard = {
        inline_keyboard: [[
          { text: '🚀 ' + (bc.btn_text || 'Open App'), web_app: { url: WEBAPP_URL } }
        ]]
      };

      const text = (bc.emoji || '📢') + ' <b>' + bc.title + '</b>\n\n' + bc.message;

      // Use Node built-in https (works on all Node versions)
      const postData = JSON.stringify({
        chat_id: user.id, text, parse_mode: 'HTML', reply_markup: keyboard
      });
      await new Promise((resolve) => {
        const https = require('https');
        const req = https.request({
          hostname: 'api.telegram.org',
          path: `/bot${BOT_TOKEN}/sendMessage`,
          method: 'POST',
          headers: {'Content-Type':'application/json','Content-Length':Buffer.byteLength(postData)}
        }, (res) => {
          let body = '';
          res.on('data', d => body += d);
          res.on('end', () => {
            try { const d = JSON.parse(body); if (d.ok) sent++; else failed++; }
            catch(e) { failed++; }
            resolve();
          });
        });
        req.on('error', () => { failed++; resolve(); });
        req.write(postData);
        req.end();
      });
    } catch(e) { failed++; }

    // Update progress every 20 users
    if ((sent + failed) % 20 === 0) {
      await db.run(
        `UPDATE broadcasts SET sent=$1, failed=$2 WHERE id=$3`,
        [sent, failed, broadcastId]
      ).catch(()=>{});
    }

    // Rate limit — Telegram allows ~30 msg/sec
    await new Promise(r => setTimeout(r, 40));
  }

  // Final update
  await db.run(
    `UPDATE broadcasts SET status='done', finished_at=NOW(), sent=$1, failed=$2, total=$3 WHERE id=$4`,
    [sent, failed, total, broadcastId]
  );
  log('BROADCAST', `Done id=${broadcastId} sent=${sent} failed=${failed} total=${total}`);
}

// Cron: check scheduled broadcasts every minute
setInterval(async () => {
  try {
    // Atomic claim: only pick up if still 'scheduled' — prevents double-send
    const claimed = await pool.query(
      `UPDATE broadcasts SET status='sending', started_at=NOW()
       WHERE status='scheduled' AND schedule_at <= NOW()
       RETURNING id`
    );
    for (const b of (claimed.rows||[])) {
      sendBroadcastNow(b.id).catch(e => log('BROADCAST', 'Scheduled error: ' + e.message));
    }
  } catch(e) {}
}, 60000);

// ══════════════════════════════════════════
// NOTICE / BROADCAST SYSTEM
// ══════════════════════════════════════════

// GET active notice for user
app.get('/api/notice', userAuth, async (req, res) => {
  try {
    const u = req.tgUser;
    const now = new Date().toISOString();

    // Get active notice (scheduled and not expired)
    const notice = await db.one(`
      SELECT * FROM notices
      WHERE is_active = TRUE
        AND (schedule_at IS NULL OR schedule_at <= NOW())
        AND (expire_at IS NULL OR expire_at > NOW())
      ORDER BY created_at DESC LIMIT 1
    `);
    if (!notice) return res.json({ notice: null });

    // Check repeat mode
    if (notice.repeat_mode === 'once') {
      const seen = await db.one(
        `SELECT id FROM notice_stats WHERE notice_id=$1 AND user_id=$2 AND action='seen'`,
        [notice.id, u.id]
      );
      if (seen) return res.json({ notice: null }); // already seen once
    } else if (notice.repeat_mode === 'daily') {
      const seen = await db.one(
        `SELECT id FROM notice_stats WHERE notice_id=$1 AND user_id=$2 AND action='seen' AND created_at > NOW() - INTERVAL '24 hours'`,
        [notice.id, u.id]
      );
      if (seen) return res.json({ notice: null });
    }
    // 'every_login' = always show

    res.json({ notice });
  } catch(e) { log('ERROR', e.message); res.status(500).json({error:'Server error. Please try again.'}); }
});

// POST track notice action (seen/click/dismiss)
app.post('/api/notice/track', userAuth, async (req, res) => {
  try {
    const u = req.tgUser;
    const { notice_id, action } = req.body;
    if (!notice_id || !action) return res.status(400).json({error:'Invalid'});
    await pool.query(
      `INSERT INTO notice_stats (notice_id, user_id, action) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
      [notice_id, u.id, action]
    );
    res.json({success:true});
  } catch(e) { log('ERROR', e.message); res.status(500).json({error:'Server error. Please try again.'}); }
});

// ── ADMIN NOTICE ROUTES ──

// GET all notices
app.get('/admin/notices', adminAuth, async (req, res) => {
  try {
    const notices = await db.all(`SELECT * FROM notices ORDER BY created_at DESC`);
    // Get stats for each
    const withStats = await Promise.all((notices||[]).map(async (n) => {
      const stats = await pool.query(
        `SELECT action, COUNT(*) as cnt FROM notice_stats WHERE notice_id=$1 GROUP BY action`,
        [n.id]
      );
      const s = {};
      (stats.rows||[]).forEach(r => { s[r.action] = parseInt(r.cnt); });
      return { ...n, stats: { seen: s.seen||0, click: s.click||0, dismiss: s.dismiss||0 } };
    }));
    res.json({notices: withStats});
  } catch(e) { log('ERROR', e.message); res.status(500).json({error:'Server error. Please try again.'}); }
});

// POST create notice
app.post('/admin/notices', adminAuth, async (req, res) => {
  try {
    const { title, message, emoji, btn_text, btn_link, is_active, repeat_mode, schedule_at, expire_at, poster_image } = req.body;
    if (!title || !message) return res.status(400).json({error:'Title and message required'});

    // Validate poster_image if provided (must be base64 data URL, max 2MB)
    if (poster_image && poster_image.length > 2 * 1024 * 1024 * 1.37) {
      return res.status(400).json({error:'Poster image too large (max 2MB)'});
    }
    if (poster_image && !poster_image.startsWith('data:image/')) {
      return res.status(400).json({error:'Invalid image format'});
    }

    // Only one active notice at a time
    if (is_active) {
      await db.run(`UPDATE notices SET is_active=FALSE`);
    }

    const r = await pool.query(
      `INSERT INTO notices (title, message, emoji, btn_text, btn_link, is_active, repeat_mode, schedule_at, expire_at, poster_image)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
      [title, message, emoji||'📢', btn_text||'', btn_link||'', !!is_active,
       repeat_mode||'once',
       schedule_at || null,
       expire_at || null,
       poster_image || null]
    );
    log('ADMIN', `Notice created id=${r.rows[0].id} title="${title}" active=${is_active}`);
    res.json({success:true, id: r.rows[0].id});
  } catch(e) { log('ERROR', e.message); res.status(500).json({error:'Server error. Please try again.'}); }
});

// PUT update notice
app.put('/admin/notices/:id', adminAuth, async (req, res) => {
  try {
    const { title, message, emoji, btn_text, btn_link, is_active, repeat_mode, schedule_at, expire_at, poster_image } = req.body;
    const id = req.params.id;

    // Validate poster if provided
    if (poster_image && poster_image.length > 2 * 1024 * 1024 * 1.37) {
      return res.status(400).json({error:'Poster image too large (max 2MB)'});
    }
    if (poster_image && !poster_image.startsWith('data:image/')) {
      return res.status(400).json({error:'Invalid image format'});
    }

    if (is_active) {
      await db.run(`UPDATE notices SET is_active=FALSE WHERE id!=$1`, [id]);
    }

    // Only update poster_image if provided (null = keep existing, '' = clear)
    const posterClause = poster_image !== undefined
      ? ', poster_image=$10'
      : '';
    const params = [title, message, emoji||'📢', btn_text||'', btn_link||'', !!is_active,
       repeat_mode||'once', schedule_at||null, expire_at||null];
    if (poster_image !== undefined) params.push(poster_image || null);
    params.push(id);

    await pool.query(
      `UPDATE notices SET title=$1, message=$2, emoji=$3, btn_text=$4, btn_link=$5,
       is_active=$6, repeat_mode=$7, schedule_at=$8, expire_at=$9${posterClause}, updated_at=NOW()
       WHERE id=$${params.length}`,
      params
    );
    log('ADMIN', `Notice updated id=${id}`);
    res.json({success:true});
  } catch(e) { log('ERROR', e.message); res.status(500).json({error:'Server error. Please try again.'}); }
});

// DELETE notice
app.delete('/admin/notices/:id', adminAuth, async (req, res) => {
  try {
    await db.run(`DELETE FROM notice_stats WHERE notice_id=$1`, [req.params.id]);
    await db.run(`DELETE FROM notices WHERE id=$1`, [req.params.id]);
    log('ADMIN', `Notice deleted id=${req.params.id}`);
    res.json({success:true});
  } catch(e) { log('ERROR', e.message); res.status(500).json({error:'Server error. Please try again.'}); }
});

// PATCH toggle active
app.patch('/admin/notices/:id/toggle', adminAuth, async (req, res) => {
  try {
    const id = req.params.id;
    const notice = await db.one(`SELECT is_active FROM notices WHERE id=$1`, [id]);
    if (!notice) return res.status(404).json({error:'Not found'});
    const newState = !notice.is_active;
    if (newState) await db.run(`UPDATE notices SET is_active=FALSE`);
    await db.run(`UPDATE notices SET is_active=$1, updated_at=NOW() WHERE id=$2`, [newState, id]);
    res.json({success:true, is_active: newState});
  } catch(e) { log('ERROR', e.message); res.status(500).json({error:'Server error. Please try again.'}); }
});

// GET notice stats
app.get('/admin/notices/:id/stats', adminAuth, async (req, res) => {
  try {
    const totalUsers = await db.one(`SELECT COUNT(*) as cnt FROM users`);
    const stats = await pool.query(
      `SELECT action, COUNT(DISTINCT user_id) as cnt FROM notice_stats WHERE notice_id=$1 GROUP BY action`,
      [req.params.id]
    );
    const s = {};
    (stats.rows||[]).forEach(r => { s[r.action] = parseInt(r.cnt); });
    res.json({
      total_users: parseInt(totalUsers?.cnt||0),
      seen: s.seen||0,
      click: s.click||0,
      dismiss: s.dismiss||0
    });
  } catch(e) { log('ERROR', e.message); res.status(500).json({error:'Server error. Please try again.'}); }
});

// ══════════════════════════════════════════
// SPECIAL USER OVERRIDE SYSTEM (Admin Only)
// ══════════════════════════════════════════

// ── Search users for override panel ──
app.get('/admin/special/search', adminAuth, async (req, res) => {
  try {
    const q = (req.query.q || '').trim();
    if (!q) return res.json({ users: [] });
    const like = '%' + q + '%';
    const rows = await db.all(
      `SELECT id, first_name, last_name, username, vip_level,
              manual_commission_enabled, manual_plan_tier, manual_vip_level,
              manual_override_expiry, manual_badge_label
       FROM users
       WHERE CAST(id AS TEXT) LIKE $1
          OR LOWER(username) LIKE LOWER($2)
          OR LOWER(first_name || ' ' || COALESCE(last_name,'')) LIKE LOWER($3)
       LIMIT 20`,
      [like, like, like]
    );
    res.json({ users: rows });
  } catch(e) { log('ERROR', e.message); res.status(500).json({ error: 'Server error' }); }
});

// ── Get override status for a user ──
app.get('/admin/special/user/:id', adminAuth, async (req, res) => {
  try {
    const row = await db.one(
      `SELECT id, first_name, last_name, username, vip_level,
              manual_commission_enabled, manual_plan_tier, manual_vip_level,
              manual_override_expiry, manual_badge_label
       FROM users WHERE id=$1`, [req.params.id]
    );
    if (!row) return res.status(404).json({ error: 'User not found' });
    res.json({ user: row });
  } catch(e) { log('ERROR', e.message); res.status(500).json({ error: 'Server error' }); }
});

// ── Set override for a user ──
app.post('/admin/special/set', adminAuth, async (req, res) => {
  try {
    const {
      user_id,
      manual_commission_enabled,
      manual_plan_tier,
      manual_vip_level,
      manual_override_expiry,
      manual_badge_label
    } = req.body;

    if (!user_id) return res.status(400).json({ error: 'user_id required' });

    const user = await db.one(`SELECT id, first_name FROM users WHERE id=$1`, [user_id]);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Build expiry
    let expiry = null;
    if (manual_override_expiry && manual_override_expiry !== 'permanent') {
      expiry = new Date(manual_override_expiry).toISOString();
      if (isNaN(new Date(expiry))) expiry = null;
    }

    // Validate enums
    const VALID_PLAN_TIERS = ['none','bronze','silver','gold','platinum','diamond','titanium','quantum'];
    const VALID_VIP_LEVELS = ['none','Member','Bronze','Silver','Gold','VIP 1','VIP 2','VIP 3','VIP 4'];
    const planTier = VALID_PLAN_TIERS.includes(manual_plan_tier) ? manual_plan_tier : 'none';
    const vipLevel = VALID_VIP_LEVELS.includes(manual_vip_level) ? manual_vip_level : 'none';
    const commEnabled = !!manual_commission_enabled;
    const badgeLabel = (manual_badge_label || '').substring(0, 50);

    // Get old values for log
    const old = await db.one(
      `SELECT manual_commission_enabled, manual_plan_tier, manual_vip_level,
              manual_override_expiry, manual_badge_label FROM users WHERE id=$1`, [user_id]
    );

    await db.run(
      `UPDATE users SET
        manual_commission_enabled=$1,
        manual_plan_tier=$2,
        manual_vip_level=$3,
        manual_override_expiry=$4,
        manual_badge_label=$5
       WHERE id=$6`,
      [commEnabled, planTier === 'none' ? null : planTier, vipLevel === 'none' ? null : vipLevel,
       expiry, badgeLabel || null, user_id]
    );

    // Log the action
    await db.run(
      `INSERT INTO override_logs (admin_action, target_user, field, old_value, new_value, note)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [
        'SET_OVERRIDE', user_id, 'all',
        JSON.stringify({ comm: old.manual_commission_enabled, plan: old.manual_plan_tier, vip: old.manual_vip_level }),
        JSON.stringify({ comm: commEnabled, plan: planTier, vip: vipLevel, expiry, badge: badgeLabel }),
        `Admin set override for user ${user_id} (${user.first_name})`
      ]
    );

    log('ADMIN', `Override SET user=${user_id} comm=${commEnabled} plan=${planTier} vip=${vipLevel} expiry=${expiry}`);
    res.json({ success: true });
  } catch(e) { log('ERROR', e.message); res.status(500).json({ error: 'Server error' }); }
});

// ── Remove all overrides for a user ──
app.post('/admin/special/remove', adminAuth, async (req, res) => {
  try {
    const { user_id } = req.body;
    if (!user_id) return res.status(400).json({ error: 'user_id required' });

    const old = await db.one(
      `SELECT manual_commission_enabled, manual_plan_tier, manual_vip_level FROM users WHERE id=$1`, [user_id]
    );

    await db.run(
      `UPDATE users SET
        manual_commission_enabled=FALSE,
        manual_plan_tier=NULL,
        manual_vip_level=NULL,
        manual_override_expiry=NULL,
        manual_badge_label=NULL
       WHERE id=$1`, [user_id]
    );

    await db.run(
      `INSERT INTO override_logs (admin_action, target_user, field, old_value, new_value, note)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [
        'REMOVE_OVERRIDE', user_id, 'all',
        JSON.stringify({ comm: old.manual_commission_enabled, plan: old.manual_plan_tier, vip: old.manual_vip_level }),
        'null',
        `Admin removed all overrides for user ${user_id}`
      ]
    );

    log('ADMIN', `Override REMOVED user=${user_id}`);
    res.json({ success: true });
  } catch(e) { log('ERROR', e.message); res.status(500).json({ error: 'Server error' }); }
});

// ── Get override action log ──
app.get('/admin/special/logs', adminAuth, async (req, res) => {
  try {
    const rows = await db.all(
      `SELECT ol.*, u.first_name, u.username
       FROM override_logs ol
       LEFT JOIN users u ON ol.target_user = u.id
       ORDER BY ol.created_at DESC LIMIT 100`
    );
    res.json({ logs: rows });
  } catch(e) { log('ERROR', e.message); res.status(500).json({ error: 'Server error' }); }
});

// ══════════════════════════════════════════
// GLOBAL ERROR HANDLER
// ══════════════════════════════════════════
app.use((err, req, res, next) => {
  // CORS error
  if (err.message === 'CORS not allowed') {
    return res.status(403).json({ error: 'Origin not allowed' });
  }
  log('ERROR', `${req.method} ${req.path} — ${err.message}`);
  if (!res.headersSent) {
    // ✅ FIX: Never expose internal error details to client
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ══════════════════════════════════════════
// START
// ══════════════════════════════════════════
setupDB().then(async () => {
  await startScanners();
  app.listen(PORT, () => {
    console.log(`✅ Server on port ${PORT} — Neon PostgreSQL connected`);

    // ── SELF-PING (Render sleep prevent) ──
    const SELF_URL = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
    setInterval(() => {
      fetch(SELF_URL + '/health')
        .then(r => console.log(`[ping] ✅ ${r.status}`))
        .catch(e => console.warn(`[ping] ⚠️ ${e.message}`));
    }, 5 * 60 * 1000); // every 5 minutes
    console.log(`[ping] Self-ping started → ${SELF_URL}/health`);
  });
}).catch(e => {
  console.error('DB setup failed:', e);
  process.exit(1);
});
