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
const depositLimit  = rateLimit(10,  60_000);   // 10/min
const verifyLimit   = rateLimit(5,   60_000);   // 5/min
const withdrawLimit = rateLimit(3,   60_000);   // 3/min

// ══════════════════════════════════════════
// AUTO DEPOSIT SCANNER CONFIG
// ══════════════════════════════════════════
const MORALIS_KEY         = process.env.MORALIS_API_KEY || '';
const DEPOSIT_WALLET      = (process.env.DEPOSIT_WALLET || '0x2abdcF2FB8D7088396b69801A3f7294BaF2d8148').toLowerCase();
const USDT_CONTRACT       = (process.env.USDT_CONTRACT  || '0x55d398326f99059fF775485246999027B3197955').toLowerCase();
const BEP20_WALLET        = DEPOSIT_WALLET;
const BEP20_USDT_CONTRACT = USDT_CONTRACT;

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

const BOT_TOKEN    = process.env.BOT_TOKEN    || "YOUR_BOT_TOKEN";
const ADMIN_SECRET = process.env.ADMIN_SECRET || "admin123";
const DATABASE_URL = process.env.DATABASE_URL || "postgresql://neondb_owner:npg_4IVJ1PZzcjnW@ep-long-art-anucops0-pooler.c-6.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require";

// ── CORS — allow Netlify frontend + Telegram ──────
const ALLOWED_ORIGIN = process.env.FRONTEND_URL || null; // e.g. https://yourapp.netlify.app
const corsConfig = {
  origin: (origin, cb) => {
    // Allow: no origin (server-to-server, mobile), allowed domain, or any if not set
    if (!origin || !ALLOWED_ORIGIN || origin === ALLOWED_ORIGIN) return cb(null, true);
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
      expires_at TIMESTAMP DEFAULT (NOW() + INTERVAL '15 minutes')
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
      {key:'first_deposit',  icon:'💰', name:'Make your first deposit',     reward:3,   sort:4},
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
    db.run(`ALTER TABLE auto_deposits ADD COLUMN IF NOT EXISTS dep_type TEXT DEFAULT 'auto'`),
    db.run(`ALTER TABLE transactions ADD COLUMN IF NOT EXISTS approved_at TIMESTAMP`),
    db.run(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active_ref BOOLEAN DEFAULT FALSE`),
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
  ]);

  console.log('✅ Database ready (Neon PostgreSQL)');
}

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  console.error('Unhandled rejection:', err.message);
});

async function getSetting(key) {
  const r = await db.one(`SELECT value FROM settings WHERE key=$1`, [key]);
  return r ? r.value : null;
}


// ── Rank + UID helpers ────────────────────
function getUserRank(activeRefs) {
  const n = parseInt(activeRefs) || 0;
  if (n >= 20) return 'VIP 5';
  if (n >= 10) return 'VIP 4';
  if (n >= 5)  return 'VIP 3';
  if (n >= 3)  return 'VIP 2';
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
  const n = (planName || '').toLowerCase();
  if (n.includes('quantum'))  return 20;
  if (n.includes('titanium')) return 10;
  if (n.includes('diamond'))  return 3;
  if (n.includes('platinum')) return 1;
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
function verifyTg(initData) {
  try {
    const p = new URLSearchParams(initData);
    const hash = p.get('hash'); p.delete('hash');
    const arr = []; p.forEach((v,k) => arr.push(`${k}=${v}`)); arr.sort();
    const secret = crypto.createHmac('sha256','WebAppData').update(BOT_TOKEN).digest();
    return crypto.createHmac('sha256',secret).update(arr.join('\n')).digest('hex') === hash;
  } catch { return false; }
}

function userAuth(req, res, next) {
  const initData = req.headers['x-telegram-init-data'] || req.body?.initData;
if (!initData) {
  req.tgUser = { id: req.body.user_id || 123456 };
  return next();
}
  // Always try to parse user data - skip strict verification
  try {
    const p = new URLSearchParams(initData);
    const userStr = p.get('user');
    req.tgUser = userStr ? JSON.parse(userStr) : null;
  } catch { req.tgUser = null; }
  return next();
}

function adminAuth(req, res, next) {
  const secret = req.headers['x-admin-secret'] || req.body?.adminSecret;
  if (secret !== ADMIN_SECRET) return res.status(403).json({error:'Unauthorized'});
  next();
}

// ══════════════════════════════════════════
// USER ROUTES
// ══════════════════════════════════════════
app.post('/api/auth', async (req, res) => {
  try {
    // Get user from any source
    let u = req.body?.tgUser || req.body?.user || null;
    if (!u) {
      const raw = req.headers['x-telegram-init-data'] || req.body?.initData || '';
      if (raw && raw.length > 10) {
        try {
          const p = new URLSearchParams(raw);
          const us = p.get('user');
          if (us) u = JSON.parse(us);
        } catch(e) {}
      }
    }
    if (!u || !u.id) return res.status(400).json({error:'No user data'});

    const uid      = u.id;
    const refCode  = 'REF' + uid;
    const ref      = req.body?.ref || null;
    const refById  = ref && String(ref).startsWith('REF') ? parseInt(String(ref).replace('REF','')) || null : null;
    const finalRef = (refById && refById !== uid) ? refById : null;

    // Check pending ref
    let pendingRef = finalRef;
    if (!pendingRef) {
      const pr = await db.one('SELECT ref_code FROM pending_refs WHERE user_id=$1', [uid]);
      if (pr) {
        const prid = parseInt(String(pr.ref_code).replace('REF',''));
        if (prid && prid !== uid) pendingRef = prid;
      }
    }

    // Upsert user
    await db.run(`
      INSERT INTO users (id,first_name,last_name,username,language,is_premium,ref_code,referred_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      ON CONFLICT (id) DO UPDATE SET
        first_name=EXCLUDED.first_name,
        last_name=EXCLUDED.last_name,
        username=EXCLUDED.username,
        language=EXCLUDED.language,
        is_premium=EXCLUDED.is_premium,
        referred_by=CASE WHEN users.referred_by IS NULL AND $8::BIGINT IS NOT NULL THEN $8::BIGINT ELSE users.referred_by END
    `, [uid, u.first_name||'', u.last_name||'', u.username||'', u.language_code||'', u.is_premium?1:0, refCode, pendingRef]);

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
    console.error('Auth error:', e.message);
    res.status(500).json({error: e.message});
  }
});

app.get('/api/user/:id', async (req, res) => {
  try {
    console.log('Fetching user:', req.params.id);
    let user = await db.one(`SELECT * FROM users WHERE id=$1`, [req.params.id]);
    // Auto-create user if not exists (handles race condition)
    if (!user) {
      const uid = req.params.id;
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
      db.all(`SELECT id,first_name,username,created_at FROM users WHERE referred_by=$1`, [req.params.id]),
      db.all(`SELECT * FROM plans WHERE is_active=1 ORDER BY id`),
      db.all(`SELECT * FROM settings`),
      db.one(`SELECT COUNT(*) as cnt FROM users WHERE referred_by=$1 AND is_active_ref=TRUE`, [req.params.id]),
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

    // Add commission data to user
    const userWithComm = {
      ...user,
      pending_commission: parseFloat(user.pending_commission || 0),
      total_commission:   parseFloat(user.total_commission   || 0),
      is_deposit_blocked: user.blocked_until && new Date() < new Date(user.blocked_until) ? 1 : 0,
    };
    userWithComm.rank   = getUserRank(activeReferrals);
    userWithComm.active_referrals = activeReferrals;
    res.json({user: userWithComm, investments, transactions, tasks, referrals, plans, settings, active_referrals: activeReferrals});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/api/invest', userAuth, async (req, res) => {
  try {
    const u = req.tgUser;
    const {plan_id, amount} = req.body;
    const user = await db.one(`SELECT * FROM users WHERE id=$1`, [u.id]);
    if (!user) return res.status(404).json({error:'Not found'});
    if (user.is_banned) return res.status(403).json({error:'banned'});

    const plan = await db.one(`SELECT * FROM plans WHERE id=$1 AND is_active=1`, [plan_id]);
    if (!plan) return res.status(404).json({error:'Plan not found'});
    if (amount < plan.min_amt) return res.status(400).json({error:`Min $${plan.min_amt}`});
    if (amount > plan.max_amt) return res.status(400).json({error:`Max $${plan.max_amt}`});
    if (user.balance < amount) return res.status(400).json({error:'Insufficient balance'});

    // [PLAN UNLOCK] Check active referral requirement (backend safety — cannot bypass)
    const refReq = getPlanReferralReq(plan.name);
    if (refReq > 0) {
      const activeRefs = await db.one(
        `SELECT COUNT(*) as cnt FROM users WHERE referred_by=$1 AND is_active_ref=TRUE`,
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
      [u.id, plan.emoji+' '+plan.name, amount, plan.daily_pct, daily, plan.duration]
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

    // Distribute referral commissions (3 levels)
    try {
      const settingRows = await db.all(`SELECT * FROM settings`);
      const sMap = settingRows.reduce((a,r) => ({...a,[r.key]:r.value}), {});
      const pcts = [
        parseFloat(sMap.ref_lvl1_pct || 8) / 100,
        parseFloat(sMap.ref_lvl2_pct || 3) / 100,
        parseFloat(sMap.ref_lvl3_pct || 1) / 100
      ];
      let currentId = u.id;
      for (let lvl = 0; lvl < 3; lvl++) {
        const row = await db.one(`SELECT referred_by FROM users WHERE id=$1`, [currentId]);
        if (!row || !row.referred_by) break;
        const referrerId = row.referred_by;
        const comm = +(amount * pcts[lvl]).toFixed(4);
        await db.run(`UPDATE users SET pending_commission=pending_commission+$1, total_commission=total_commission+$1 WHERE id=$2`, [comm, referrerId]);
        await db.run(`INSERT INTO commissions (user_id,from_user_id,level,amount) VALUES ($1,$2,$3,$4)`, [referrerId, u.id, lvl+1, comm]);
        currentId = referrerId;
      }
    } catch(e) { console.log('Commission error:', e.message); }

    res.json({success:true, daily_earn:daily});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/api/deposit', userAuth, async (req, res) => {
  try {
    const u = req.tgUser;
    const {amount, network, txid} = req.body;
    const minDep = parseFloat(await getSetting('deposit_min') || 5);
    if (amount < minDep) return res.status(400).json({error:`Min $${minDep}`});
    await db.run(
      `INSERT INTO transactions (user_id,type,amount,network,txid) VALUES ($1,$2,$3,$4,$5)`,
      [u.id,'deposit',amount,network,txid]
    );
    res.json({success:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/api/withdraw', withdrawLimit, userAuth, async (req, res) => {
  try {
    const u = req.tgUser;
    const { amount, address } = req.body;
    const network = 'BEP20';

    const user = await db.one(`SELECT * FROM users WHERE id=$1`, [u.id]);
    if (!user) return res.status(404).json({error:'Not found'});
    if (user.is_banned) return res.status(403).json({error:'banned'});

    // [NEW] Block check
    const blockMsg = await checkBlocked(u.id);
    if (blockMsg) return res.status(429).json({error: blockMsg});

    // [IMPROVED] Validations
    const minW   = parseFloat(await getSetting('withdraw_min') || 2);
    const maxW   = parseFloat(await getSetting('withdraw_max') || 10000);
    const feePct = parseFloat(await getSetting('withdraw_fee_pct') || 0);
    const amt    = parseFloat(amount);

    if (!amt || amt < minW) {
      log('WITHDRAW', `User ${u.id} rejected: amount too low (${amt})`);
      return res.status(400).json({error:`Minimum withdrawal is $${minW} USDT`});
    }
    if (amt > maxW) return res.status(400).json({error:`Maximum withdrawal is $${maxW}`});
    if (!address || !isValidBEP20Address(address)) {
      log('WITHDRAW', `User ${u.id} rejected: invalid address format`);
      return res.status(400).json({error:'Invalid BEP20 wallet address (must start with 0x, 42 chars)'});
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
    // [COOLDOWN] 5 min between withdrawal requests
    const lastWith = await db.one(
      `SELECT created_at FROM transactions WHERE user_id=$1 AND type='withdraw' ORDER BY created_at DESC LIMIT 1`,
      [u.id]
    );
    if (lastWith) {
      const minsAgo = (Date.now() - new Date(lastWith.created_at).getTime()) / 60000;
      if (minsAgo < 5) {
        const wait = Math.ceil(5 - minsAgo);
        return res.status(429).json({error:`Please wait ${wait} minute(s) before next withdrawal request`});
      }
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
    log('WITHDRAW', `User ${u.id} requested $${amt} to ${address.trim().slice(0,16)}... fee=$${fee}`);
    res.json({success:true, fee, message:'Withdrawal submitted. Processing time: 0–24 hours.'});
  } catch(e) { res.status(500).json({error:e.message}); }
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
    await db.run(
      `UPDATE users SET balance=balance+$1, total_earned=total_earned+$1, today_earned=today_earned+$1 WHERE id=$2`,
      [earn, u.id]
    );
    await db.run(
      `UPDATE investments SET days_done=days_done+1, last_collect=NOW() WHERE id=$1`,
      [inv.id]
    );
    await db.run(
      `INSERT INTO transactions (user_id,type,amount,status,note) VALUES ($1,$2,$3,$4,$5)`,
      [u.id,'earn',earn,'completed',`Daily: ${inv.plan_name}`]
    );
    if (inv.days_done+1 >= inv.days_total) {
      await db.run(`UPDATE investments SET status='completed' WHERE id=$1`, [inv.id]);
    }
    res.json({success:true, earned:earn});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/api/task/complete', userAuth, async (req, res) => {
  try {
    const u = req.tgUser;
    const {task_key, reward} = req.body;
    const ex = await db.one(`SELECT * FROM tasks WHERE user_id=$1 AND task_key=$2`, [u.id, task_key]);
    if (ex?.completed) return res.status(400).json({error:'Already done'});

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

    await db.run(
      `INSERT INTO tasks (user_id,task_key,completed,completed_at) VALUES ($1,$2,1,NOW()) ON CONFLICT (user_id,task_key) DO UPDATE SET completed=1`,
      [u.id, task_key]
    );
    await db.run(`UPDATE users SET balance=balance+$1, total_earned=total_earned+$1 WHERE id=$2`, [reward, u.id]);
    await db.run(
      `INSERT INTO transactions (user_id,type,amount,status,note) VALUES ($1,$2,$3,$4,$5)`,
      [u.id, 'task_reward', reward, 'completed', 'Task: ' + task_key]
    );
    res.json({success:true});
  } catch(e) { res.status(500).json({error:e.message}); }
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
  } catch(e) { res.status(500).json({error:e.message}); }
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
    const {user_id, ref_code} = req.body;
    if (!user_id || !ref_code) return res.json({success:false});
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
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ══════════════════════════════════════════
// ADMIN ROUTES
// ══════════════════════════════════════════
app.get('/admin/stats', adminAuth, async (req, res) => {
  try {
    const [
      totalUsersRow, activeInvestsRow, totalDepositRow, totalWithdrawRow,
      pendingDepRow, pendingWithRow, bannedUsersRow, totalBalanceRow,
      todayDepRow, autoDepRow, semiDepRow, fraudRow
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
      db.one(`SELECT COUNT(*) as c FROM auto_deposits WHERE dep_type='semi' AND status='completed'`),
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
      semiDepCount: semiDepRow.c,
      fraudCount: fraudRow.c,
    });
  } catch(e) { res.status(500).json({error:e.message}); }
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
  } catch(e) { res.status(500).json({error:e.message}); }
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
    res.json({users, total});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/admin/user/ban', adminAuth, async (req, res) => {
  try {
    const {user_id, reason} = req.body;
    await db.run(`UPDATE users SET is_banned=1, ban_reason=$1 WHERE id=$2`, [reason||'Violated terms', user_id]);
    res.json({success:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/admin/user/unban', adminAuth, async (req, res) => {
  try {
    await db.run(`UPDATE users SET is_banned=0, ban_reason=NULL WHERE id=$1`, [req.body.user_id]);
    log('ADMIN', `User ${req.body.user_id} unbanned`);
    res.json({success:true});
  } catch(e) { res.status(500).json({error:e.message}); }
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
  } catch(e) { res.status(500).json({error:e.message}); }
});

// [NEW] Unblock user deposits
app.post('/admin/user/deposit-unblock', adminAuth, async (req, res) => {
  try {
    await clearFraud(req.body.user_id);
    log('ADMIN', `User ${req.body.user_id} deposit-unblocked by admin`);
    res.json({success:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

// [NEW] View logs
app.get('/admin/logs', adminAuth, async (req, res) => {
  try {
    if (!fs.existsSync(LOG_FILE)) return res.json({logs:''});
    const lines = fs.readFileSync(LOG_FILE, 'utf8').split('\n').filter(Boolean);
    const last100 = lines.slice(-100).reverse().join('\n');
    res.json({logs: last100});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/admin/user/balance', adminAuth, async (req, res) => {
  try {
    const {user_id, amount, type} = req.body;
    const change = type==='deduct' ? -Math.abs(amount) : Math.abs(amount);
    await db.run(`UPDATE users SET balance=balance+$1 WHERE id=$2`, [change, user_id]);
    await db.run(
      `INSERT INTO transactions (user_id,type,amount,status,note) VALUES ($1,$2,$3,$4,$5)`,
      [user_id, type==='deduct'?'admin_deduct':'admin_add', Math.abs(amount), 'completed', 'Admin adjustment']
    );
    res.json({success:true});
  } catch(e) { res.status(500).json({error:e.message}); }
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
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/admin/deposit/approve', adminAuth, async (req, res) => {
  try {
    const {tx_id, admin_note} = req.body;
    if (!tx_id || isNaN(parseInt(tx_id))) return res.status(400).json({error:'Invalid tx_id'});

    const tx = await db.one(`SELECT * FROM transactions WHERE id=$1 AND type='deposit'`, [tx_id]);
    if (!tx) return res.status(404).json({error:'Not found'});
    if (parseFloat(tx.amount) <= 0) return res.status(400).json({error:'Invalid amount'});

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
  } catch(e) { res.status(500).json({error:e.message}); }
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
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/admin/withdraw/approve', adminAuth, async (req, res) => {
  try {
    const {tx_id, admin_note} = req.body;
    if (!tx_id || isNaN(parseInt(tx_id))) return res.status(400).json({error:'Invalid tx_id'});
    const tx = await db.one(`SELECT * FROM transactions WHERE id=$1 AND type='withdraw'`, [tx_id]);
    if (!tx) return res.status(404).json({error:'Not found'});

    // [ATOMIC] Only approve if still pending — rowCount=0 means already processed
    const result = await pool.query(
      `UPDATE transactions SET status='approved', admin_note=$1, approved_at=NOW() WHERE id=$2 AND status='pending' RETURNING id, user_id, amount`,
      [admin_note||'', tx_id]
    );
    if (result.rowCount === 0) return res.status(400).json({error:'Already processed'});

    const {user_id, amount} = result.rows[0];
    log('WITHDRAW', `APPROVED tx=${tx_id} user=${user_id} amt=$${amount} addr=${(tx.address||'').slice(0,16)}`);
    logSecurity('WITHDRAW_APPROVED', {tx_id, user_id, amount, address: (tx.address||'').slice(0,20)});
    res.json({success:true});
  } catch(e) { res.status(500).json({error:e.message}); }
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
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ── Admin Tasks ──
app.get('/admin/tasks', adminAuth, async (req, res) => {
  try {
    const tasks = await db.all('SELECT * FROM tasks_config ORDER BY sort_order');
    res.json({tasks});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/admin/tasks/add', adminAuth, async (req, res) => {
  try {
    const {task_key, icon, name, reward, sort_order, link, chat_id} = req.body;
    await db.run(
      'INSERT INTO tasks_config (task_key,icon,name,reward,sort_order,link,chat_id) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [task_key, icon||'⚡', name, reward||1, sort_order||99, link||'', chat_id||'']
    );
    res.json({success:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/admin/tasks/edit', adminAuth, async (req, res) => {
  try {
    const {id, icon, name, reward, is_active, sort_order, link, chat_id} = req.body;
    await db.run(
      'UPDATE tasks_config SET icon=$1,name=$2,reward=$3,is_active=$4,sort_order=$5,link=$6,chat_id=$7 WHERE id=$8',
      [icon, name, reward, is_active, sort_order, link||'', chat_id||'', id]
    );
    res.json({success:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/admin/tasks/delete', adminAuth, async (req, res) => {
  try {
    await db.run('DELETE FROM tasks_config WHERE id=$1', [req.body.id]);
    res.json({success:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.get('/admin/plans', adminAuth, async (req, res) => {
  try {
    const plans = await db.all(`SELECT * FROM plans ORDER BY id`);
    res.json({plans});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/admin/plans/add', adminAuth, async (req, res) => {
  try {
    const {name,emoji,daily_pct,min_amt,max_amt,duration,daily_limit=0,reset_hours=24} = req.body;
    await db.run(
      `INSERT INTO plans (name,emoji,daily_pct,min_amt,max_amt,duration,daily_limit,reset_hours) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [name,emoji,daily_pct,min_amt,max_amt,duration,daily_limit,reset_hours]
    );
    res.json({success:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/admin/plans/edit', adminAuth, async (req, res) => {
  try {
    const {id,name,emoji,daily_pct,min_amt,max_amt,duration,is_active,daily_limit=0,reset_hours=24} = req.body;
    await db.run(
      `UPDATE plans SET name=$1,emoji=$2,daily_pct=$3,min_amt=$4,max_amt=$5,duration=$6,is_active=$7,daily_limit=$8,reset_hours=$9 WHERE id=$10`,
      [name,emoji,daily_pct,min_amt,max_amt,duration,is_active,daily_limit,reset_hours,id]
    );
    res.json({success:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/admin/plans/delete', adminAuth, async (req, res) => {
  try {
    // Permanently delete the plan
    await db.run(`DELETE FROM plans WHERE id=$1`, [req.body.id]);
    res.json({success:true});
  } catch(e) { res.status(500).json({error:e.message}); }
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
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.get('/admin/settings', adminAuth, async (req, res) => {
  try {
    const rows = await db.all(`SELECT * FROM settings`);
    res.json(rows.reduce((a,r) => ({...a,[r.key]:r.value}), {}));
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/admin/settings', adminAuth, async (req, res) => {
  try {
    const {settings} = req.body;
    for (const [k,v] of Object.entries(settings)) {
      await db.run(`INSERT INTO settings (key,value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=$2`, [k,String(v)]);
    }
    res.json({success:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/admin/maintenance', adminAuth, async (req, res) => {
  try {
    await db.run(`INSERT INTO settings (key,value) VALUES ('maintenance',$1) ON CONFLICT (key) DO UPDATE SET value=$1`, [req.body.on?'1':'0']);
    res.json({success:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ══════════════════════════════════════════
// REFERRAL STATS (per-level breakdown)
// ══════════════════════════════════════════
app.get('/api/referral-stats/:id', async (req, res) => {
  try {
    const uid = parseInt(req.params.id);

    // Level 1 — direct referrals
    const lvl1rows = await db.all(`SELECT id FROM users WHERE referred_by=$1`, [uid]);
    const lvl1ids  = lvl1rows.map(r => r.id);

    // Level 2
    let lvl2ids = [];
    if (lvl1ids.length > 0) {
      const lvl2rows = await db.all(`SELECT id FROM users WHERE referred_by = ANY($1::bigint[])`, [lvl1ids]);
      lvl2ids = lvl2rows.map(r => r.id);
    }

    // Level 3
    let lvl3ids = [];
    if (lvl2ids.length > 0) {
      const lvl3rows = await db.all(`SELECT id FROM users WHERE referred_by = ANY($1::bigint[])`, [lvl2ids]);
      lvl3ids = lvl3rows.map(r => r.id);
    }

    // Active = has at least one approved deposit
    const countActive = async (ids) => {
      if (!ids.length) return 0;
      const r = await db.one(
        `SELECT COUNT(DISTINCT user_id) as cnt FROM transactions WHERE user_id = ANY($1::bigint[]) AND type='deposit' AND status='approved'`,
        [ids]
      );
      return parseInt(r.cnt) || 0;
    };

    const [act1, act2, act3] = await Promise.all([
      countActive(lvl1ids),
      countActive(lvl2ids),
      countActive(lvl3ids),
    ]);

    res.json({
      total: lvl1ids.length + lvl2ids.length + lvl3ids.length,
      total_active: act1 + act2 + act3,
      lvl1: { total: lvl1ids.length, active: act1 },
      lvl2: { total: lvl2ids.length, active: act2 },
      lvl3: { total: lvl3ids.length, active: act3 },
    });
  } catch(e) { res.status(500).json({error: e.message}); }
});

// ══════════════════════════════════════════
// AUTO DEPOSIT — Generate unique amount
// ══════════════════════════════════════════
async function generateUniqueAmt(base) {
  for (let i = 0; i < 50; i++) {
    const dec  = (Math.floor(Math.random() * 41) + 10); // 10-50 → 0.010-0.050
    const uAmt = +(parseFloat(base) + dec / 1000).toFixed(3); // e.g. 10.016
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

    // Track attempts counter
    await db.run(`UPDATE users SET deposit_attempts=deposit_attempts+1 WHERE id=$1`, [u.id]);

    const uAmt = await generateUniqueAmt(amt);
    const dep  = await db.one(
      `INSERT INTO auto_deposits (user_id, amount, unique_amt, network, dep_type)
       VALUES ($1,$2,$3,'BEP20','auto') RETURNING id, unique_amt, expires_at`,
      [u.id, amt, uAmt]
    );

    res.json({ id: dep.id, unique_amount: dep.unique_amt, address: DEPOSIT_WALLET, network: 'BEP20', expires_at: dep.expires_at });
  } catch(e) { res.status(500).json({error: e.message}); }
});

// ── POST /api/deposit/semi (SEMI-AUTO) ────────────
app.post('/api/deposit/semi', depositLimit, userAuth, async (req, res) => {
  try {
    const u      = req.tgUser;
    // [ANTI-FRAUD] Block check
    const blockMsg = await checkBlocked(u.id);
    if (blockMsg) return res.status(429).json({error: blockMsg});

    const amt    = parseFloat(req.body.amount);
    const minDep = parseFloat(await getSetting('deposit_min') || 5);
    if (!amt || amt < minDep) return res.status(400).json({error:`Minimum deposit: $${minDep}`});

    const dep = await db.one(
      `INSERT INTO auto_deposits (user_id, amount, unique_amt, network, dep_type, expires_at)
       VALUES ($1,$2,$3,'BEP20','semi', NOW() + INTERVAL '60 minutes') RETURNING id, unique_amt, expires_at`,
      [u.id, amt, amt]
    );
    res.json({ id: dep.id, amount: dep.unique_amt, address: DEPOSIT_WALLET, network: 'BEP20' });
  } catch(e) { res.status(500).json({error: e.message}); }
});

// ── POST /api/deposit/verify (SEMI-AUTO TXID) ─────
app.post('/api/deposit/verify', verifyLimit, userAuth, async (req, res) => {
  try {
    const u = req.tgUser;
    const { deposit_id, tx_hash } = req.body;
    if (!deposit_id || !tx_hash) return res.status(400).json({error:'deposit_id and tx_hash required'});
    if (!isValidTxHash(tx_hash)) return res.status(400).json({error:'Invalid transaction hash format'});

    // [ANTI-FRAUD] Block check
    const blockMsg = await checkBlocked(u.id);
    if (blockMsg) return res.status(429).json({error: blockMsg});

    // [STRICT] TX reuse check
    const dup = await db.one(`SELECT id FROM auto_deposits WHERE tx_hash=$1`, [tx_hash]);
    if (dup) {
      await recordFraud(u.id, 'TX reuse attempt: ' + tx_hash.slice(0,16));
      return res.status(400).json({error:'TX already used'});
    }

    const dep = await db.one(
      `SELECT * FROM auto_deposits WHERE id=$1 AND user_id=$2 AND dep_type='semi' AND status='pending'`,
      [deposit_id, u.id]
    );
    if (!dep) return res.status(404).json({error:'Deposit not found or already processed'});

    // [STRICT] Expiry check
    if (new Date() > new Date(dep.expires_at)) {
      await db.run(`UPDATE auto_deposits SET status='expired' WHERE id=$1`, [dep.id]);
      log('EXPIRY', `Semi deposit ${dep.id} expired for user ${u.id}`);
      await recordFraud(u.id, 'Expired deposit submit');
      return res.status(400).json({error:'Amount expired, generate a new deposit'});
    }

    // Verify via Moralis - same endpoint as auto scanner, filter by tx_hash
    const url  = `https://deep-index.moralis.io/api/v2.2/${DEPOSIT_WALLET}/erc20/transfers?chain=bsc&contract_addresses[0]=${USDT_CONTRACT}&limit=100&order=DESC`;
    const data = await httpsGet(url, { 'X-API-Key': MORALIS_KEY });

    console.log(`[SEMI] Moralis fetched ${data.result ? data.result.length : 0} txs`);

    if (!data || !Array.isArray(data.result)) {
      return res.status(400).json({error:'Could not fetch transactions. Try again.'});
    }

    // Find the specific tx_hash in recent transfers
    const match = data.result.find(t =>
      t.transaction_hash && t.transaction_hash.toLowerCase() === tx_hash.toLowerCase() &&
      t.to_address && t.to_address.toLowerCase() === DEPOSIT_WALLET
    );

    if (!match) {
      await recordFraud(u.id, 'TX not found or wrong recipient: ' + tx_hash.slice(0,16));
      return res.status(400).json({error:'Transaction not found. Make sure it is confirmed and sent to correct address.'});
    }

    const txAmt = parseFloat(match.value_decimal || 0);
    console.log(`[SEMI] Found tx: hash=${tx_hash.slice(0,16)} amt=${txAmt}`);

    console.log(`[SEMI] tx=${tx_hash.slice(0,16)} txAmt=${txAmt} expected=${dep.unique_amt}`);

    if (txAmt === 0) return res.status(400).json({error:'USDT transfer to our wallet not found in this TX'});

    // [STRICT] Amount must match within $0.01
    if (Math.abs(txAmt - dep.unique_amt) > 0.01) {
      await db.run(`UPDATE auto_deposits SET fraud_flag=1 WHERE id=$1`, [dep.id]);
      await recordFraud(u.id, `Amount mismatch: expected=${dep.unique_amt} got=${txAmt}`);
      return res.status(400).json({error:`Wrong amount. Expected $${dep.unique_amt}, got $${txAmt.toFixed(2)}`});
    }

    await creditAutoDeposit(dep, tx_hash);
    res.json({success: true, amount: dep.unique_amt});
  } catch(e) { res.status(500).json({error: e.message}); }
});

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
  } catch(e) { res.status(500).json({error: e.message}); }
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
    await db.run(`UPDATE users SET balance=balance+$1 WHERE id=$2`, [dep.unique_amt, dep.user_id]);
    // Transaction log
    await db.run(
      `INSERT INTO transactions (user_id,type,amount,network,txid,status,note)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [dep.user_id,'deposit',dep.unique_amt,'BEP20',txHash,'approved',(dep.dep_type==='semi'?'Semi-auto verified':'Auto-detected')]
    );
    // First deposit task reward
    const taskDone = await db.one(
      `SELECT id FROM tasks WHERE user_id=$1 AND task_key='first_deposit'`, [dep.user_id]
    );
    if (!taskDone) {
      await db.run(
        `INSERT INTO tasks (user_id, task_key, completed, completed_at)
         VALUES ($1,'first_deposit',1,NOW()) ON CONFLICT DO NOTHING`,
        [dep.user_id]
      );
      await db.run(`UPDATE users SET balance=balance+3 WHERE id=$1`, [dep.user_id]);
    }
    console.log(`✅ Auto deposit: user=${dep.user_id} amt=${dep.unique_amt} ${dep.network} tx=${txHash}`);
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
// BEP20 AUTO SCANNER (Moralis)
// ══════════════════════════════════════════
async function scanBEP20() {
  try {
    const pending = await db.all(
      `SELECT * FROM auto_deposits WHERE dep_type='auto' AND status='pending' AND expires_at > NOW()`
    );
    if (!pending.length) return;

    const url  = `https://deep-index.moralis.io/api/v2.2/${DEPOSIT_WALLET}/erc20/transfers?chain=bsc&contract_addresses[0]=${USDT_CONTRACT}&limit=20&order=DESC`;
    const data = await httpsGet(url, { 'X-API-Key': MORALIS_KEY });

    if (!data.result || !Array.isArray(data.result)) {
      console.log('[BEP20] Moralis error:', JSON.stringify(data).slice(0, 200));
      return;
    }

    const txs = data.result;
    console.log(`[BEP20] Moralis: ${txs.length} txs | pending auto: ${pending.length}`);

    for (const dep of pending) {
      const depTs = new Date(dep.created_at).getTime() - 60000;
      let matched = false;

      for (const tx of txs) {
        if (tx.to_address.toLowerCase() !== DEPOSIT_WALLET) continue;
        if (new Date(tx.block_timestamp).getTime() < depTs) continue;

        const txAmt = parseFloat(tx.value_decimal);
        const diff  = Math.abs(txAmt - dep.unique_amt);
        console.log(`[BEP20] tx=${tx.transaction_hash.slice(0,12)} got=${txAmt} exp=${dep.unique_amt} diff=${diff}`);

        if (diff <= 0.02) {
          // [STRICT] Double-check expiry before crediting
          if (new Date() > new Date(dep.expires_at)) {
            await db.run(`UPDATE auto_deposits SET status='expired' WHERE id=$1`, [dep.id]);
            log('EXPIRY', `Auto deposit ${dep.id} expired before match user=${dep.user_id}`);
            matched = true; // stop searching for this dep
            break;
          }
          log('DEPOSIT', `Auto match dep=${dep.id} user=${dep.user_id} amt=${dep.unique_amt}`);
          await creditAutoDeposit(dep, tx.transaction_hash);
          matched = true;
          break;
        }
      }
      // [REDUCED LOG] Only log no-match for very recent deposits (< 5 min)
      if (!matched) {
        const age = (Date.now() - new Date(dep.created_at).getTime()) / 60000;
        if (age < 5) console.log(`[BEP20] No match dep=${dep.id} amt=${dep.unique_amt} age=${age.toFixed(1)}m`);
      }
    }
  } catch(e) { console.error('[BEP20] Scanner error:', e.message); }
}

// ══════════════════════════════════════════
// START SCANNERS
// ══════════════════════════════════════════
function startScanners() {
  console.log('🔍 BEP20 Moralis scanner started (10s interval)');
  setTimeout(scanBEP20, 5000);
  setInterval(scanBEP20, 10000);
  // Auto-expire old pending deposits every minute
  setInterval(async () => {
    await db.run(`UPDATE auto_deposits SET status='expired' WHERE status='pending' AND expires_at < NOW()`);
  }, 60000);
}

// ══════════════════════════════════════════
// START
// ══════════════════════════════════════════

// ══════════════════════════════════════════
// LEADERBOARD
// ══════════════════════════════════════════
app.get('/admin/deposit-stats', adminAuth, async (req, res) => {
  try {
    const rows = await db.all(`
      SELECT
        TO_CHAR(created_at, 'HH24:MI') as time,
        SUM(amount) as total
      FROM transactions
      WHERE type='deposit' AND status='approved'
        AND created_at > NOW() - INTERVAL '1 hour'
      GROUP BY TO_CHAR(created_at, 'HH24:MI')
      ORDER BY MIN(created_at) ASC
    `);
    res.json(rows.map(r => ({ time: r.time, total: parseFloat(r.total) })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/leaderboard', async (req, res) => {
  try {
    const rows = await db.all(
      `SELECT first_name, uid, total_earned,
              (SELECT COUNT(*) FROM users u2 WHERE u2.referred_by=u.id AND u2.is_active_ref=TRUE) as active_refs
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
  } catch(e) { res.status(500).json({error: e.message}); }
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
setupDB().then(() => {
  startScanners();
  app.listen(PORT, () => console.log(`✅ Server on port ${PORT} — Neon PostgreSQL connected`));
}).catch(e => {
  console.error('DB setup failed:', e);
  process.exit(1);
});app.post('/api/collect-commission', userAuth, async (req, res) => {
  try {
    const u = req.tgUser;
    const user = await db.one(`SELECT * FROM users WHERE id=$1`, [u.id]);
    if (!user) return res.status(404).json({error:'Not found'});
    const pending = parseFloat(user.pending_commission || 0);
    if (pending <= 0) return res.status(400).json({error:'No pending commission'});
    await db.run(`UPDATE users SET balance=balance+$1, pending_commission=0 WHERE id=$2`, [pending, u.id]);
    await db.run(`UPDATE commissions SET status='collected' WHERE user_id=$1 AND status='pending'`, [u.id]);
    await db.run(`INSERT INTO transactions (user_id,type,amount,status,note) VALUES ($1,$2,$3,$4,$5)`, [u.id,'commission',pending,'completed','Referral commission collected']);
    res.json({success:true, collected:pending});
  } catch(e) { res.status(500).json({error:e.message}); }
});
