const express  = require('express');
const cors     = require('cors');
const crypto   = require('crypto');
const { Pool } = require('pg');

const app  = express();
const PORT = process.env.PORT || 3000;

const BOT_TOKEN    = process.env.BOT_TOKEN    || "YOUR_BOT_TOKEN";
const ADMIN_SECRET = process.env.ADMIN_SECRET || "admin123";
const DATABASE_URL = process.env.DATABASE_URL || "postgresql://neondb_owner:npg_4IVJ1PZzcjnW@ep-long-art-anucops0-pooler.c-6.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require";

app.use(cors());
app.use(express.json());

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

  // Default settings
  const defaults = {
    withdraw_fee_pct: '2', withdraw_min: '10', withdraw_max: '10000',
    deposit_min: '5',
    trc20_address: 'TGnuvLYAHJn2sxvi7MqVqHUkMQ66DiKgSJ',
    erc20_address: '0x4878d34e544b79801249d36303b321ca8e634bdd',
    bep20_address: '0x4878d34e544b79801249d36303b321ca8e634bdd',
    ref_lvl1_pct: '8', ref_lvl2_pct: '3', ref_lvl3_pct: '1',
    maintenance: '0',
  };
  for (const [k,v] of Object.entries(defaults)) {
    await db.run(`INSERT INTO settings (key,value) VALUES ($1,$2) ON CONFLICT (key) DO NOTHING`, [k,v]);
  }

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

  // Migration: add daily_limit columns if not exists
  await db.run(`ALTER TABLE plans ADD COLUMN IF NOT EXISTS daily_limit INTEGER DEFAULT 0`);
  await db.run(`ALTER TABLE plans ADD COLUMN IF NOT EXISTS today_count INTEGER DEFAULT 0`);
  await db.run(`ALTER TABLE plans ADD COLUMN IF NOT EXISTS last_reset TIMESTAMP DEFAULT NOW()`);
  await db.run(`ALTER TABLE plans ADD COLUMN IF NOT EXISTS reset_hours REAL DEFAULT 24`);

  console.log('✅ Database ready (Neon PostgreSQL)');
}

async function getSetting(key) {
  const r = await db.one(`SELECT value FROM settings WHERE key=$1`, [key]);
  return r ? r.value : null;
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
  if (!initData) return res.status(401).json({error:'No auth'});
  if (process.env.NODE_ENV !== 'production' || verifyTg(initData)) {
    try {
      const p = new URLSearchParams(initData);
      req.tgUser = JSON.parse(p.get('user') || 'null');
    } catch { req.tgUser = null; }
    return next();
  }
  return res.status(403).json({error:'Invalid auth'});
}

function adminAuth(req, res, next) {
  const secret = req.headers['x-admin-secret'] || req.body?.adminSecret;
  if (secret !== ADMIN_SECRET) return res.status(403).json({error:'Unauthorized'});
  next();
}

// ══════════════════════════════════════════
// USER ROUTES
// ══════════════════════════════════════════
app.post('/api/auth', userAuth, async (req, res) => {
  try {
    const u = req.tgUser;
    if (!u) return res.status(400).json({error:'No user'});
    if (await getSetting('maintenance') === '1') return res.status(503).json({error:'maintenance'});

    const refCode = 'REF'+u.id;

    // Get referral code - from request OR pending_refs table
    let ref = req.body.ref || null;

    // Check pending_refs if no ref in request
    if (!ref) {
      const pending = await db.one(`SELECT ref_code FROM pending_refs WHERE user_id=$1`, [u.id]);
      if (pending) ref = pending.ref_code;
    }

    // Extract numeric ID from REF123456 format
    let referredById = null;
    if (ref && String(ref).startsWith('REF')) {
      referredById = parseInt(String(ref).replace('REF','')) || null;
    }
    // Don't refer yourself
    if (referredById === u.id) referredById = null;

    // Check if user already exists
    const existingUser = await db.one(`SELECT id, referred_by FROM users WHERE id=$1`, [u.id]);

    if (!existingUser) {
      await db.run(`
        INSERT INTO users (id,first_name,last_name,username,language,is_premium,ref_code,referred_by)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      `, [u.id, u.first_name||'', u.last_name||'', u.username||'', u.language_code||'', u.is_premium?1:0, refCode, referredById]);
      console.log('New user:', u.id, 'referred by:', referredById);
    } else {
      await db.run(`
        UPDATE users SET first_name=$1, last_name=$2, username=$3, language=$4, is_premium=$5,
          referred_by = CASE WHEN referred_by IS NULL AND $6::BIGINT IS NOT NULL THEN $6::BIGINT ELSE referred_by END
        WHERE id=$7
      `, [u.first_name||'', u.last_name||'', u.username||'', u.language_code||'', u.is_premium?1:0, referredById, u.id]);
    }

    // Clean up pending ref
    await db.run(`DELETE FROM pending_refs WHERE user_id=$1`, [u.id]);

    const user = await db.one(`SELECT * FROM users WHERE id=$1`, [u.id]);
    if (user.is_banned) return res.status(403).json({error:'banned', reason: user.ban_reason||'Violated terms'});
    res.json({success:true, user});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.get('/api/user/:id', async (req, res) => {
  try {
    const user = await db.one(`SELECT * FROM users WHERE id=$1`, [req.params.id]);
    if (!user) return res.status(404).json({error:'Not found'});

    const investments  = await db.all(`SELECT * FROM investments WHERE user_id=$1 AND status='active'`, [req.params.id]);
    const transactions = await db.all(`SELECT * FROM transactions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 20`, [req.params.id]);
    const taskRows     = await db.all(`SELECT task_key FROM tasks WHERE user_id=$1 AND completed=1`, [req.params.id]);
    const tasks        = taskRows.map(t => t.task_key);
    const referrals    = await db.all(`SELECT id,first_name,username,created_at FROM users WHERE referred_by=$1`, [req.params.id]);
    // Reset today_count based on reset_hours
    await db.run(`
      UPDATE plans SET today_count=0, last_reset=NOW()
      WHERE daily_limit > 0
        AND last_reset IS NOT NULL
        AND EXTRACT(EPOCH FROM (NOW() - last_reset))/3600 >= reset_hours
    `);
    const plans        = await db.all(`SELECT * FROM plans WHERE is_active=1 ORDER BY id`);
    const settingRows  = await db.all(`SELECT * FROM settings`);
    const settings     = settingRows.reduce((a,r) => ({...a,[r.key]:r.value}), {});

    res.json({user, investments, transactions, tasks, referrals, plans, settings});
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
    await db.run(`UPDATE users SET balance=balance-$1 WHERE id=$2`, [amount, u.id]);
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

app.post('/api/withdraw', userAuth, async (req, res) => {
  try {
    const u = req.tgUser;
    const {amount, network, address} = req.body;
    const user = await db.one(`SELECT * FROM users WHERE id=$1`, [u.id]);
    if (!user) return res.status(404).json({error:'Not found'});
    if (user.is_banned) return res.status(403).json({error:'banned'});

    const minW   = parseFloat(await getSetting('withdraw_min') || 10);
    const maxW   = parseFloat(await getSetting('withdraw_max') || 10000);
    const feePct = parseFloat(await getSetting('withdraw_fee_pct') || 2);
    if (amount < minW) return res.status(400).json({error:`Min $${minW}`});
    if (amount > maxW) return res.status(400).json({error:`Max $${maxW}`});
    if (user.balance < amount) return res.status(400).json({error:'Insufficient balance'});

    const fee = +(amount * feePct / 100).toFixed(2);
    await db.run(`UPDATE users SET balance=balance-$1 WHERE id=$2`, [amount, u.id]);
    await db.run(
      `INSERT INTO transactions (user_id,type,amount,network,address,fee) VALUES ($1,$2,$3,$4,$5,$6)`,
      [u.id,'withdraw',amount,network,address,fee]
    );
    res.json({success:true, fee});
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
      if (diff < 24*60*60*1000) return res.status(400).json({error:'Already collected today'});
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
    await db.run(
      `INSERT INTO tasks (user_id,task_key,completed,completed_at) VALUES ($1,$2,1,NOW()) ON CONFLICT (user_id,task_key) DO UPDATE SET completed=1`,
      [u.id, task_key]
    );
    await db.run(`UPDATE users SET balance=balance+$1 WHERE id=$2`, [reward, u.id]);
    res.json({success:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ══════════════════════════════════════════
// PUBLIC ROUTES
// ══════════════════════════════════════════

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
    const totalUsers    = (await db.one(`SELECT COUNT(*) as c FROM users`)).c;
    const activeInvests = (await db.one(`SELECT COUNT(*) as c FROM investments WHERE status='active'`)).c;
    const totalDeposit  = (await db.one(`SELECT COALESCE(SUM(amount),0) as s FROM transactions WHERE type='deposit' AND status='approved'`)).s;
    const totalWithdraw = (await db.one(`SELECT COALESCE(SUM(amount),0) as s FROM transactions WHERE type='withdraw' AND status='approved'`)).s;
    const pendingDep    = (await db.one(`SELECT COUNT(*) as c FROM transactions WHERE type='deposit' AND status='pending'`)).c;
    const pendingWith   = (await db.one(`SELECT COUNT(*) as c FROM transactions WHERE type='withdraw' AND status='pending'`)).c;
    const bannedUsers   = (await db.one(`SELECT COUNT(*) as c FROM users WHERE is_banned=1`)).c;
    const totalBalance  = (await db.one(`SELECT COALESCE(SUM(balance),0) as s FROM users`)).s;
    res.json({totalUsers,activeInvests,totalDeposit,totalWithdraw,pendingDep,pendingWith,bannedUsers,totalBalance});
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
    res.json({success:true});
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
    const tx = await db.one(`SELECT * FROM transactions WHERE id=$1 AND type='deposit'`, [tx_id]);
    if (!tx) return res.status(404).json({error:'Not found'});
    if (tx.status !== 'pending') return res.status(400).json({error:'Already processed'});
    await db.run(`UPDATE transactions SET status='approved', admin_note=$1 WHERE id=$2`, [admin_note||'', tx_id]);
    await db.run(`UPDATE users SET balance=balance+$1 WHERE id=$2`, [tx.amount, tx.user_id]);
    res.json({success:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/admin/deposit/reject', adminAuth, async (req, res) => {
  try {
    const {tx_id, admin_note} = req.body;
    await db.run(`UPDATE transactions SET status='rejected', admin_note=$1 WHERE id=$2`, [admin_note||'', tx_id]);
    res.json({success:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/admin/withdraw/approve', adminAuth, async (req, res) => {
  try {
    const {tx_id, admin_note} = req.body;
    const tx = await db.one(`SELECT * FROM transactions WHERE id=$1 AND type='withdraw'`, [tx_id]);
    if (!tx) return res.status(404).json({error:'Not found'});
    if (tx.status !== 'pending') return res.status(400).json({error:'Already processed'});
    await db.run(`UPDATE transactions SET status='approved', admin_note=$1 WHERE id=$2`, [admin_note||'', tx_id]);
    res.json({success:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/admin/withdraw/reject', adminAuth, async (req, res) => {
  try {
    const {tx_id, admin_note} = req.body;
    const tx = await db.one(`SELECT * FROM transactions WHERE id=$1 AND type='withdraw'`, [tx_id]);
    if (!tx) return res.status(404).json({error:'Not found'});
    if (tx.status !== 'pending') return res.status(400).json({error:'Already processed'});
    await db.run(`UPDATE transactions SET status='rejected', admin_note=$1 WHERE id=$2`, [admin_note||'', tx_id]);
    await db.run(`UPDATE users SET balance=balance+$1 WHERE id=$2`, [tx.amount, tx.user_id]);
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
// START
// ══════════════════════════════════════════
setupDB().then(() => {
  app.listen(PORT, () => console.log(`✅ Server on port ${PORT} — Neon PostgreSQL connected`));
}).catch(e => {
  console.error('DB setup failed:', e);
  process.exit(1);
});
