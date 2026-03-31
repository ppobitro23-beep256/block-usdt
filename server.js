const express  = require('express');
const Database = require('better-sqlite3');
const cors     = require('cors');
const crypto   = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;

const BOT_TOKEN    = process.env.BOT_TOKEN    || "YOUR_BOT_TOKEN";
const ADMIN_SECRET = process.env.ADMIN_SECRET || "admin123"; // ← পরিবর্তন করুন

app.use(cors());
app.use(express.json());

// ══════════════════════════════════════════
// DATABASE
// ══════════════════════════════════════════
const db = new Database('cryptovault.db');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY,
    first_name   TEXT, last_name TEXT, username TEXT, language TEXT,
    is_premium   INTEGER DEFAULT 0,
    balance      REAL DEFAULT 0,
    total_earned REAL DEFAULT 0,
    today_earned REAL DEFAULT 0,
    ref_code     TEXT UNIQUE,
    referred_by  INTEGER,
    is_banned    INTEGER DEFAULT 0,
    ban_reason   TEXT,
    created_at   TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS plans (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT, emoji TEXT,
    daily_pct  REAL, min_amt REAL, max_amt REAL,
    duration   INTEGER, is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS investments (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER, plan_name TEXT,
    amount       REAL, daily_pct REAL, daily_earn REAL,
    days_total   INTEGER DEFAULT 50, days_done INTEGER DEFAULT 0,
    pending_earn REAL DEFAULT 0,
    last_collect TEXT,
    status       TEXT DEFAULT 'active',
    started_at   TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS transactions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER, type TEXT, amount REAL,
    status     TEXT DEFAULT 'pending',
    network    TEXT, address TEXT, txid TEXT,
    fee        REAL DEFAULT 0, note TEXT,
    admin_note TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS tasks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER, task_key TEXT,
    completed    INTEGER DEFAULT 0,
    completed_at TEXT
  );
  CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
  );
`);

// Default settings
const defaultSettings = {
  withdraw_fee_pct:  '2',
  withdraw_min:      '10',
  withdraw_max:      '10000',
  deposit_min:       '5',
  trc20_address:     'TGnuvLYAHJn2sxvi7MqVqHUkMQ66DiKgSJ',
  erc20_address:     '0x4878d34e544b79801249d36303b321ca8e634bdd',
  bep20_address:     '0x4878d34e544b79801249d36303b321ca8e634bdd',
  ref_lvl1_pct:      '8',
  ref_lvl2_pct:      '3',
  ref_lvl3_pct:      '1',
  maintenance:       '0',
};
for (const [k,v] of Object.entries(defaultSettings)) {
  db.prepare(`INSERT OR IGNORE INTO settings (key,value) VALUES (?,?)`).run(k,v);
}

// Default plans
const existingPlans = db.prepare('SELECT COUNT(*) as c FROM plans').get();
if (existingPlans.c === 0) {
  const defaultPlans = [
    {name:'Bronze Plan', emoji:'🥉', daily_pct:2.5, min_amt:10,  max_amt:20,   duration:50},
    {name:'Silver Plan', emoji:'🥈', daily_pct:2.8, min_amt:20,  max_amt:50,   duration:50},
    {name:'Golden Plan', emoji:'🥇', daily_pct:3.0, min_amt:50,  max_amt:100,  duration:50},
    {name:'Diamond Plan',emoji:'💎', daily_pct:4.0, min_amt:100, max_amt:1000, duration:50},
  ];
  const ins = db.prepare(`INSERT INTO plans (name,emoji,daily_pct,min_amt,max_amt,duration) VALUES (?,?,?,?,?,?)`);
  defaultPlans.forEach(p => ins.run(p.name,p.emoji,p.daily_pct,p.min_amt,p.max_amt,p.duration));
}

function getSetting(key) {
  const r = db.prepare('SELECT value FROM settings WHERE key=?').get(key);
  return r ? r.value : null;
}

// ══════════════════════════════════════════
// AUTH HELPERS
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
app.post('/api/auth', userAuth, (req, res) => {
  const u = req.tgUser;
  if (!u) return res.status(400).json({error:'No user'});
  if (getSetting('maintenance') === '1') return res.status(503).json({error:'maintenance'});
  const refCode = 'REF'+u.id;
  const ref = req.body.ref || null;
  db.prepare(`INSERT INTO users (id,first_name,last_name,username,language,is_premium,ref_code,referred_by)
    VALUES (?,?,?,?,?,?,?,?)
    ON CONFLICT(id) DO UPDATE SET first_name=excluded.first_name,last_name=excluded.last_name,
    username=excluded.username,language=excluded.language,is_premium=excluded.is_premium
  `).run(u.id,u.first_name||'',u.last_name||'',u.username||'',u.language_code||'',u.is_premium?1:0,refCode,ref);
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(u.id);
  if (user.is_banned) return res.status(403).json({error:'banned', reason: user.ban_reason||'Violated terms'});
  res.json({success:true, user});
});

app.get('/api/user/:id', (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
  if (!user) return res.status(404).json({error:'Not found'});
  const investments  = db.prepare(`SELECT * FROM investments WHERE user_id=? AND status='active'`).all(req.params.id);
  const transactions = db.prepare(`SELECT * FROM transactions WHERE user_id=? ORDER BY created_at DESC LIMIT 20`).all(req.params.id);
  const tasks        = db.prepare('SELECT task_key FROM tasks WHERE user_id=? AND completed=1').all(req.params.id).map(t=>t.task_key);
  const referrals    = db.prepare('SELECT id,first_name,username,created_at FROM users WHERE referred_by=?').all(req.params.id);
  const plans        = db.prepare('SELECT * FROM plans WHERE is_active=1').all();
  const settings     = db.prepare('SELECT * FROM settings').all().reduce((a,r)=>({...a,[r.key]:r.value}),{});
  res.json({user,investments,transactions,tasks,referrals,plans,settings});
});

app.post('/api/invest', userAuth, (req, res) => {
  const u = req.tgUser;
  const {plan_id, amount} = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(u.id);
  if (!user) return res.status(404).json({error:'User not found'});
  if (user.is_banned) return res.status(403).json({error:'banned'});
  const plan = db.prepare('SELECT * FROM plans WHERE id=? AND is_active=1').get(plan_id);
  if (!plan) return res.status(404).json({error:'Plan not found'});
  if (amount < plan.min_amt) return res.status(400).json({error:`Min $${plan.min_amt}`});
  if (amount > plan.max_amt) return res.status(400).json({error:`Max $${plan.max_amt}`});
  if (user.balance < amount) return res.status(400).json({error:'Insufficient balance'});
  const daily = +(amount * plan.daily_pct / 100).toFixed(4);
  db.prepare('UPDATE users SET balance=balance-? WHERE id=?').run(amount, u.id);
  db.prepare(`INSERT INTO investments (user_id,plan_name,amount,daily_pct,daily_earn,days_total) VALUES (?,?,?,?,?,?)`)
    .run(u.id, plan.emoji+' '+plan.name, amount, plan.daily_pct, daily, plan.duration);
  db.prepare(`INSERT INTO transactions (user_id,type,amount,status,note) VALUES (?,?,?,?,?)`)
    .run(u.id,'invest',amount,'completed',`Invested in ${plan.name}`);
  res.json({success:true, daily_earn:daily});
});

app.post('/api/deposit', userAuth, (req, res) => {
  const u = req.tgUser;
  const {amount, network, txid} = req.body;
  const minDep = parseFloat(getSetting('deposit_min')||5);
  if (amount < minDep) return res.status(400).json({error:`Min deposit $${minDep}`});
  db.prepare(`INSERT INTO transactions (user_id,type,amount,network,txid) VALUES (?,?,?,?,?)`)
    .run(u.id,'deposit',amount,network,txid);
  res.json({success:true});
});

app.post('/api/withdraw', userAuth, (req, res) => {
  const u = req.tgUser;
  const {amount, network, address} = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(u.id);
  if (!user) return res.status(404).json({error:'Not found'});
  if (user.is_banned) return res.status(403).json({error:'banned'});
  const minW   = parseFloat(getSetting('withdraw_min')||10);
  const maxW   = parseFloat(getSetting('withdraw_max')||10000);
  const feePct = parseFloat(getSetting('withdraw_fee_pct')||2);
  if (amount < minW) return res.status(400).json({error:`Min $${minW}`});
  if (amount > maxW) return res.status(400).json({error:`Max $${maxW}`});
  if (user.balance < amount) return res.status(400).json({error:'Insufficient balance'});
  const fee = +(amount * feePct / 100).toFixed(2);
  db.prepare('UPDATE users SET balance=balance-? WHERE id=?').run(amount, u.id);
  db.prepare(`INSERT INTO transactions (user_id,type,amount,network,address,fee) VALUES (?,?,?,?,?,?)`)
    .run(u.id,'withdraw',amount,network,address,fee);
  res.json({success:true, fee});
});

app.post('/api/collect-daily', userAuth, (req, res) => {
  const u = req.tgUser;
  const {investment_id} = req.body;
  const inv = db.prepare('SELECT * FROM investments WHERE id=? AND user_id=? AND status=?').get(investment_id, u.id, 'active');
  if (!inv) return res.status(404).json({error:'Investment not found'});
  const lastCollect = inv.last_collect ? new Date(inv.last_collect) : null;
  const now = new Date();
  if (lastCollect && (now - lastCollect) < 24*60*60*1000)
    return res.status(400).json({error:'Already collected today'});
  const earn = inv.daily_earn;
  db.prepare('UPDATE users SET balance=balance+?,total_earned=total_earned+?,today_earned=today_earned+? WHERE id=?').run(earn,earn,earn,u.id);
  db.prepare('UPDATE investments SET days_done=days_done+1, last_collect=datetime("now") WHERE id=?').run(inv.id);
  db.prepare(`INSERT INTO transactions (user_id,type,amount,status,note) VALUES (?,?,?,?,?)`)
    .run(u.id,'earn',earn,'completed',`Daily return: ${inv.plan_name}`);
  if (inv.days_done+1 >= inv.days_total)
    db.prepare(`UPDATE investments SET status='completed' WHERE id=?`).run(inv.id);
  res.json({success:true, earned:earn});
});

app.post('/api/collect-commission', userAuth, (req, res) => {
  const u = req.tgUser;
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(u.id);
  // pending commission stored in a temp field - simplified
  res.json({success:true, collected:0});
});

app.post('/api/task/complete', userAuth, (req, res) => {
  const u = req.tgUser;
  const {task_key, reward} = req.body;
  const ex = db.prepare('SELECT * FROM tasks WHERE user_id=? AND task_key=?').get(u.id, task_key);
  if (ex?.completed) return res.status(400).json({error:'Already done'});
  db.prepare(`INSERT OR REPLACE INTO tasks (user_id,task_key,completed,completed_at) VALUES (?,?,1,datetime('now'))`).run(u.id,task_key);
  db.prepare('UPDATE users SET balance=balance+? WHERE id=?').run(reward, u.id);
  res.json({success:true});
});

// ══════════════════════════════════════════
// ADMIN ROUTES
// ══════════════════════════════════════════

// Dashboard stats
app.get('/admin/stats', adminAuth, (req,res) => {
  const totalUsers    = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  const activeInvests = db.prepare(`SELECT COUNT(*) as c FROM investments WHERE status='active'`).get().c;
  const totalDeposit  = db.prepare(`SELECT COALESCE(SUM(amount),0) as s FROM transactions WHERE type='deposit' AND status='approved'`).get().s;
  const totalWithdraw = db.prepare(`SELECT COALESCE(SUM(amount),0) as s FROM transactions WHERE type='withdraw' AND status='approved'`).get().s;
  const pendingDep    = db.prepare(`SELECT COUNT(*) as c FROM transactions WHERE type='deposit' AND status='pending'`).get().c;
  const pendingWith   = db.prepare(`SELECT COUNT(*) as c FROM transactions WHERE type='withdraw' AND status='pending'`).get().c;
  const bannedUsers   = db.prepare('SELECT COUNT(*) as c FROM users WHERE is_banned=1').get().c;
  const totalBalance  = db.prepare('SELECT COALESCE(SUM(balance),0) as s FROM users').get().s;
  res.json({totalUsers,activeInvests,totalDeposit,totalWithdraw,pendingDep,pendingWith,bannedUsers,totalBalance});
});

// Users
app.get('/admin/users', adminAuth, (req,res) => {
  const {search, page=1, limit=20} = req.query;
  const offset = (page-1)*limit;
  let q = 'SELECT * FROM users';
  let params = [];
  if (search) { q += ' WHERE first_name LIKE ? OR username LIKE ? OR id LIKE ?'; params=[`%${search}%`,`%${search}%`,`%${search}%`]; }
  q += ` ORDER BY created_at DESC LIMIT ${limit} OFFSET ${offset}`;
  const users = db.prepare(q).all(...params);
  const total = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  res.json({users, total});
});

app.post('/admin/user/ban', adminAuth, (req,res) => {
  const {user_id, reason} = req.body;
  db.prepare('UPDATE users SET is_banned=1, ban_reason=? WHERE id=?').run(reason||'Violated terms', user_id);
  res.json({success:true});
});

app.post('/admin/user/unban', adminAuth, (req,res) => {
  const {user_id} = req.body;
  db.prepare('UPDATE users SET is_banned=0, ban_reason=NULL WHERE id=?').run(user_id);
  res.json({success:true});
});

app.post('/admin/user/balance', adminAuth, (req,res) => {
  const {user_id, amount, type} = req.body; // type: add | deduct
  const change = type==='deduct' ? -Math.abs(amount) : Math.abs(amount);
  db.prepare('UPDATE users SET balance=balance+? WHERE id=?').run(change, user_id);
  db.prepare(`INSERT INTO transactions (user_id,type,amount,status,note) VALUES (?,?,?,?,?)`)
    .run(user_id, type==='deduct'?'admin_deduct':'admin_add', Math.abs(amount), 'completed', 'Admin adjustment');
  res.json({success:true});
});

// Transactions
app.get('/admin/transactions', adminAuth, (req,res) => {
  const {type, status, page=1, limit=20} = req.query;
  const offset = (page-1)*limit;
  let q = `SELECT t.*, u.first_name, u.username FROM transactions t LEFT JOIN users u ON t.user_id=u.id WHERE 1=1`;
  const params = [];
  if (type)   { q += ' AND t.type=?';   params.push(type); }
  if (status) { q += ' AND t.status=?'; params.push(status); }
  q += ` ORDER BY t.created_at DESC LIMIT ${limit} OFFSET ${offset}`;
  const txs = db.prepare(q).all(...params);
  res.json({transactions: txs});
});

// Approve deposit
app.post('/admin/deposit/approve', adminAuth, (req,res) => {
  const {tx_id, admin_note} = req.body;
  const tx = db.prepare('SELECT * FROM transactions WHERE id=? AND type=?').get(tx_id,'deposit');
  if (!tx) return res.status(404).json({error:'Not found'});
  if (tx.status !== 'pending') return res.status(400).json({error:'Already processed'});
  db.prepare('UPDATE transactions SET status=?,admin_note=? WHERE id=?').run('approved',admin_note||'',tx_id);
  db.prepare('UPDATE users SET balance=balance+? WHERE id=?').run(tx.amount, tx.user_id);
  res.json({success:true});
});

// Reject deposit
app.post('/admin/deposit/reject', adminAuth, (req,res) => {
  const {tx_id, admin_note} = req.body;
  db.prepare('UPDATE transactions SET status=?,admin_note=? WHERE id=?').run('rejected',admin_note||'Rejected by admin',tx_id);
  res.json({success:true});
});

// Approve withdrawal
app.post('/admin/withdraw/approve', adminAuth, (req,res) => {
  const {tx_id, admin_note} = req.body;
  const tx = db.prepare('SELECT * FROM transactions WHERE id=? AND type=?').get(tx_id,'withdraw');
  if (!tx) return res.status(404).json({error:'Not found'});
  if (tx.status !== 'pending') return res.status(400).json({error:'Already processed'});
  db.prepare('UPDATE transactions SET status=?,admin_note=? WHERE id=?').run('approved',admin_note||'',tx_id);
  res.json({success:true});
});

// Reject withdrawal — refund
app.post('/admin/withdraw/reject', adminAuth, (req,res) => {
  const {tx_id, admin_note} = req.body;
  const tx = db.prepare('SELECT * FROM transactions WHERE id=? AND type=?').get(tx_id,'withdraw');
  if (!tx) return res.status(404).json({error:'Not found'});
  if (tx.status !== 'pending') return res.status(400).json({error:'Already processed'});
  db.prepare('UPDATE transactions SET status=?,admin_note=? WHERE id=?').run('rejected',admin_note||'',tx_id);
  db.prepare('UPDATE users SET balance=balance+? WHERE id=?').run(tx.amount, tx.user_id); // refund
  res.json({success:true});
});

// Plans CRUD
app.get('/admin/plans', adminAuth, (req,res) => {
  res.json({plans: db.prepare('SELECT * FROM plans').all()});
});
app.post('/admin/plans/add', adminAuth, (req,res) => {
  const {name,emoji,daily_pct,min_amt,max_amt,duration} = req.body;
  db.prepare(`INSERT INTO plans (name,emoji,daily_pct,min_amt,max_amt,duration) VALUES (?,?,?,?,?,?)`)
    .run(name,emoji,daily_pct,min_amt,max_amt,duration);
  res.json({success:true});
});
app.post('/admin/plans/edit', adminAuth, (req,res) => {
  const {id,name,emoji,daily_pct,min_amt,max_amt,duration,is_active} = req.body;
  db.prepare(`UPDATE plans SET name=?,emoji=?,daily_pct=?,min_amt=?,max_amt=?,duration=?,is_active=? WHERE id=?`)
    .run(name,emoji,daily_pct,min_amt,max_amt,duration,is_active,id);
  res.json({success:true});
});
app.post('/admin/plans/delete', adminAuth, (req,res) => {
  db.prepare('UPDATE plans SET is_active=0 WHERE id=?').run(req.body.id);
  res.json({success:true});
});

// Settings
app.get('/admin/settings', adminAuth, (req,res) => {
  const rows = db.prepare('SELECT * FROM settings').all();
  res.json(rows.reduce((a,r)=>({...a,[r.key]:r.value}),{}));
});
app.post('/admin/settings', adminAuth, (req,res) => {
  const {settings} = req.body;
  const upd = db.prepare('INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)');
  for (const [k,v] of Object.entries(settings)) upd.run(k,String(v));
  res.json({success:true});
});

// Maintenance toggle
app.post('/admin/maintenance', adminAuth, (req,res) => {
  db.prepare('INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)').run('maintenance', req.body.on?'1':'0');
  res.json({success:true});
});

// ══════════════════════════════════════════
// CRON: hourly earnings tick
// ══════════════════════════════════════════
setInterval(() => {
  const invs = db.prepare(`SELECT * FROM investments WHERE status='active'`).all();
  invs.forEach(inv => {
    db.prepare('UPDATE investments SET pending_earn=pending_earn+? WHERE id=?').run(inv.daily_earn/24, inv.id);
  });
  console.log(`[CRON] Ticked ${invs.length} investments`);
}, 60*60*1000);

setInterval(() => {
  db.prepare('UPDATE users SET today_earned=0').run();
}, 24*60*60*1000);

app.listen(PORT, () => console.log(`✅ Backend on port ${PORT}`));
