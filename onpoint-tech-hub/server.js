const express = require('express'), { Pool } = require('pg'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'), crypto = require('crypto');
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));
app.use((req, res, next) => { res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin' }); next(); });

const BR = ['Maseno', 'Kisumu', 'Nairobi'], ST = ['Received', 'In repair', 'Ready', 'Collected'];
const JWT = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const EK = crypto.createHash('sha256').update(process.env.ENCRYPTION_KEY || 'dev-only-change-me').digest();
const url = process.env.DATABASE_URL || '';
const pool = new Pool({ connectionString: url, ssl: url && !/localhost|127\.0\.0\.1/.test(url) ? { rejectUnauthorized: false } : false });

const enc = t => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', EK, iv), b = Buffer.concat([c.update(t, 'utf8'), c.final()]); return [iv, c.getAuthTag(), b].map(x => x.toString('base64')).join('.'); };
const dec = t => { const [iv, tag, b] = t.split('.').map(x => Buffer.from(x, 'base64')), d = crypto.createDecipheriv('aes-256-gcm', EK, iv); d.setAuthTag(tag); return Buffer.concat([d.update(b), d.final()]).toString('utf8'); };

const q = (t, p) => pool.query(t, p);
async function tx(fn) { const c = await pool.connect(); try { await c.query('BEGIN'); const r = await fn(c); await c.query('COMMIT'); return r; } catch (e) { await c.query('ROLLBACK'); throw e; } finally { c.release(); } }
const kvGet = async (c, k) => { const r = await c.query('SELECT value FROM kv WHERE key=$1 FOR UPDATE', [k]); return r.rows[0] ? r.rows[0].value : null; };
const kvSet = (c, k, v) => c.query('INSERT INTO kv(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=$2', [k, JSON.stringify(v)]);
const nextNo = async (c, k, start) => (await c.query("INSERT INTO kv(key,value) VALUES($1,$2::jsonb) ON CONFLICT(key) DO UPDATE SET value=to_jsonb((kv.value#>>'{}')::int+1) RETURNING value", [k, String(start)])).rows[0].value;
const aud = (c, req, b, a) => c.query("INSERT INTO docs(coll,branch,data) VALUES('audit',$1,$2)", [b || req.u.branch, { u: req.u.name, a }]);
const bad = (m, s = 400) => { const e = new Error(m); e.status = s; throw e; };
const h = f => (req, res) => f(req, res).catch(e => { if (!e.status) console.error(e); res.status(e.status || 500).json({ error: e.status ? e.message : 'Server error. Try again.' }); });
const brOf = req => req.u.branch === 'All' ? (BR.includes(req.body.branch) ? req.body.branch : null) : req.u.branch;
function auth(...roles) {
  return (req, res, next) => {
    try { req.u = jwt.verify((req.headers.authorization || '').slice(7), JWT); } catch (e) { return res.status(401).json({ error: 'Please sign in again' }); }
    if (roles.length && !roles.includes(req.u.role)) return res.status(403).json({ error: 'Your role cannot do that' });
    next();
  };
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY,name TEXT,role TEXT,branch TEXT,pin_hash TEXT);
CREATE TABLE IF NOT EXISTS docs(id SERIAL PRIMARY KEY,coll TEXT,branch TEXT,data JSONB,created_at TIMESTAMPTZ DEFAULT now());
CREATE INDEX IF NOT EXISTS docs_coll ON docs(coll);
CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY,value JSONB);`;

async function init() {
  await q(SCHEMA);
  if ((await q('SELECT 1 FROM users LIMIT 1')).rowCount) return;
  const pin = process.env.OWNER_PIN || '1234';
  for (const [n, r, b, p] of [['Owner', 'Owner', 'All', pin], ['Branch Manager', 'Manager', 'Kisumu', '2222'], ['Cashier', 'Cashier', 'Kisumu', '3333'], ['Technician', 'Technician', 'Kisumu', '4444']])
    await q('INSERT INTO users(name,role,branch,pin_hash) VALUES($1,$2,$3,$4)', [n, r, b, bcrypt.hashSync(p, 10)]);
  const ins = async (coll, d, b) => (await q('INSERT INTO docs(coll,branch,data) VALUES($1,$2,$3) RETURNING id', [coll, b || null, d])).rows[0].id;
  for (const [name, price] of [['Printing B/W (page)', 10], ['Printing colour (page)', 30], ['Photocopy (page)', 5], ['Scanning', 20], ['Typing (page)', 50], ['KRA / eCitizen application', 300], ['HELB / KUCCPS / SHA application', 200], ['Passport photos', 250], ['Lamination', 50], ['CV writing', 500]]) await ins('services', { name, price });
  for (const [name, price, cost] of [['Phone charger 20W', 900, 450], ['Earphones', 600, 250], ['Flash disk 32GB', 900, 500]]) await ins('products', { name, price, cost, stock: { Maseno: 0, Kisumu: 0, Nairobi: 0 } });
  const gas = { Maseno: {}, Kisumu: {}, Nairobi: {} };
  for (const [brand, size, exch, comp] of [['K-Gas', 6, 1300, 3500], ['K-Gas', 13, 2700, 6800], ['Total', 6, 1300, 3600], ['Total', 13, 2700, 7000], ['ProGas', 22.5, 4600, 11500]]) {
    const id = await ins('cyl', { brand, size, exch, comp });
    BR.forEach(b => gas[b][id] = { full: 0, empty: 0 });
  }
  const set = (k, v) => q('INSERT INTO kv(key,value) VALUES($1,$2)', [k, JSON.stringify(v)]);
  await set('gas', gas); await set('tank', { Maseno: 0, Kisumu: 0, Nairobi: 0 }); await set('rate', 200); await set('cbsecret', crypto.randomBytes(16).toString('hex'));
  console.log('Database seeded. Sign in as Owner and add your real stock.');
}

/* ---------- auth ---------- */
const tries = {};
app.get('/healthz', (req, res) => res.send('ok'));
app.get('/api/users-public', h(async (req, res) => res.json((await q('SELECT id,name,role,branch AS b FROM users ORDER BY id')).rows)));
app.post('/api/login', h(async (req, res) => {
  const t = tries[req.ip] = (tries[req.ip] || []).filter(x => Date.now() - x < 60000);
  if (t.length >= 5) bad('Too many attempts. Wait a minute.', 429);
  const u = (await q('SELECT * FROM users WHERE id=$1', [+req.body.userId || 0])).rows[0];
  if (!u || !(await bcrypt.compare(String(req.body.pin || ''), u.pin_hash))) { t.push(Date.now()); bad('Wrong PIN', 401); }
  const me = { id: u.id, name: u.name, role: u.role, branch: u.branch };
  await q("INSERT INTO docs(coll,branch,data) VALUES('audit',$1,$2)", [u.branch, { u: u.name, a: 'Signed in' }]);
  res.json({ token: jwt.sign(me, JWT, { expiresIn: '12h' }), user: { ...me, b: u.branch } });
}));
app.get('/api/me', auth(), (req, res) => res.json({ id: req.u.id, name: req.u.name, role: req.u.role, b: req.u.branch }));
app.put('/api/users/:id/pin', auth('Owner'), h(async (req, res) => {
  const pin = String(req.body.pin || '');
  if (!/^\d{4,8}$/.test(pin)) bad('PIN must be 4 to 8 digits');
  await tx(async c => { const u = (await c.query('UPDATE users SET pin_hash=$2 WHERE id=$1 RETURNING name', [req.params.id, bcrypt.hashSync(pin, 10)])).rows[0]; if (!u) bad('No such user', 404); await aud(c, req, null, 'PIN changed for ' + u.name); });
  res.json({ ok: true });
}));

/* ---------- state ---------- */
const rows = async (coll, lim) => (await q('SELECT id,branch,data,created_at FROM docs WHERE coll=$1 ORDER BY id DESC' + (lim ? ' LIMIT ' + lim : ''), [coll])).rows.reverse();
const mapD = r => ({ ...r.data, id: r.id, b: r.branch, t: r.created_at });
app.get('/api/state', auth(), h(async (req, res) => {
  const own = req.u.branch === 'All', mine = x => own || x.b === req.u.branch, role = req.u.role;
  const kvs = Object.fromEntries((await q("SELECT key,value FROM kv WHERE key IN ('gas','tank','rate')")).rows.map(r => [r.key, r.value]));
  const repairs = role === 'Cashier' ? [] : (await rows('repairs', 1000)).map(mapD).filter(mine);
  if (role === 'Cashier') repairs.forEach(r => delete r.pw);
  res.json({
    rate: kvs.rate, tank: kvs.tank, gasStock: kvs.gas,
    services: (await rows('services')).map(mapD),
    products: (await rows('products')).map(mapD),
    cyl: (await rows('cyl')).map(r => ({ ...mapD(r), id: String(r.id) })),
    sales: (await rows('sales', 3000)).map(r => ({ ...mapD(r), id: r.data.no })).filter(mine),
    repairs, expenses: ['Owner', 'Manager'].includes(role) ? (await rows('expenses', 1000)).map(mapD).filter(mine) : [],
    audit: own ? (await rows('audit', 200)).map(r => ({ t: r.created_at, u: r.data.u, b: r.branch, a: r.data.a })) : [],
    users: role === 'Owner' ? (await q('SELECT id,name,role,branch AS b FROM users ORDER BY id')).rows : []
  });
}));

/* ---------- sales ---------- */
app.post('/api/sales', auth('Owner', 'Manager', 'Cashier'), h(async (req, res) => {
  const b = brOf(req); if (!b) bad('Choose a branch');
  const { items = [], pay, cust = '', checkoutId } = req.body;
  let disc = Math.max(0, +req.body.disc || 0), ref = String(req.body.ref || '').trim().toUpperCase();
  if (!items.length || !['Cash', 'M-Pesa', 'Credit'].includes(pay)) bad('Invalid sale');
  if (pay === 'Credit' && !String(cust).trim()) bad('Enter the customer phone for a credit sale');
  const sale = await tx(async c => {
    const gas = await kvGet(c, 'gas'), tank = await kvGet(c, 'tank'), rate = await kvGet(c, 'rate'), lines = [];
    for (const it of items) {
      const n = Math.floor(+it.q), t = String(it.k)[0], id = String(it.k).slice(1);
      if (!(n > 0)) bad('Invalid quantity');
      if (t === 's') { const d = (await c.query("SELECT data FROM docs WHERE id=$1 AND coll='services'", [+id || 0])).rows[0]; if (!d) bad('Unknown service'); lines.push({ n: d.data.name, q: n, p: d.data.price, ln: 'Cyber' }); }
      else if (t === 'p') {
        const p = (await c.query("SELECT data FROM docs WHERE id=$1 AND coll='products' FOR UPDATE", [+id || 0])).rows[0]?.data;
        if (!p) bad('Unknown product'); if ((p.stock[b] || 0) < n) bad(`${p.name}: only ${p.stock[b] || 0} in stock at ${b}`);
        p.stock[b] -= n; await c.query('UPDATE docs SET data=$2 WHERE id=$1', [+id, p]); lines.push({ n: p.name, q: n, p: p.price, ln: 'Electronics' });
      } else if (t === 'r') { if (tank[b] < n) bad(`Bulk tank has only ${tank[b]} kg at ${b}`); tank[b] -= n; lines.push({ n: 'Gas refill (per kg)', q: n, p: rate, ln: 'Gas' }); }
      else if (t === 'x' || t === 'c') {
        const cy = (await c.query("SELECT data FROM docs WHERE id=$1 AND coll='cyl'", [+id || 0])).rows[0]?.data, g = gas[b] && gas[b][id];
        if (!cy || !g) bad('Unknown cylinder'); const nm = `${cy.brand} ${cy.size}kg`;
        if (g.full < n) bad(`${nm}: only ${g.full} full cylinders at ${b}`);
        g.full -= n; if (t === 'x') g.empty += n;
        lines.push({ n: t === 'x' ? 'Exchange ' + nm : `Complete ${nm} (cylinder + gas)`, q: n, p: t === 'x' ? cy.exch : cy.comp, ln: 'Gas' });
      } else bad('Unknown item');
    }
    const sub = lines.reduce((s, l) => s + l.p * l.q, 0);
    disc = Math.min(disc, req.u.role === 'Cashier' ? Math.floor(sub * 0.05) : sub);
    const total = sub - disc;
    if (pay === 'M-Pesa') {
      if (checkoutId) {
        const m = (await c.query("SELECT id,data FROM docs WHERE coll='mpesa' AND data->>'checkoutId'=$1 FOR UPDATE", [String(checkoutId)])).rows[0];
        if (!m || m.data.status !== 'success') bad('That M-Pesa payment is not confirmed yet');
        if (m.data.used) bad('That M-Pesa payment was already used');
        if (+m.data.paid < total) bad(`Customer paid KES ${m.data.paid}, sale total is KES ${total}`);
        ref = m.data.receipt; m.data.used = true; await c.query('UPDATE docs SET data=$2 WHERE id=$1', [m.id, m.data]);
      } else if (ref.length < 8) bad('Enter the M-Pesa confirmation code');
    }
    const no = 'R' + await nextNo(c, 'seq', 1001);
    const d = { no, items: lines, total, disc, ref, by: req.u.name, pay, cust, settled: false };
    const r = (await c.query("INSERT INTO docs(coll,branch,data) VALUES('sales',$1,$2) RETURNING created_at", [b, d])).rows[0];
    await kvSet(c, 'gas', gas); await kvSet(c, 'tank', tank);
    await aud(c, req, b, `Sale ${no} KES ${total} ${pay}${disc ? ' (discount ' + disc + ')' : ''}`);
    return { ...d, id: no, b, t: r.created_at };
  });
  res.json(sale);
}));
app.post('/api/sales/:no/settle', auth('Owner', 'Manager', 'Cashier'), h(async (req, res) => {
  await tx(async c => {
    const r = (await c.query("SELECT id,branch,data FROM docs WHERE coll='sales' AND data->>'no'=$1 FOR UPDATE", [req.params.no])).rows[0];
    if (!r || (req.u.branch !== 'All' && r.branch !== req.u.branch)) bad('Sale not found', 404);
    r.data.settled = true; await c.query('UPDATE docs SET data=$2 WHERE id=$1', [r.id, r.data]); await aud(c, req, r.branch, `Credit sale ${req.params.no} marked paid`);
  }); res.json({ ok: true });
}));

/* ---------- repairs ---------- */
app.post('/api/repairs', auth('Owner', 'Manager', 'Technician'), h(async (req, res) => {
  const b = brOf(req), x = req.body; if (!b) bad('Choose a branch');
  if (!x.cust || !x.phone || !x.device || !x.issue) bad('Customer, phone, device and fault are required');
  const no = await tx(async c => {
    const no = 'JC-' + await nextNo(c, 'job', 1001);
    const d = { no, cust: x.cust, phone: x.phone, idno: x.idno, type: x.type, device: x.device, serial: x.serial, colour: x.colour, issue: x.issue, cond: x.cond, acc: Array.isArray(x.acc) ? x.acc : [], pw: x.pw, est: +x.est || 0, dep: +x.dep || 0, due: x.due, tech: x.tech, status: 'Received' };
    await c.query("INSERT INTO docs(coll,branch,data) VALUES('repairs',$1,$2)", [b, d]); await aud(c, req, b, `Repair job ${no} created for ${x.cust}`); return no;
  });
  res.json({ no });
}));
app.post('/api/repairs/:id/advance', auth('Owner', 'Manager', 'Technician'), h(async (req, res) => {
  await tx(async c => {
    const r = (await c.query("SELECT id,branch,data FROM docs WHERE id=$1 AND coll='repairs' FOR UPDATE", [+req.params.id || 0])).rows[0];
    if (!r || (req.u.branch !== 'All' && r.branch !== req.u.branch)) bad('Job not found', 404);
    const d = r.data, i = ST.indexOf(d.status); if (i >= ST.length - 1) bad('Already collected');
    d.status = ST[i + 1]; await c.query('UPDATE docs SET data=$2 WHERE id=$1', [r.id, d]);
    if (d.status === 'Collected' && d.est > 0) {
      const no = 'R' + await nextNo(c, 'seq', 1001);
      await c.query("INSERT INTO docs(coll,branch,data) VALUES('sales',$1,$2)", [r.branch, { no, items: [{ n: `Repair ${d.no} ${d.device}`, q: 1, p: d.est, ln: 'Electronics' }], total: d.est, disc: 0, ref: '', by: req.u.name, pay: 'Cash', cust: d.phone, settled: false }]);
    }
    await aud(c, req, r.branch, `${d.no} marked ${d.status}`);
  }); res.json({ ok: true });
}));

/* ---------- catalog, stock, expenses ---------- */
const MGR = auth('Owner', 'Manager');
app.post('/api/services', MGR, h(async (req, res) => { const n = String(req.body.name || '').trim(); if (!n) bad('Name required'); await tx(async c => { await c.query("INSERT INTO docs(coll,data) VALUES('services',$1)", [{ name: n, price: +req.body.price || 0 }]); await aud(c, req, null, 'Service added: ' + n); }); res.json({ ok: true }); }));
app.put('/api/services/:id', MGR, h(async (req, res) => {
  await tx(async c => { const r = (await c.query("SELECT data FROM docs WHERE id=$1 AND coll='services' FOR UPDATE", [+req.params.id || 0])).rows[0]; if (!r) bad('Not found', 404); const d = r.data, p = Math.max(0, +req.body.price || 0); await aud(c, req, null, `Price change: ${d.name} ${d.price} to ${p}`); d.price = p; await c.query('UPDATE docs SET data=$2 WHERE id=$1', [+req.params.id, d]); });
  res.json({ ok: true });
}));
app.post('/api/products', MGR, h(async (req, res) => {
  const b = brOf(req), n = String(req.body.name || '').trim(); if (!n || !b) bad('Name and branch required');
  const stock = { Maseno: 0, Kisumu: 0, Nairobi: 0 }; stock[b] = Math.max(0, Math.floor(+req.body.qty || 0));
  await tx(async c => { await c.query("INSERT INTO docs(coll,data) VALUES('products',$1)", [{ name: n, price: +req.body.price || 0, cost: +req.body.cost || 0, stock }]); await aud(c, req, b, 'Product added: ' + n); }); res.json({ ok: true });
}));
app.post('/api/products/:id/stock', MGR, h(async (req, res) => {
  const b = brOf(req), dl = Math.floor(+req.body.delta); if (!b || !dl) bad('Invalid change');
  await tx(async c => { const p = (await c.query("SELECT data FROM docs WHERE id=$1 AND coll='products' FOR UPDATE", [+req.params.id || 0])).rows[0]?.data; if (!p) bad('Not found', 404); p.stock[b] = Math.max(0, (p.stock[b] || 0) + dl); await c.query('UPDATE docs SET data=$2 WHERE id=$1', [+req.params.id, p]); await aud(c, req, b, `Stock ${dl > 0 ? '+' : ''}${dl}: ${p.name}`); });
  res.json({ ok: true });
}));
app.post('/api/transfer', MGR, h(async (req, res) => {
  const from = req.u.branch === 'All' ? req.body.from : req.u.branch, to = req.body.to, n = Math.floor(+req.body.qty);
  if (!BR.includes(from) || !BR.includes(to) || from === to || !(n > 0)) bad('Invalid transfer');
  await tx(async c => { const p = (await c.query("SELECT data FROM docs WHERE id=$1 AND coll='products' FOR UPDATE", [+req.body.id || 0])).rows[0]?.data; if (!p) bad('Unknown product'); if ((p.stock[from] || 0) < n) bad('Not enough stock at ' + from); p.stock[from] -= n; p.stock[to] = (p.stock[to] || 0) + n; await c.query('UPDATE docs SET data=$2 WHERE id=$1', [+req.body.id, p]); await aud(c, req, from, `Transfer ${n} x ${p.name} from ${from} to ${to}`); });
  res.json({ ok: true });
}));
app.post('/api/expenses', MGR, h(async (req, res) => {
  const b = brOf(req), a = +req.body.amt; if (!b || !(a > 0)) bad('Amount required');
  await tx(async c => { await c.query("INSERT INTO docs(coll,branch,data) VALUES('expenses',$1,$2)", [b, { c: req.body.c, n: req.body.n || '', amt: a }]); await aud(c, req, b, `Expense ${req.body.c} KES ${a}`); }); res.json({ ok: true });
}));

/* ---------- gas ---------- */
const gasOp = fn => h(async (req, res) => { const b = brOf(req); if (!b) bad('Choose a branch'); await tx(c => fn(c, b, req)); res.json({ ok: true }); });
app.post('/api/gas/stock', MGR, gasOp(async (c, b, req) => { const g = await kvGet(c, 'gas'), x = g[b][req.body.id]; if (!x) bad('Unknown cylinder'); const n = Math.max(0, Math.floor(+req.body.full || 0)); x.full += n; await kvSet(c, 'gas', g); await aud(c, req, b, `Received ${n} full cylinders`); }));
app.post('/api/gas/refill-empties', MGR, gasOp(async (c, b, req) => { const g = await kvGet(c, 'gas'), x = g[b][req.body.id]; if (!x) bad('Unknown cylinder'); const n = x.empty; x.full += n; x.empty = 0; await kvSet(c, 'gas', g); await aud(c, req, b, `Refilled ${n} empty cylinders`); }));
app.post('/api/gas/tank', MGR, gasOp(async (c, b, req) => { const t = await kvGet(c, 'tank'), kg = +req.body.kg || 0; t[b] = Math.max(0, t[b] + kg); await kvSet(c, 'tank', t); await aud(c, req, b, `Bulk tank ${kg > 0 ? '+' : ''}${kg} kg`); }));
app.put('/api/gas/rate', auth('Owner'), h(async (req, res) => { await tx(async c => { await kvSet(c, 'rate', Math.max(0, +req.body.rate || 0)); await aud(c, req, null, 'Gas rate set to ' + req.body.rate); }); res.json({ ok: true }); }));

/* ---------- M-Pesa Daraja ---------- */
const mpGet = async () => { const r = (await q("SELECT value FROM kv WHERE key='mpesa'")).rows[0]; return r ? JSON.parse(dec(r.value)) : null; };
const dBase = c => c.env === 'production' ? 'https://api.safaricom.co.ke' : 'https://sandbox.safaricom.co.ke';
const origin = req => (process.env.BASE_URL || `${req.protocol}://${req.get('host')}`).replace(/\/$/, '');
async function dToken(c) {
  const r = await fetch(dBase(c) + '/oauth/v1/generate?grant_type=client_credentials', { headers: { Authorization: 'Basic ' + Buffer.from(c.consumerKey + ':' + c.consumerSecret).toString('base64') } });
  if (!r.ok) bad(`Daraja rejected the keys (${r.status}). Check the key, secret and environment.`);
  return (await r.json()).access_token;
}
app.get('/api/settings/mpesa', auth('Owner'), h(async (req, res) => {
  const c = await mpGet() || {}, sec = (await q("SELECT value FROM kv WHERE key='cbsecret'")).rows[0].value;
  res.json({ configured: !!(c.consumerKey && c.consumerSecret && c.shortcode && c.passkey), env: c.env || 'sandbox', txType: c.txType || 'CustomerPayBillOnline', shortcode: c.shortcode || '', partyB: c.partyB || '', accountRef: c.accountRef || 'OnPoint', hasKey: !!c.consumerKey, keyHint: c.consumerKey ? '...' + c.consumerKey.slice(-4) : '', hasSecret: !!c.consumerSecret, hasPasskey: !!c.passkey, callbackUrl: `${origin(req)}/api/mpesa/callback/${sec}` });
}));
app.put('/api/settings/mpesa', auth('Owner'), h(async (req, res) => {
  const c = await mpGet() || {}, b = req.body;
  for (const k of ['env', 'txType', 'shortcode', 'partyB', 'accountRef', 'consumerKey', 'consumerSecret', 'passkey']) if (typeof b[k] === 'string' && (b[k].trim() || ['partyB', 'accountRef'].includes(k))) c[k] = b[k].trim();
  if (!['sandbox', 'production'].includes(c.env)) c.env = 'sandbox';
  await tx(async cl => { await cl.query("INSERT INTO kv(key,value) VALUES('mpesa',$1) ON CONFLICT(key) DO UPDATE SET value=$1", [JSON.stringify(enc(JSON.stringify(c)))]); await aud(cl, req, null, 'M-Pesa settings updated (' + c.env + ')'); });
  res.json({ ok: true });
}));
app.post('/api/mpesa/test', auth('Owner'), h(async (req, res) => { const c = await mpGet(); if (!c || !c.consumerKey || !c.consumerSecret) bad('Save your consumer key and secret first'); await dToken(c); res.json({ ok: true }); }));
app.post('/api/mpesa/stkpush', auth('Owner', 'Manager', 'Cashier'), h(async (req, res) => {
  const c = await mpGet(); if (!c || !c.shortcode || !c.passkey) bad('M-Pesa is not set up yet. The Owner can add the Daraja keys under Settings.');
  let ph = String(req.body.phone || '').replace(/\D/g, ''); if (ph.startsWith('0')) ph = '254' + ph.slice(1); else if (/^[17]/.test(ph)) ph = '254' + ph;
  if (!/^254[17]\d{8}$/.test(ph)) bad('Enter a valid Safaricom number like 0712345678');
  const amt = Math.ceil(+req.body.amount); if (!(amt >= 1)) bad('Invalid amount');
  const ts = new Date().toISOString().replace(/\D/g, '').slice(0, 14), sec = (await q("SELECT value FROM kv WHERE key='cbsecret'")).rows[0].value;
  const r = await fetch(dBase(c) + '/mpesa/stkpush/v1/processrequest', { method: 'POST', headers: { Authorization: 'Bearer ' + await dToken(c), 'Content-Type': 'application/json' }, body: JSON.stringify({ BusinessShortCode: c.shortcode, Password: Buffer.from(c.shortcode + c.passkey + ts).toString('base64'), Timestamp: ts, TransactionType: c.txType || 'CustomerPayBillOnline', Amount: amt, PartyA: ph, PartyB: c.partyB || c.shortcode, PhoneNumber: ph, CallBackURL: `${origin(req)}/api/mpesa/callback/${sec}`, AccountReference: (c.accountRef || 'OnPoint').slice(0, 12), TransactionDesc: 'OnPoint payment' }) });
  const j = await r.json().catch(() => ({}));
  if (j.ResponseCode !== '0') bad('M-Pesa: ' + (j.errorMessage || j.ResponseDescription || 'request failed'));
  await q("INSERT INTO docs(coll,branch,data) VALUES('mpesa',$1,$2)", [req.u.branch === 'All' ? null : req.u.branch, { checkoutId: j.CheckoutRequestID, phone: ph, amount: amt, status: 'pending' }]);
  res.json({ checkoutId: j.CheckoutRequestID });
}));
app.post('/api/mpesa/callback/:s', h(async (req, res) => {
  const sec = (await q("SELECT value FROM kv WHERE key='cbsecret'")).rows[0].value;
  if (req.params.s !== sec) return res.status(403).end();
  const cb = req.body && req.body.Body && req.body.Body.stkCallback;
  if (cb) {
    const it = Object.fromEntries(((cb.CallbackMetadata && cb.CallbackMetadata.Item) || []).map(i => [i.Name, i.Value]));
    await q("UPDATE docs SET data=data||$2::jsonb WHERE coll='mpesa' AND data->>'checkoutId'=$1", [cb.CheckoutRequestID, JSON.stringify({ status: cb.ResultCode === 0 ? 'success' : 'failed', desc: cb.ResultDesc, receipt: it.MpesaReceiptNumber, paid: it.Amount })]);
  }
  res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
}));
app.get('/api/mpesa/tx/:id', auth(), h(async (req, res) => {
  const m = (await q("SELECT data FROM docs WHERE coll='mpesa' AND data->>'checkoutId'=$1", [req.params.id])).rows[0];
  if (!m) bad('Unknown payment', 404); res.json({ status: m.data.status, receipt: m.data.receipt, desc: m.data.desc, amount: m.data.paid || m.data.amount });
}));

app.use(express.static(__dirname + '/public'));
init().then(() => app.listen(process.env.PORT || 3000, () => console.log('OnPoint Tech Hub running'))).catch(e => { console.error('Startup failed:', e.message); process.exit(1); });
