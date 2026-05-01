// ===== THEDON~ - Backend =====
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'thedon-secret-change-me';

// ===== ADMIN =====
const ADMIN_EMAIL = 'baraazarouali11@gmail.com';
const ADMIN_PASSWORD = 'Dandana2011';

// ===== VISITEURS EN TEMPS RÉEL =====
const activeVisitors = new Map();
function cleanVisitors() {
  const now = Date.now();
  for (const [ip, ts] of activeVisitors) {
    if (now - ts > 5 * 60 * 1000) activeVisitors.delete(ip);
  }
}
setInterval(cleanVisitors, 30000);

// ===== EVENTS POUR ADMIN (SSE) =====
const adminClients = new Set();
function notifyAdmin(event, data) {
  const msg = `data: ${JSON.stringify({ event, ...data })}\n\n`;
  for (const res of adminClients) {
    try { res.write(msg); } catch {}
  }
}

// ===== DETECT DEVICE =====
function detectDevice(ua = '') {
  if (!ua) return 'Inconnu';
  ua = ua.toLowerCase();
  // Mobiles
  if (ua.includes('iphone')) return 'iPhone';
  if (ua.includes('ipad')) return 'iPad';
  if (ua.includes('samsung')) {
    const m = ua.match(/samsung-([a-z0-9-]+)/i) || ua.match(/sm-([a-z0-9]+)/i);
    return 'Samsung ' + (m ? m[1].toUpperCase() : 'Galaxy');
  }
  if (ua.includes('huawei') || ua.includes('hmscore')) return 'Huawei';
  if (ua.includes('xiaomi') || ua.includes('redmi')) return 'Xiaomi';
  if (ua.includes('oppo')) return 'OPPO';
  if (ua.includes('oneplus')) return 'OnePlus';
  if (ua.includes('realme')) return 'Realme';
  if (ua.includes('pixel')) return 'Google Pixel';
  if (ua.includes('android')) return 'Android';
  // PC/Mac
  if (ua.includes('macintosh') || ua.includes('mac os x')) {
    if (ua.includes('chrome')) return 'Mac · Chrome';
    if (ua.includes('safari')) return 'Mac · Safari';
    if (ua.includes('firefox')) return 'Mac · Firefox';
    return 'Mac';
  }
  if (ua.includes('windows')) {
    if (ua.includes('chrome')) return 'PC · Chrome';
    if (ua.includes('firefox')) return 'PC · Firefox';
    if (ua.includes('edge')) return 'PC · Edge';
    return 'PC · Windows';
  }
  if (ua.includes('linux')) return 'PC · Linux';
  return 'Appareil inconnu';
}

// ===== DATABASE =====
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render.com')
    ? { rejectUnauthorized: false }
    : false
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      device VARCHAR(100),
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      order_num VARCHAR(20) UNIQUE NOT NULL,
      first_name VARCHAR(100),
      last_name VARCHAR(100),
      email VARCHAR(255),
      phone VARCHAR(50),
      address TEXT,
      zip VARCHAR(20),
      city VARCHAR(100),
      country VARCHAR(100),
      size VARCHAR(10),
      total_cents INTEGER,
      device VARCHAR(100),
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log('✓ Database ready');
}

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

// ===== PING VISITEUR =====
app.post('/api/ping', (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown-' + Math.random();
  activeVisitors.set(ip, Date.now());
  res.json({ ok: true, count: activeVisitors.size });
});

// ===== SSE ADMIN (notifications en temps réel) =====
app.get('/api/admin/events', (req, res) => {
  const auth = req.headers.authorization || req.query.token;
  if (!auth) return res.status(401).end();
  try {
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : auth;
    const payload = jwt.verify(token, JWT_SECRET);
    if (!payload.isAdmin) return res.status(403).end();
  } catch { return res.status(401).end(); }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();
  res.write('data: {"event":"connected"}\n\n');

  adminClients.add(res);
  req.on('close', () => adminClients.delete(res));
});

// ===== AUTH MIDDLEWARE =====
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Non connecté' });
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Session expirée' });
  }
}
function requireAdmin(req, res, next) {
  if (!req.user || !req.user.isAdmin) return res.status(403).json({ error: 'Admin uniquement' });
  next();
}

// ===== ROUTES AUTH =====
app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password || password.length < 4) {
      return res.status(400).json({ error: 'Email et code (4 car. min) requis' });
    }
    const lower = email.toLowerCase().trim();
    if (lower === ADMIN_EMAIL.toLowerCase()) return res.status(400).json({ error: 'Adresse réservée' });
    const exists = await pool.query('SELECT id FROM users WHERE email=$1', [lower]);
    if (exists.rowCount > 0) return res.status(400).json({ error: 'Compte déjà existant' });
    const hash = await bcrypt.hash(password, 10);
    const device = detectDevice(req.headers['user-agent']);
    await pool.query('INSERT INTO users (email, password_hash, device) VALUES ($1, $2, $3)', [lower, hash, device]);
    const token = jwt.sign({ email: lower, isAdmin: false }, JWT_SECRET, { expiresIn: '30d' });
    // Notif admin
    notifyAdmin('new_user', { email: lower, device, time: new Date().toISOString() });
    res.json({ token, email: lower, isAdmin: false });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email et code requis' });
    const lower = email.toLowerCase().trim();
    const result = await pool.query('SELECT * FROM users WHERE email=$1', [lower]);
    if (result.rowCount === 0) return res.status(401).json({ error: 'Aucun compte trouvé' });
    const ok = await bcrypt.compare(password, result.rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'Code incorrect' });
    const token = jwt.sign({ email: lower, isAdmin: false }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, email: lower, isAdmin: false });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email et code requis' });
    const lower = email.toLowerCase().trim();
    if (lower !== ADMIN_EMAIL.toLowerCase() || password !== ADMIN_PASSWORD) {
      return res.status(401).json({ error: 'Identifiants admin incorrects' });
    }
    const token = jwt.sign({ email: lower, isAdmin: true }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, email: lower, isAdmin: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ email: req.user.email, isAdmin: req.user.isAdmin });
});

// ===== COMMANDES =====
app.post('/api/order', async (req, res) => {
  try {
    const { firstName, lastName, email, phone, address, zip, city, country, size } = req.body;
    if (!firstName || !lastName || !email || !phone || !address || !zip || !city || !country || !size) {
      return res.status(400).json({ error: 'Tous les champs sont requis' });
    }
    const orderNum = 'VG-' + Math.floor(100000 + Math.random() * 900000);
    const device = detectDevice(req.headers['user-agent']);
    await pool.query(
      `INSERT INTO orders (order_num, first_name, last_name, email, phone, address, zip, city, country, size, total_cents, device)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [orderNum, firstName, lastName, email, phone, address, zip, city, country, size, 2500, device]
    );
    // Notif admin EN TEMPS RÉEL
    notifyAdmin('new_order', {
      orderNum, firstName, lastName, email, phone,
      address: `${address}, ${zip} ${city}, ${country}`,
      size, total: 25, device,
      time: new Date().toISOString()
    });
    res.json({ orderNum, success: true, total: 25 });
  } catch (e) {
    console.error('Order error:', e);
    res.status(500).json({ error: 'Erreur lors de la commande' });
  }
});

// ===== ADMIN =====
app.get('/api/admin/orders', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM orders ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: 'Erreur serveur' }); }
});

app.delete('/api/admin/orders/:orderNum', requireAuth, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM orders WHERE order_num=$1', [req.params.orderNum]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Erreur serveur' }); }
});

app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT email, device, created_at FROM users ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: 'Erreur serveur' }); }
});

app.get('/api/admin/stats', requireAuth, requireAdmin, async (req, res) => {
  try {
    const orders = await pool.query("SELECT COUNT(*)::int AS c, COALESCE(SUM(total_cents),0)::int AS total FROM orders");
    const today = await pool.query("SELECT COUNT(*)::int AS c FROM orders WHERE created_at::date = CURRENT_DATE");
    const users = await pool.query('SELECT COUNT(*)::int AS c FROM users');
    cleanVisitors();
    res.json({
      totalOrders: orders.rows[0].c,
      revenueCents: orders.rows[0].total,
      ordersToday: today.rows[0].c,
      totalUsers: users.rows[0].c,
      realVisitors: activeVisitors.size
    });
  } catch (e) { res.status(500).json({ error: 'Erreur serveur' }); }
});

// ===== START =====
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`✓ THEDON~ server on port ${PORT}`);
  });
}).catch(err => {
  console.error('DB init failed:', err);
  process.exit(1);
});
