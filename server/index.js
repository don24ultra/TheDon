// ===== VAGUE THEDON - Backend =====
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'vague-thedon-secret-change-me';

// ===== ADMIN HARDCODÉ (comme demandé) =====
const ADMIN_EMAIL = 'baraazarouali11@gmail.com';
const ADMIN_PASSWORD = 'Dandana2011';

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
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log('✓ Database ready');
}

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

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
      return res.status(400).json({ error: 'Email et code (4 caractères min) requis' });
    }
    const lower = email.toLowerCase().trim();
    if (lower === ADMIN_EMAIL.toLowerCase()) {
      return res.status(400).json({ error: 'Cette adresse est réservée' });
    }
    const exists = await pool.query('SELECT id FROM users WHERE email=$1', [lower]);
    if (exists.rowCount > 0) return res.status(400).json({ error: 'Compte déjà existant' });
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)', [lower, hash]);
    const token = jwt.sign({ email: lower, isAdmin: false }, JWT_SECRET, { expiresIn: '30d' });
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

// Connexion ADMIN — séparée pour la sécurité
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
// Note : pas besoin d'être connecté pour commander, juste l'email
app.post('/api/order', async (req, res) => {
  try {
    const { firstName, lastName, email, phone, address, zip, city, country, size } = req.body;
    if (!firstName || !lastName || !email || !phone || !address || !zip || !city || !country || !size) {
      return res.status(400).json({ error: 'Tous les champs sont requis' });
    }
    const orderNum = 'VG-' + Math.floor(100000 + Math.random() * 900000);
    await pool.query(
      `INSERT INTO orders (order_num, first_name, last_name, email, phone, address, zip, city, country, size, total_cents)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [orderNum, firstName, lastName, email, phone, address, zip, city, country, size, 2500]
    );
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
    const result = await pool.query('SELECT email, created_at FROM users ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: 'Erreur serveur' }); }
});

app.get('/api/admin/stats', requireAuth, requireAdmin, async (req, res) => {
  try {
    const orders = await pool.query("SELECT COUNT(*)::int AS c, COALESCE(SUM(total_cents),0)::int AS total FROM orders");
    const today = await pool.query("SELECT COUNT(*)::int AS c FROM orders WHERE created_at::date = CURRENT_DATE");
    const users = await pool.query('SELECT COUNT(*)::int AS c FROM users');
    res.json({
      totalOrders: orders.rows[0].c,
      revenueCents: orders.rows[0].total,
      ordersToday: today.rows[0].c,
      totalUsers: users.rows[0].c
    });
  } catch (e) { res.status(500).json({ error: 'Erreur serveur' }); }
});

// ===== START =====
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`✓ VAGUE THEDON server on port ${PORT}`);
    console.log(`✓ Admin: ${ADMIN_EMAIL}`);
  });
}).catch(err => {
  console.error('DB init failed:', err);
  process.exit(1);
});
