require('dotenv').config(); // โหลดค่าจากไฟล์ .env
const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const JWT_SECRET = process.env.JWT_SECRET || 'nexphone_dev_secret';
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) {
  console.error('❌ ไม่พบ DATABASE_URL ใน .env — ต้องตั้งค่าให้ชี้ไปที่ฐานข้อมูล Neon (Postgres)');
}

// เชื่อมต่อ Neon (Postgres) ผ่าน connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const defaultProducts = [
  ['iPhone 14 Pro Max', 'สมาร์ทโฟนระดับโปร', 49999, 'images/iphone-14-pro-max.jpg'],
  ['iPhone 14 Pro', 'สมาร์ทโฟนระดับโปร', 44999, 'images/iphone-14-pro.jpg'],
  ['Samsung S24 Ultra', 'เรือธงจาก Samsung', 47999, 'images/samsung-s24-ultra.png'],
  ['Samsung Galaxy S24', 'สมาร์ทโฟนรุ่นยอดนิยม', 42999, 'images/samsung-galaxy-s24.png'],
  ['Google Pixel 8 Pro', 'กล้อง AI ระดับพรีเมียม', 44999, 'images/pixel-8-pro.jpg'],
  ['Google Pixel 8', 'ใช้งานง่ายและถ่ายภาพสวย', 35999, 'images/pixel-8.jpg'],
  ['Xiaomi 14 Ultra', 'กล้องและประสิทธิภาพแรง', 38999, 'images/xiaomi-14-ultra.jpg'],
  ['Xiaomi 14', 'ประสิทธิภาพสูง ราคาดี', 28999, 'images/xiaomi-14.jpg'],
  ['OnePlus 12', 'เน้นความเร็วและอุณหภูมิ', 32999, 'images/oneplus-12.jpg'],
  ['Nothing Phone 2', 'ดีไซน์โดดเด่นและล้ำ', 25999, 'images/nothing-phone-2.png'],
  ['OPPO Find X7', 'โฟกัสกล้องและสไตล์', 30999, 'images/oppo-find-x7.jpg'],
  ['Vivo X100', 'กล้องคมชัดและเร็ว', 31999, 'images/vivo-x100.jpg'],
  ['Samsung Galaxy Z Fold6', 'สมาร์ทโฟนพับได้สุดล้ำ', 59999, 'images/มือถือใหม่-removebg-preview.png'],
  ['Asus Zenfone 10', 'มือถือขนาดกะทัดรัดและแรง', 26999, 'images/29598.jpg'],
  ['Realme GT 6', 'ประสิทธิภาพแรงในราคาย่อมเยา', 24999, 'images/29598.jpg']
];

// ฟังก์ชันส่งการแจ้งเตือนเข้า Discord Webhook
async function sendDiscordNotification(title, description, color = 3447003) {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
  if (!webhookUrl) return;

  try {
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        embeds: [{ title, description, color, timestamp: new Date().toISOString() }]
      })
    });
  } catch (err) {
    console.error('Discord Webhook Error:', err);
  }
}

// Simple symmetric encryption for reversible passwords
const ENC_ALGO = 'aes-256-cbc';
const ENC_KEY = crypto.createHash('sha256')
  .update(process.env.ENC_KEY || 'nexphone_dev_enc_key')
  .digest();

function encryptText(plain) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ENC_ALGO, ENC_KEY, iv);
  let encrypted = cipher.update(String(plain), 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return iv.toString('base64') + ':' + encrypted;
}

function decryptText(payload) {
  try {
    const parts = payload.split(':');
    const iv = Buffer.from(parts[0], 'base64');
    const enc = parts[1];
    const decipher = crypto.createDecipheriv(ENC_ALGO, ENC_KEY, iv);
    let dec = decipher.update(enc, 'base64', 'utf8');
    dec += decipher.final('utf8');
    return dec;
  } catch (e) {
    return null;
  }
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ---------------------------------------------------------------------------
// สร้างตาราง + seed ข้อมูลเริ่มต้นใน Neon (Postgres)
// ---------------------------------------------------------------------------
async function initDb() {
  await pool.query(`CREATE TABLE IF NOT EXISTS products (
    id SERIAL PRIMARY KEY,
    title TEXT,
    description TEXT,
    price INTEGER,
    image TEXT
  )`);

  await pool.query(`CREATE TABLE IF NOT EXISTS contacts (
    id SERIAL PRIMARY KEY,
    name TEXT,
    email TEXT,
    phone TEXT,
    subject TEXT,
    message TEXT,
    created_at TIMESTAMP DEFAULT NOW()
  )`);

  await pool.query(`CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
    order_code TEXT UNIQUE,
    product_title TEXT,
    price INTEGER,
    quantity INTEGER DEFAULT 1,
    customer_name TEXT,
    customer_email TEXT,
    image TEXT,
    created_at TIMESTAMP DEFAULT NOW()
  )`);

  // ตารางบัญชีผู้ใช้ (สมัครสมาชิก / ล็อกอิน) พร้อมเก็บเวลาล็อกอินล่าสุด
  await pool.query(`CREATE TABLE IF NOT EXISTS logins (
    id SERIAL PRIMARY KEY,
    name TEXT,
    email TEXT UNIQUE,
    password_enc TEXT,
    role TEXT DEFAULT 'user',
    created_at TIMESTAMP DEFAULT NOW(),
    last_login_at TIMESTAMP
  )`);

  // เผื่อฐานข้อมูลเก่ายังไม่มีคอลัมน์นี้ (อัปเกรดแบบไม่ทำลายข้อมูลเดิม)
  await pool.query(`ALTER TABLE logins ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP`);

  // Seed admin user if not exists
  const adminRow = await pool.query('SELECT id FROM logins WHERE email = $1', ['admin@nexphone.local']);
  if (adminRow.rows.length === 0) {
    const enc = encryptText('1234');
    await pool.query(
      'INSERT INTO logins (name, email, password_enc, role) VALUES ($1,$2,$3,$4)',
      ['Admin', 'admin@nexphone.local', enc, 'admin']
    );
    console.log('Seeded admin login -> email: admin@nexphone.local password: 1234');
  }

  // Restore product catalog if missing or incomplete
  const countRow = await pool.query('SELECT COUNT(*) AS count FROM products');
  const count = Number(countRow.rows[0]?.count || 0);
  if (count < defaultProducts.length) {
    await pool.query('DELETE FROM products');
    for (const product of defaultProducts) {
      await pool.query(
        'INSERT INTO products (title, description, price, image) VALUES ($1,$2,$3,$4)',
        product
      );
    }
    console.log('Restored default products');
  }
}

const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: '30mb' }));
app.use(express.static(path.join(__dirname)));

app.get('/', (req, res) => {
  const indexPath = path.join(__dirname, 'index.html');
  if (fs.existsSync(indexPath)) {
    return res.sendFile(indexPath);
  }
  res.status(404).send('index.html not found');
});

app.get('/robots.txt', (req, res) => {
  res.type('text/plain').send(`User-agent: *\nAllow: /\nSitemap: /sitemap.xml\n`);
});

app.get('/sitemap.xml', (req, res) => {
  const host = req.headers.host;
  const baseUrl = `${req.protocol}://${host}`;
  const pages = [
    '/',
    '/login.html',
    '/products.html',
    '/admin.html',
    '/contact.html'
  ];
  const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${pages.map(page => `  <url><loc>${baseUrl}${page}</loc></url>`).join('\n')}
</urlset>`;
  res.type('application/xml').send(sitemap);
});

function authenticate(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Missing Authorization header' });
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid Authorization format' });
  try {
    const payload = jwt.verify(parts[1], JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// Login route + บันทึกเวลาล็อกอิน + Discord Notification
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  const normalizedEmail = normalizeEmail(email);
  if (!isValidEmail(normalizedEmail) || !password) return res.status(400).json({ error: 'กรุณากรอกอีเมลและรหัสผ่านให้ถูกต้อง' });

  try {
    const result = await pool.query(
      'SELECT id, name, email, password_enc, role FROM logins WHERE email = $1',
      [normalizedEmail]
    );
    const row = result.rows[0];
    if (!row) return res.status(401).json({ error: 'Invalid credentials' });

    const dec = decryptText(row.password_enc);
    if (dec === null || dec !== String(password)) return res.status(401).json({ error: 'Invalid credentials' });

    const now = new Date();
    await pool.query('UPDATE logins SET last_login_at = $1 WHERE id = $2', [now, row.id]);

    const token = jwt.sign({ id: row.id, email: row.email, role: row.role }, JWT_SECRET, { expiresIn: '8h' });
    const displayName = row.name || normalizedEmail.split('@')[0];

    // ส่งแจ้งเตือนเมื่อเข้าสู่ระบบสำเร็จ
    sendDiscordNotification(
      '🔑 มีผู้ใช้งานเข้าสู่ระบบ',
      `**ชื่อผู้ใช้:** ${displayName}\n**อีเมล:** ${row.email}\n**เวลา:** ${now.toLocaleString('th-TH')}`,
      3447003
    );

    res.json({ token, user: { name: displayName, email: row.email, role: row.role, lastLoginAt: now } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// Check current user session
app.get('/api/me', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email, role, last_login_at FROM logins WHERE id = $1',
      [req.user.id]
    );
    const row = result.rows[0];
    if (!row) return res.status(404).json({ error: 'User not found' });

    const displayName = row.name || row.email.split('@')[0];
    res.json({ id: row.id, name: displayName, email: row.email, role: row.role, lastLoginAt: row.last_login_at });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// เปลี่ยนชื่อผู้ใช้ (ทำได้หลังล็อกอินแล้วเท่านั้น)
app.put('/api/me', authenticate, async (req, res) => {
  const { name } = req.body || {};
  const newName = String(name || '').trim();
  if (!newName || newName.length < 2 || newName.length > 50) {
    return res.status(400).json({ error: 'ชื่อผู้ใช้ต้องมีความยาว 2-50 ตัวอักษร' });
  }

  try {
    const result = await pool.query(
      'UPDATE logins SET name = $1 WHERE id = $2 RETURNING id, name, email, role, last_login_at',
      [newName, req.user.id]
    );
    const row = result.rows[0];
    if (!row) return res.status(404).json({ error: 'User not found' });

    res.json({ id: row.id, name: row.name, email: row.email, role: row.role, lastLoginAt: row.last_login_at });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// Register new user + Discord Notification
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body || {};
  const normalizedEmail = normalizeEmail(email);
  if (!isValidEmail(normalizedEmail)) return res.status(400).json({ error: 'รูปแบบอีเมลไม่ถูกต้อง' });
  if (typeof password !== 'string' || password.length < 4) return res.status(400).json({ error: 'รหัสผ่านต้องมีอย่างน้อย 4 ตัวอักษร' });

  const displayName = String(name || '').trim() || normalizedEmail.split('@')[0];

  try {
    const now = new Date();
    const result = await pool.query(
      'INSERT INTO logins (name, email, password_enc, last_login_at) VALUES ($1,$2,$3,$4) RETURNING id',
      [displayName, normalizedEmail, encryptText(password), now]
    );

    const token = jwt.sign({ id: result.rows[0].id, email: normalizedEmail, role: 'user' }, JWT_SECRET, { expiresIn: '8h' });

    // ส่งแจ้งเตือนเมื่อสมัครสมาชิกสำเร็จ
    sendDiscordNotification(
      '🆕 มีผู้สมัครสมาชิกใหม่!',
      `**ชื่อผู้ใช้:** ${displayName}\n**อีเมล:** ${normalizedEmail}\n**เวลา:** ${now.toLocaleString('th-TH')}`,
      3066993
    );

    res.status(201).json({ token, user: { name: displayName, email: normalizedEmail } });
  } catch (err) {
    if (err && err.code === '23505') return res.status(409).json({ error: 'อีเมลนี้มีบัญชีอยู่แล้ว กรุณาเข้าสู่ระบบ' });
    console.error(err);
    res.status(500).json({ error: 'ไม่สามารถสร้างบัญชีได้' });
  }
});

// Public products list
app.get('/api/products', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, title, description, price, image FROM products');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// Update product (Admin only)
app.put('/api/products/:id', authenticate, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid id' });

  const { title, description, price, image } = req.body || {};
  const updates = [];
  const values = [];
  let idx = 1;

  if (typeof title !== 'undefined') {
    updates.push(`title = $${idx++}`);
    values.push(String(title));
  }
  if (typeof description !== 'undefined') {
    updates.push(`description = $${idx++}`);
    values.push(String(description));
  }
  if (typeof price !== 'undefined') {
    const parsedPrice = Number(price);
    if (!Number.isFinite(parsedPrice) || parsedPrice < 0) {
      return res.status(400).json({ error: 'Invalid price' });
    }
    updates.push(`price = $${idx++}`);
    values.push(parsedPrice);
  }
  if (typeof image !== 'undefined') {
    updates.push(`image = $${idx++}`);
    values.push(String(image));
  }

  if (!updates.length) return res.status(400).json({ error: 'No changes provided' });

  values.push(id);
  try {
    const result = await pool.query(`UPDATE products SET ${updates.join(', ')} WHERE id = $${idx}`, values);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ updated: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// Upload product image (Admin only)
app.post('/api/upload', authenticate, requireAdmin, (req, res) => {
  const { filename, data } = req.body || {};
  if (!filename || !data) return res.status(400).json({ error: 'Filename and data required' });

  const ext = path.extname(filename).toLowerCase();
  const allowed = ['.jpg', '.jpeg', '.png', '.webp', '.gif'];
  if (!allowed.includes(ext)) return res.status(400).json({ error: 'Unsupported file type' });

  const safeName = path.basename(filename, ext).replace(/[^a-z0-9-_]/gi, '_');
  const newName = `${Date.now()}-${safeName}${ext}`;
  const imagesDir = path.join(__dirname, 'images');

  if (!fs.existsSync(imagesDir)) {
    fs.mkdirSync(imagesDir, { recursive: true });
  }

  const imagePath = path.join(imagesDir, newName);
  const buffer = Buffer.from(data, 'base64');

  fs.writeFile(imagePath, buffer, (err) => {
    if (err) return res.status(500).json({ error: 'Unable to save file' });
    res.json({ url: `images/${newName}` });
  });
});

// Delete product (Admin only)
app.delete('/api/products/:id', authenticate, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid id' });
  try {
    const result = await pool.query('DELETE FROM products WHERE id = $1', [id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ deleted: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// Create new product (Admin only)
app.post('/api/products', authenticate, requireAdmin, async (req, res) => {
  const { title, description, price, image } = req.body || {};
  try {
    const result = await pool.query(
      'INSERT INTO products (title, description, price, image) VALUES($1,$2,$3,$4) RETURNING id',
      [title, description, price, image]
    );
    res.json({ id: result.rows[0].id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// Save contact submission + Discord Notification
app.post('/api/contacts', async (req, res) => {
  const { name, email, phone, subject, message } = req.body || {};
  try {
    const result = await pool.query(
      'INSERT INTO contacts (name, email, phone, subject, message) VALUES ($1,$2,$3,$4,$5) RETURNING id',
      [name, email, phone, subject, message]
    );

    // ส่งแจ้งเตือนเมื่อมีผู้ส่งข้อความติดต่อ
    sendDiscordNotification(
      '📩 มีข้อความติดต่อใหม่',
      `**ชื่อผู้ส่ง:** ${name || 'ไม่ระบุ'}\n**อีเมล:** ${email || '-'}\n**เบอร์โทร:** ${phone || '-'}\n**หัวข้อ:** ${subject || '-'}\n**ข้อความ:** ${message || '-'}`,
      15105570
    );

    res.json({ id: result.rows[0].id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// Create new order + Discord Notification
app.post('/api/orders', authenticate, async (req, res) => {
  const { product, price, quantity, customerName, customerEmail, image } = req.body || {};
  const title = String(product || '').trim();
  const amount = Number(price || 0);
  const qty = Math.max(1, Number(quantity || 1));
  const code = `NP${Date.now().toString().slice(-8)}`;

  if (!title) return res.status(400).json({ error: 'Missing product title' });

  try {
    const result = await pool.query(
      'INSERT INTO orders (order_code, product_title, price, quantity, customer_name, customer_email, image) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id',
      [code, title, amount, qty, customerName || req.user.email || '', customerEmail || req.user.email || '', image || '']
    );

    const cName = customerName || req.user.email || 'ไม่ระบุตัวตน';
    const totalPrice = amount * qty;

    // ส่งแจ้งเตือนเมื่อสั่งซื้อสำเร็จ
    sendDiscordNotification(
      '🛒 มีคำสั่งซื้อใหม่!',
      `**รหัสออเดอร์:** ${code}\n**ผู้สั่งซื้อ:** ${cName}\n**สินค้า:** ${title}\n**จำนวน:** ${qty}\n**ราคารวม:** ฿${totalPrice.toLocaleString()}`,
      5763719
    );

    res.status(201).json({ orderCode: code, id: result.rows[0].id, product: title, price: amount, quantity: qty });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// List orders (Admin only)
app.get('/api/orders', authenticate, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, order_code, product_title, price, quantity, customer_name, customer_email, image, created_at FROM orders ORDER BY id DESC'
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// Summary stats for orders (Admin only)
app.get('/api/orders/stats', authenticate, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT product_title AS product,
             COUNT(*) AS order_count,
             SUM(quantity) AS total_units,
             SUM(price * quantity) AS revenue
      FROM orders
      GROUP BY product_title
      ORDER BY order_count DESC, revenue DESC
    `);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// List account logins (Admin only) — รวมเวลาล็อกอินล่าสุดของแต่ละคน
app.get('/api/logins', authenticate, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email, created_at, last_login_at FROM logins ORDER BY created_at DESC'
    );
    const masked = result.rows.map(r => ({
      id: r.id,
      name: r.name,
      email: r.email,
      password: '*****',
      created_at: r.created_at,
      last_login_at: r.last_login_at
    }));
    res.json(masked);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// Change user password (Admin only)
app.put('/api/logins/:id/password', authenticate, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const { password } = req.body || {};
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid id' });
  if (typeof password !== 'string' || password.trim().length < 4) return res.status(400).json({ error: 'รหัสผ่านต้องมีอย่างน้อย 4 ตัวอักษร' });

  try {
    const result = await pool.query('UPDATE logins SET password_enc = $1 WHERE id = $2', [encryptText(password), id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ updated: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// Reveal user password (Admin only)
app.get('/api/logins/:id/password', authenticate, requireAdmin, async (req, res) => {
  const id = req.params.id;
  try {
    const result = await pool.query('SELECT password_enc FROM logins WHERE id = $1', [id]);
    const row = result.rows[0];
    if (!row) return res.status(404).json({ error: 'Not found' });
    const dec = decryptText(row.password_enc);
    res.json({ password: dec });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// Delete login account (Admin only)
app.delete('/api/logins/:id', authenticate, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid id' });
  try {
    const result = await pool.query('DELETE FROM logins WHERE id = $1', [id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ deleted: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// Get contact submissions (Admin only)
app.get('/api/contacts', authenticate, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email, phone, subject, message, created_at FROM contacts ORDER BY created_at DESC'
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`API server running on http://localhost:${PORT}`));
  })
  .catch((err) => {
    console.error('ไม่สามารถเชื่อมต่อฐานข้อมูลได้ ตรวจสอบ DATABASE_URL ใน .env:', err);
    process.exit(1);
  });
