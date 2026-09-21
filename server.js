import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { Pool } from 'pg';
import Razorpay from 'razorpay';
import fs from 'fs';
import path from 'path';
import multer from 'multer';

const app = express();
const PORT = process.env.PORT || 4000;

if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET is required');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes('supabase') ? { rejectUnauthorized: false } : undefined
});

const origins = (process.env.CORS_ORIGINS || '*').split(',').map(x => x.trim());
app.use(cors({ origin: (origin, cb) => cb(null, !origin || origins.includes('*') || origins.includes(origin)) }));
app.use(express.json({ limit: '2mb' }));

const uploadDir = path.resolve(process.env.STORAGE_DIR || './uploads');
fs.mkdirSync(uploadDir, { recursive: true });
const upload = multer({ dest: uploadDir });

const razorpay = process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET
  ? new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET })
  : null;

const q = (text, params = []) => pool.query(text, params);
const sign = u => jwt.sign(
  { sub: u.id, role: u.role, name: u.name },
  process.env.JWT_SECRET,
  { expiresIn: '7d' }
);

function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    req.user = jwt.verify(h.replace(/^Bearer\s+/i, ''), process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
}

const roles = (...rs) => (req, res, next) =>
  rs.includes(req.user.role) ? next() : res.status(403).json({ error: 'Forbidden' });

function normalizeStatus(value) {
  const s = String(value || '').toLowerCase().replace(/\s+/g, '_');
  return s === 'complete' ? 'completed' : s;
}

function toScheduledDateTime(date, time) {
  if (!date) return null;
  return time ? `${date}T${time}` : `${date}T09:00:00`;
}

// The original MVP schema used a different users table.  The current Supabase
// schema deliberately keeps customers and partners separate, so credentials
// live in this small compatibility table instead of changing the business tables.
async function ensureAuthTable() {
  await q(`
    CREATE TABLE IF NOT EXISTS auth_credentials (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      phone TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('customer','partner','admin')),
      profile_id UUID,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
  await q(`CREATE INDEX IF NOT EXISTS idx_auth_credentials_profile ON auth_credentials(profile_id)`);
}

app.get('/health', async (_, res) => {
  try {
    await q('SELECT 1');
    res.json({ ok: true, service: 'CarCareBay API', database: 'postgresql' });
  } catch {
    res.status(503).json({ ok: false, error: 'Database unavailable' });
  }
});

app.post('/api/auth/register', async (req, res) => {
  const { phone, name, password, email = null, apartment_id = null, role = 'customer' } = req.body;
  if (!phone || !name || !password) return res.status(400).json({ error: 'phone, name and password required' });
  if (!['customer', 'partner'].includes(role)) return res.status(400).json({ error: 'Invalid registration role' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const hash = await bcrypt.hash(password, 10);
    let profile;

    if (role === 'customer') {
      const r = await client.query(
        `INSERT INTO customers(full_name, phone, email, apartment_id, role, status)
         VALUES($1,$2,$3,$4,'customer','active')
         RETURNING id, full_name AS name, phone, email, apartment_id, role, status`,
        [name, phone, email, apartment_id]
      );
      profile = r.rows[0];
    } else {
      const r = await client.query(
        `INSERT INTO partners(full_name, phone, email, status, rating, jobs_completed)
         VALUES($1,$2,$3,'active',0,0)
         RETURNING id, full_name AS name, phone, email, status, rating, jobs_completed`,
        [name, phone, email]
      );
      profile = r.rows[0];
    }

    await client.query(
      `INSERT INTO auth_credentials(phone, password_hash, role, profile_id) VALUES($1,$2,$3,$4)`,
      [phone, hash, role, profile.id]
    );
    await client.query('COMMIT');

    res.status(201).json({ user: profile, token: sign({ id: profile.id, role, name }) });
  } catch (e) {
    await client.query('ROLLBACK');
    if (e.code === '23505') return res.status(409).json({ error: 'Phone already registered' });
    console.error(e);
    res.status(500).json({ error: 'Registration failed' });
  } finally {
    client.release();
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { phone, password } = req.body;
  if (!phone || !password) return res.status(400).json({ error: 'phone and password required' });
  try {
    const { rows } = await q(`SELECT * FROM auth_credentials WHERE phone=$1`, [phone]);
    const cred = rows[0];
    if (!cred || !await bcrypt.compare(password, cred.password_hash)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    let user;
    if (cred.role === 'customer') {
      const r = await q(`SELECT id, full_name AS name, phone, email, apartment_id, role, status FROM customers WHERE id=$1`, [cred.profile_id]);
      user = r.rows[0];
    } else if (cred.role === 'partner') {
      const r = await q(`SELECT id, full_name AS name, phone, email, status FROM partners WHERE id=$1`, [cred.profile_id]);
      user = r.rows[0];
    } else {
      user = { id: cred.profile_id || cred.id, name: 'Admin', phone, role: 'admin', status: 'active' };
    }

    if (!user) return res.status(401).json({ error: 'Account not found' });
    res.json({ user, token: sign({ id: user.id, role: cred.role, name: user.name }) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/me', auth, async (req, res) => {
  if (req.user.role === 'customer') {
    const { rows } = await q(`SELECT id, full_name AS name, phone, email, apartment_id, role, status FROM customers WHERE id=$1`, [req.user.sub]);
    return res.json(rows[0] || null);
  }
  if (req.user.role === 'partner') {
    const { rows } = await q(`SELECT id, full_name AS name, phone, email, status, rating, jobs_completed FROM partners WHERE id=$1`, [req.user.sub]);
    return res.json(rows[0] || null);
  }
  res.json({ id: req.user.sub, name: req.user.name, role: 'admin' });
});

app.get('/api/plans', async (_, res) => {
  const { rows } = await q(`
    SELECT id, name, description, monthly_price,
           ROUND(monthly_price * 100)::int AS price_paise,
           wash_credits AS included_exterior,
           interior_credits AS included_interior,
           active
    FROM service_plans WHERE active=true ORDER BY monthly_price
  `);
  res.json(rows);
});

app.get('/api/customers', auth, roles('admin'), async (_, res) => {
  const { rows } = await q(`
    SELECT c.id, c.full_name AS name, c.phone, c.email,
           COUNT(DISTINCT v.id)::int AS vehicles,
           COALESCE(MAX(s.status), 'none') AS subscription_status
    FROM customers c
    LEFT JOIN vehicles v ON v.customer_id=c.id
    LEFT JOIN subscriptions s ON s.customer_id=c.id
    GROUP BY c.id ORDER BY c.created_at DESC
  `);
  res.json(rows);
});

app.get('/api/apartments', auth, roles('admin'), async (_, res) => {
  const { rows } = await q(`
    SELECT a.*, COUNT(DISTINCT v.id)::int AS cars,
           COUNT(DISTINCT s.customer_id)::int AS subscribers,
           COALESCE(SUM(sp.monthly_price) FILTER (WHERE s.status='active'),0) AS mrr
    FROM apartments a
    LEFT JOIN vehicles v ON v.customer_id IN (SELECT id FROM customers WHERE apartment_id=a.id)
    LEFT JOIN subscriptions s ON s.customer_id=v.customer_id
    LEFT JOIN service_plans sp ON sp.id=s.plan_id
    GROUP BY a.id ORDER BY a.name
  `);
  res.json(rows);
});

app.get('/api/partners', auth, roles('admin'), async (_, res) => {
  const { rows } = await q(`
    SELECT p.id, p.full_name AS name, p.phone, p.email, p.employee_code,
           p.rating, p.jobs_completed,
           COUNT(b.id) FILTER (WHERE b.scheduled_date=CURRENT_DATE)::int AS jobs_today,
           COUNT(b.id) FILTER (WHERE b.scheduled_date=CURRENT_DATE AND b.status='completed')::int AS completed_today,
           COUNT(b.id) FILTER (WHERE b.scheduled_date=CURRENT_DATE AND b.status IN ('assigned','in_progress'))::int AS active_jobs
    FROM partners p LEFT JOIN bookings b ON b.partner_id=p.id
    GROUP BY p.id ORDER BY p.full_name
  `);
  res.json(rows);
});

app.get('/api/bookings', auth, async (req, res) => {
  let sql = `
    SELECT b.id, b.service_type AS service,
           (b.scheduled_date::text || ' ' || b.scheduled_time::text) AS scheduled_at,
           b.scheduled_date, b.scheduled_time, b.status,
           b.before_photo_url, b.after_photo_url,
           c.full_name AS customer, c.phone,
           (v.make || ' ' || v.model) AS car, v.registration_number AS plate,
           a.name AS apartment, pb.tower, pb.floor, pb.bay_number AS bay,
           p.full_name AS partner
    FROM bookings b
    JOIN customers c ON c.id=b.customer_id
    JOIN vehicles v ON v.id=b.vehicle_id
    JOIN apartments a ON a.id=b.apartment_id
    LEFT JOIN parking_bays pb ON pb.id=b.parking_bay_id
    LEFT JOIN partners p ON p.id=b.partner_id`;
  const args = [];
  if (req.user.role === 'customer') { sql += ' WHERE b.customer_id=$1'; args.push(req.user.sub); }
  else if (req.user.role === 'partner') { sql += ' WHERE b.partner_id=$1'; args.push(req.user.sub); }
  sql += ' ORDER BY b.scheduled_date DESC, b.scheduled_time DESC';
  const { rows } = await q(sql, args);
  res.json(rows);
});

app.post('/api/bookings', auth, roles('customer','admin'), async (req, res) => {
  const vehicleId = req.body.vehicle_id;
  const service = req.body.service || req.body.service_type;
  const apartmentId = req.body.apartment_id;
  const bayId = req.body.bay_id || req.body.parking_bay_id || null;
  const scheduledAt = req.body.scheduled_at;
  const scheduledDate = req.body.scheduled_date || (scheduledAt ? String(scheduledAt).slice(0,10) : null);
  const scheduledTime = req.body.scheduled_time || (scheduledAt ? String(scheduledAt).slice(11,19) : null);
  const customerId = req.user.role === 'admin' ? req.body.customer_id : req.user.sub;

  if (!vehicleId || !service || !apartmentId || !scheduledDate || !scheduledTime) {
    return res.status(400).json({ error: 'vehicle_id, service, apartment_id, scheduled_date and scheduled_time are required' });
  }

  const { rows } = await q(`
    INSERT INTO bookings(customer_id, vehicle_id, apartment_id, parking_bay_id, service_type, scheduled_date, scheduled_time, status, customer_notes)
    VALUES($1,$2,$3,$4,$5,$6,$7,'scheduled',$8)
    RETURNING *
  `, [customerId, vehicleId, apartmentId, bayId, service, scheduledDate, scheduledTime, req.body.customer_notes || null]);
  res.status(201).json(rows[0]);
});

app.patch('/api/bookings/:id', auth, async (req, res) => {
  const id = req.params.id;
  const current = await q(`SELECT * FROM bookings WHERE id=$1`, [id]);
  if (!current.rows[0]) return res.status(404).json({ error: 'Booking not found' });
  const booking = current.rows[0];
  if (req.user.role === 'customer' && booking.customer_id !== req.user.sub) return res.status(403).json({ error: 'Forbidden' });
  if (req.user.role === 'partner' && booking.partner_id !== req.user.sub) return res.status(403).json({ error: 'Forbidden' });

  const sets = [];
  const vals = [];
  const add = (column, value) => { vals.push(value); sets.push(`${column}=$${vals.length}`); };

  if (req.body.status !== undefined) add('status', normalizeStatus(req.body.status));
  if (req.body.partner_id !== undefined) add('partner_id', req.body.partner_id || null);
  if (req.body.customer_notes !== undefined) add('customer_notes', req.body.customer_notes);
  if (req.body.partner_notes !== undefined) add('partner_notes', req.body.partner_notes);
  if (req.body.notes !== undefined) add(req.user.role === 'partner' ? 'partner_notes' : 'customer_notes', req.body.notes);
  if (req.body.before_photo_url !== undefined) add('before_photo_url', req.body.before_photo_url);
  if (req.body.after_photo_url !== undefined) add('after_photo_url', req.body.after_photo_url);

  if (req.body.status && normalizeStatus(req.body.status) === 'completed') {
    sets.push('completed_at=now()');
  }
  if (!sets.length) return res.status(400).json({ error: 'No editable fields' });

  vals.push(id);
  const { rows } = await q(`UPDATE bookings SET ${sets.join(', ')} WHERE id=$${vals.length} RETURNING *`, vals);

  if (req.body.status && normalizeStatus(req.body.status) === 'completed') {
    await q(`UPDATE partners SET jobs_completed=jobs_completed+1 WHERE id=$1`, [booking.partner_id || req.body.partner_id || null]).catch(() => {});
  }
  res.json(rows[0]);
});

app.post('/api/bookings/:id/photos', auth, upload.single('photo'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'photo required' });
  const type = req.body.type === 'after' ? 'after_photo_url' : 'before_photo_url';
  const url = `/uploads/${req.file.filename}`;
  const { rows } = await q(`UPDATE bookings SET ${type}=$1 WHERE id=$2 RETURNING id, ${type}`, [url, req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'Booking not found' });
  res.json(rows[0]);
});

app.use('/uploads', express.static(uploadDir));

app.post('/api/ratings', auth, roles('customer'), async (req, res) => {
  const rating = req.body.rating ?? req.body.score;
  if (!req.body.booking_id || !rating) return res.status(400).json({ error: 'booking_id and rating required' });
  const { rows } = await q(
    `INSERT INTO ratings(booking_id,customer_id,partner_id,rating,comment)
     SELECT b.id,b.customer_id,b.partner_id,$3,$4 FROM bookings b
     WHERE b.id=$1 AND b.customer_id=$2
     RETURNING *`,
    [req.body.booking_id, req.user.sub, Number(rating), req.body.comment || null]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Booking not found' });
  res.status(201).json(rows[0]);
});

app.get('/api/dashboard', auth, roles('admin'), async (_, res) => {
  const [s, m, j, r] = await Promise.all([
    q(`SELECT COUNT(*)::int AS n FROM subscriptions WHERE status='active'`),
    q(`SELECT COALESCE(SUM(sp.monthly_price),0) AS n FROM subscriptions s JOIN service_plans sp ON sp.id=s.plan_id WHERE s.status='active'`),
    q(`SELECT COUNT(*)::int AS n, COUNT(*) FILTER (WHERE status='completed')::int AS completed FROM bookings WHERE scheduled_date=CURRENT_DATE`),
    q(`SELECT COALESCE(ROUND(AVG(rating),2),0) AS n FROM ratings`)
  ]);
  res.json({
    activeSubscribers: s.rows[0].n,
    mrr_paise: Math.round(Number(m.rows[0].n) * 100),
    mrr: Number(m.rows[0].n),
    todaysJobs: j.rows[0].n,
    completed: j.rows[0].completed,
    avgRating: Number(r.rows[0].n)
  });
});

app.post('/api/payments/order', auth, roles('customer'), async (req, res) => {
  if (!razorpay) return res.status(503).json({ error: 'Razorpay not configured' });
  const amount = Number(req.body.amount_paise);
  if (!amount) return res.status(400).json({ error: 'amount_paise required' });
  const order = await razorpay.orders.create({ amount, currency: 'INR', receipt: `ccb_${Date.now()}` });
  res.json(order);
});

app.post('/api/subscriptions', auth, roles('customer','admin'), async (req, res) => {
  const customerId = req.user.role === 'admin' ? req.body.customer_id : req.user.sub;
  const { plan_id, vehicle_id } = req.body;
  if (!plan_id || !vehicle_id) return res.status(400).json({ error: 'plan_id and vehicle_id required' });
  const { rows } = await q(`
    INSERT INTO subscriptions(customer_id,vehicle_id,plan_id,status,start_date,end_date)
    VALUES($1,$2,$3,'active',CURRENT_DATE,CURRENT_DATE + INTERVAL '1 month')
    RETURNING *`, [customerId, vehicle_id, plan_id]);
  res.status(201).json(rows[0]);
});

app.get('/api/jobs', auth, async (req, res) => {
  let where = '';
  const args = [];
  if (req.user.role === 'customer') { where = 'WHERE b.customer_id=$1'; args.push(req.user.sub); }
  else if (req.user.role === 'partner') { where = 'WHERE b.partner_id=$1'; args.push(req.user.sub); }

  const { rows } = await q(`
    SELECT b.id,
           b.service_type AS service,
           b.scheduled_time::text AS time,
           b.status,
           (v.make || ' ' || v.model) AS car,
           v.registration_number AS plate,
           (pb.tower || ' · ' || pb.floor || ' · ' || pb.bay_number) AS bay,
           a.name AS apartment,
           c.full_name AS customer
    FROM bookings b
    JOIN vehicles v ON v.id=b.vehicle_id
    JOIN customers c ON c.id=b.customer_id
    JOIN apartments a ON a.id=b.apartment_id
    LEFT JOIN parking_bays pb ON pb.id=b.parking_bay_id
    ${where}
    ORDER BY b.scheduled_date, b.scheduled_time
  `, args);
  res.json(rows);
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

await ensureAuthTable();
app.listen(PORT, () => console.log(`CarCareBay API listening on :${PORT}`));
