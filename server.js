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

const origins = (process.env.CORS_ORIGINS || '*').split(',').map(s => s.trim());
app.use(cors({ origin: (o, cb) => cb(null, !o || origins.includes('*') || origins.includes(o)) }));
app.use(express.json({ limit: '2mb' }));

const uploadDir = path.resolve(process.env.STORAGE_DIR || './uploads');
fs.mkdirSync(uploadDir, { recursive: true });
const upload = multer({ dest: uploadDir });

const razorpay = process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET
  ? new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET })
  : null;

const q = (text, params = []) => pool.query(text, params);

async function ensureAuthTable() {
  // The existing Supabase schema uses:
  // auth_credentials(id, phone, password_hash, role, profile_id, created_at)
  // where profile_id points to the corresponding profile/customer.
  // Do not try to recreate this table with a customer_id column.
  await q(`
    SELECT 1
    FROM information_schema.tables
    WHERE table_schema='public' AND table_name='auth_credentials'
    LIMIT 1
  `);
}
ensureAuthTable().catch(e => console.error('auth_credentials check failed:', e.message));

const sign = u => jwt.sign(
  { sub: u.id, role: u.role, name: u.full_name, phone: u.phone },
  process.env.JWT_SECRET,
  { expiresIn: '7d' }
);

function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    if (!h.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
    req.user = jwt.verify(h.slice(7), process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

const roles = (...rs) => (req, res, next) =>
  rs.includes(req.user.role) ? next() : res.status(403).json({ error: 'Forbidden' });

const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

app.get('/health', asyncRoute(async (_, res) => {
  await q('SELECT 1');
  res.json({ ok: true, service: 'CarCareBay API', database: 'postgresql' });
}));

app.get('/', (_, res) => res.json({ service: 'CarCareBay API', ok: true }));

/* ---------- AUTH ---------- */

app.post('/api/auth/register', asyncRoute(async (req, res) => {
  const { name, full_name, phone, email, password, apartment_id } = req.body;
  if (!phone || !password || !(name || full_name)) {
    return res.status(400).json({ error: 'name, phone and password are required' });
  }
  await ensureAuthTable();

  const existing = await q('SELECT id FROM customers WHERE phone=$1 LIMIT 1', [phone]);
  if (existing.rows.length) return res.status(409).json({ error: 'Phone already registered' });

  const customer = (await q(`
    INSERT INTO customers(full_name, phone, email, apartment_id, role, status)
    VALUES($1,$2,$3,$4,'customer','active')
    RETURNING *
  `, [name || full_name, phone, email || null, apartment_id || null])).rows[0];

  const hash = await bcrypt.hash(password, 12);

  // Keep authentication credentials in the existing Supabase auth_credentials schema.
  await q(`
    DELETE FROM auth_credentials
    WHERE profile_id=$1 OR phone=$2
  `, [customer.id, phone]);

  await q(`
    INSERT INTO auth_credentials(id,phone,password_hash,role,profile_id)
    VALUES(gen_random_uuid(),$1,$2,'customer',$3)
  `, [phone, hash, customer.id]);

  res.status(201).json({ token: sign(customer), user: customer });
}));

app.post('/api/auth/login', asyncRoute(async (req, res) => {
  const { phone, password } = req.body;
  if (!phone || !password) return res.status(400).json({ error: 'phone number and password required' });
  await ensureAuthTable();

  const r = await q(`
    SELECT c.*, a.password_hash
    FROM customers c
    JOIN auth_credentials a ON a.profile_id=c.id
    WHERE a.phone=$1
    LIMIT 1
  `, [phone]);

  if (!r.rows.length || !(await bcrypt.compare(password, r.rows[0].password_hash))) {
    return res.status(401).json({ error: 'Invalid phone or password' });
  }

  const { password_hash, ...user } = r.rows[0];
  if (user.status && user.status !== 'active') return res.status(403).json({ error: 'Account is not active' });
  res.json({ token: sign(user), user });
}));

/* One-time admin bootstrap. Requires ADMIN_BOOTSTRAP_KEY in Render. */
app.post('/api/auth/bootstrap-admin', asyncRoute(async (req, res) => {
  const supplied = req.headers['x-admin-bootstrap-key'];
  if (!process.env.ADMIN_BOOTSTRAP_KEY || supplied !== process.env.ADMIN_BOOTSTRAP_KEY) {
    return res.status(403).json({ error: 'Invalid bootstrap key' });
  }

  const { name, full_name, phone, email, password } = req.body;
  if (!phone || !password || !(name || full_name)) {
    return res.status(400).json({ error: 'name, phone and password are required' });
  }
  await ensureAuthTable();

  const existing = await q('SELECT id FROM customers WHERE phone=$1 LIMIT 1', [phone]);
  let customer;

  if (existing.rows.length) {
    customer = (await q(`
      UPDATE customers
      SET full_name=$1,email=$2,role='admin',status='active'
      WHERE id=$3 RETURNING *
    `, [name || full_name, email || null, existing.rows[0].id])).rows[0];
  } else {
    customer = (await q(`
      INSERT INTO customers(full_name,phone,email,role,status)
      VALUES($1,$2,$3,'admin','active') RETURNING *
    `, [name || full_name, phone, email || null])).rows[0];
  }

  const hash = await bcrypt.hash(password, 12);

  // Replace any credentials belonging to this phone/profile using the actual schema.
  await q(`
    DELETE FROM auth_credentials
    WHERE profile_id=$1 OR phone=$2
  `, [customer.id, phone]);

  await q(`
    INSERT INTO auth_credentials(id,phone,password_hash,role,profile_id)
    VALUES(gen_random_uuid(),$1,$2,'admin',$3)
  `, [phone, hash, customer.id]);

  res.status(201).json({ message: 'Admin created', user: customer, token: sign(customer) });
}));

app.get('/api/me', auth, asyncRoute(async (req, res) => {
  const r = await q('SELECT * FROM customers WHERE id=$1', [req.user.sub]);
  if (!r.rows.length) return res.status(404).json({ error: 'Customer not found' });
  res.json(r.rows[0]);
}));

/* ---------- PLANS ---------- */

app.get('/api/plans', asyncRoute(async (_, res) => {
  const r = await q(`
    SELECT id,name,description,monthly_price,
           COALESCE(wash_credits,0) AS wash_credits,
           COALESCE(interior_credits,0) AS interior_credits,
           active, created_at
    FROM service_plans WHERE active=true ORDER BY monthly_price
  `);
  res.json(r.rows.map(p => ({
    ...p,
    price_paise: Math.round(Number(p.monthly_price) * 100),
    included_exterior: Number(p.wash_credits),
    included_interior: Number(p.interior_credits)
  })));
}));

/* ---------- VEHICLES ---------- */

app.get('/api/vehicles', auth, asyncRoute(async (req, res) => {
  const r = await q('SELECT * FROM vehicles WHERE customer_id=$1 ORDER BY created_at DESC', [req.user.sub]);
  res.json(r.rows);
}));

app.post('/api/vehicles', auth, asyncRoute(async (req, res) => {
  const { make, model, registration_number, color, vehicle_type, parking_bay_id } = req.body;
  if (!registration_number) return res.status(400).json({ error: 'registration_number is required' });

  if (parking_bay_id) {
    const bay = await q('SELECT id FROM parking_bays WHERE id=$1 LIMIT 1', [parking_bay_id]);
    if (!bay.rows.length) return res.status(400).json({ error: 'Parking bay not found', parking_bay_id });
  }

  const existing = await q(
    'SELECT * FROM vehicles WHERE customer_id=$1 AND registration_number=$2 LIMIT 1',
    [req.user.sub, registration_number]
  );
  if (existing.rows.length) {
    return res.status(409).json({ error: 'Vehicle with this registration number already exists', vehicle: existing.rows[0] });
  }

  const r = await q(`
    INSERT INTO vehicles(customer_id,parking_bay_id,registration_number,make,model,color,vehicle_type)
    VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *
  `, [req.user.sub, parking_bay_id || null, registration_number, make || null, model || null, color || null, vehicle_type || 'car']);
  res.status(201).json(r.rows[0]);
}));

app.patch('/api/vehicles/:id', auth, asyncRoute(async (req, res) => {
  const allowed = ['make','model','registration_number','color','vehicle_type','parking_bay_id'];
  const fields = allowed.filter(k => Object.prototype.hasOwnProperty.call(req.body, k));
  if (!fields.length) return res.status(400).json({ error: 'No fields to update' });
  const vals = fields.map(k => req.body[k]);
  const set = fields.map((k,i) => `${k}=$${i+1}`).join(',');
  vals.push(req.params.id, req.user.sub);
  const r = await q(`UPDATE vehicles SET ${set} WHERE id=$${vals.length-1} AND customer_id=$${vals.length} RETURNING *`, vals);
  if (!r.rows.length) return res.status(404).json({ error: 'Vehicle not found' });
  res.json(r.rows[0]);
}));

app.delete('/api/vehicles/:id', auth, asyncRoute(async (req, res) => {
  const r = await q('DELETE FROM vehicles WHERE id=$1 AND customer_id=$2 RETURNING id', [req.params.id, req.user.sub]);
  if (!r.rows.length) return res.status(404).json({ error: 'Vehicle not found' });
  res.json({ ok: true });
}));

/* ---------- APARTMENTS ---------- */

app.get('/api/apartments', auth, asyncRoute(async (req, res) => {
  if (req.user.role === 'admin') {
    const r = await q('SELECT * FROM apartments ORDER BY created_at DESC');
    return res.json(r.rows);
  }
  const r = await q('SELECT * FROM apartments WHERE status IS NULL OR status <> $1 ORDER BY name', ['inactive']);
  res.json(r.rows);
}));

app.post('/api/apartments', auth, roles('admin'), asyncRoute(async (req, res) => {
  const { name, address, city, pincode, total_cars, status } = req.body;
  if (!name) return res.status(400).json({ error: 'name is required' });
  const r = await q(`
    INSERT INTO apartments(name,address,city,pincode,total_cars,status)
    VALUES($1,$2,$3,$4,$5,$6) RETURNING *
  `, [name,address || null,city || null,pincode || null,Number(total_cars || 0),status || 'active']);
  res.status(201).json(r.rows[0]);
}));

app.patch('/api/apartments/:id', auth, roles('admin'), asyncRoute(async (req,res)=>{
  const fields=['name','address','city','pincode','total_cars','status'].filter(k=>Object.hasOwn(req.body,k));
  if(!fields.length) return res.status(400).json({error:'No fields to update'});
  const vals=fields.map(k=>req.body[k]); const set=fields.map((k,i)=>`${k}=$${i+1}`).join(',');
  vals.push(req.params.id);
  const r=await q(`UPDATE apartments SET ${set} WHERE id=$${vals.length} RETURNING *`,vals);
  if(!r.rows.length)return res.status(404).json({error:'Apartment not found'});
  res.json(r.rows[0]);
}));

/* ---------- PARKING BAYS ---------- */

app.get('/api/parking-bays', auth, asyncRoute(async (req,res)=>{
  const apartmentId=req.query.apartment_id;
  const r=apartmentId
    ? await q('SELECT * FROM parking_bays WHERE apartment_id=$1 ORDER BY tower,floor,bay_number',[apartmentId])
    : await q('SELECT * FROM parking_bays ORDER BY apartment_id,tower,floor,bay_number');
  res.json(r.rows);
}));

app.post('/api/parking-bays', auth, roles('admin'), asyncRoute(async(req,res)=>{
  const {apartment_id,tower,floor,bay_number,status}=req.body;
  if(!apartment_id || !bay_number)return res.status(400).json({error:'apartment_id and bay_number are required'});
  const r=await q(`
    INSERT INTO parking_bays(apartment_id,tower,floor,bay_number,status)
    VALUES($1,$2,$3,$4,$5) RETURNING *
  `,[apartment_id,tower || null,floor || null,bay_number,status || 'available']);
  res.status(201).json(r.rows[0]);
}));

app.patch('/api/parking-bays/:id', auth, roles('admin'), asyncRoute(async(req,res)=>{
  const fields=['tower','floor','bay_number','status'].filter(k=>Object.hasOwn(req.body,k));
  if(!fields.length)return res.status(400).json({error:'No fields to update'});
  const vals=fields.map(k=>req.body[k]); const set=fields.map((k,i)=>`${k}=$${i+1}`).join(',');
  vals.push(req.params.id);
  const r=await q(`UPDATE parking_bays SET ${set} WHERE id=$${vals.length} RETURNING *`,vals);
  if(!r.rows.length)return res.status(404).json({error:'Parking bay not found'});
  res.json(r.rows[0]);
}));

/* ---------- SUBSCRIPTIONS ---------- */

app.get('/api/subscriptions', auth, asyncRoute(async(req,res)=>{
  const r=await q(`
    SELECT s.*, p.name AS plan_name, p.monthly_price, v.registration_number
    FROM subscriptions s
    JOIN service_plans p ON p.id=s.plan_id
    JOIN vehicles v ON v.id=s.vehicle_id
    WHERE s.customer_id=$1 ORDER BY s.created_at DESC
  `,[req.user.sub]);
  res.json(r.rows);
}));

app.post('/api/subscriptions', auth, asyncRoute(async(req,res)=>{
  const {vehicle_id,plan_id,start_date,end_date,razorpay_subscription_id}=req.body;
  if(!vehicle_id || !plan_id)return res.status(400).json({error:'vehicle_id and plan_id are required'});
  const vr=await q('SELECT id FROM vehicles WHERE id=$1 AND customer_id=$2',[vehicle_id,req.user.sub]);
  if(!vr.rows.length)return res.status(404).json({error:'Vehicle not found'});
  const r=await q(`
    INSERT INTO subscriptions(customer_id,vehicle_id,plan_id,status,start_date,end_date,razorpay_subscription_id)
    VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *
  `,[req.user.sub,vehicle_id,plan_id,'active',start_date || new Date().toISOString().slice(0,10),end_date || null,razorpay_subscription_id || null]);
  res.status(201).json(r.rows[0]);
}));

app.patch('/api/subscriptions/:id', auth, asyncRoute(async(req,res)=>{
  const fields=['status','end_date','razorpay_subscription_id'].filter(k=>Object.hasOwn(req.body,k));
  if(!fields.length)return res.status(400).json({error:'No fields to update'});
  const vals=fields.map(k=>req.body[k]); const set=fields.map((k,i)=>`${k}=$${i+1}`).join(',');
  vals.push(req.params.id,req.user.sub);
  const r=await q(`UPDATE subscriptions SET ${set} WHERE id=$${vals.length-1} AND customer_id=$${vals.length} RETURNING *`,vals);
  if(!r.rows.length)return res.status(404).json({error:'Subscription not found'});
  res.json(r.rows[0]);
}));

/* ---------- BOOKINGS ---------- */

app.get('/api/bookings', auth, asyncRoute(async(req,res)=>{
  let r;
  if(req.user.role==='admin'){
    r=await q(`
      SELECT b.*, c.full_name AS customer_name,c.phone AS customer_phone,
             v.registration_number,v.make,v.model,
             a.name AS apartment_name,p.full_name AS partner_name
      FROM bookings b
      JOIN customers c ON c.id=b.customer_id
      JOIN vehicles v ON v.id=b.vehicle_id
      LEFT JOIN apartments a ON a.id=b.apartment_id
      LEFT JOIN partners p ON p.id=b.partner_id
      ORDER BY b.scheduled_date DESC,b.scheduled_time DESC
    `);
  } else if(req.user.role==='partner'){
    r=await q(`
      SELECT b.*, c.full_name AS customer_name,c.phone AS customer_phone,
             v.registration_number,v.make,v.model,a.name AS apartment_name
      FROM bookings b JOIN customers c ON c.id=b.customer_id
      JOIN vehicles v ON v.id=b.vehicle_id
      LEFT JOIN apartments a ON a.id=b.apartment_id
      WHERE b.partner_id=$1 ORDER BY b.scheduled_date,b.scheduled_time
    `,[req.user.sub]);
  } else {
    r=await q(`
      SELECT b.*, v.registration_number,v.make,v.model,a.name AS apartment_name,
             p.full_name AS partner_name
      FROM bookings b JOIN vehicles v ON v.id=b.vehicle_id
      LEFT JOIN apartments a ON a.id=b.apartment_id
      LEFT JOIN partners p ON p.id=b.partner_id
      WHERE b.customer_id=$1 ORDER BY b.scheduled_date DESC,b.scheduled_time DESC
    `,[req.user.sub]);
  }
  res.json(r.rows);
}));

app.post('/api/bookings', auth, asyncRoute(async(req,res)=>{
  const {vehicle_id,apartment_id,parking_bay_id,service_type,scheduled_date,scheduled_time,customer_notes}=req.body;
  if(!vehicle_id || !service_type || !scheduled_date || !scheduled_time)return res.status(400).json({error:'vehicle_id, service_type, scheduled_date and scheduled_time are required'});
  const vr=await q('SELECT * FROM vehicles WHERE id=$1 AND customer_id=$2',[vehicle_id,req.user.sub]);
  if(!vr.rows.length)return res.status(404).json({error:'Vehicle not found'});
  const r=await q(`
    INSERT INTO bookings(customer_id,vehicle_id,apartment_id,parking_bay_id,service_type,scheduled_date,scheduled_time,status,customer_notes)
    VALUES($1,$2,$3,$4,$5,$6,$7,'scheduled',$8) RETURNING *
  `,[req.user.sub,vehicle_id,apartment_id || null,parking_bay_id || vr.rows[0].parking_bay_id || null,service_type,scheduled_date,scheduled_time,customer_notes || null]);
  res.status(201).json(r.rows[0]);
}));

app.patch('/api/bookings/:id', auth, asyncRoute(async(req,res)=>{
  const fields=['parking_bay_id','service_type','scheduled_date','scheduled_time','status','customer_notes','partner_notes','partner_id','before_photo_url','after_photo_url','started_at','completed_at'].filter(k=>Object.hasOwn(req.body,k));
  if(!fields.length)return res.status(400).json({error:'No fields to update'});
  const vals=fields.map(k=>req.body[k]); const set=fields.map((k,i)=>`${k}=$${i+1}`).join(',');
  vals.push(req.params.id);
  let where=`id=$${vals.length}`;
  if(req.user.role==='customer') { vals.push(req.user.sub); where += ` AND customer_id=$${vals.length}`; }
  if(req.user.role==='partner') { vals.push(req.user.sub); where += ` AND partner_id=$${vals.length}`; }
  const r=await q(`UPDATE bookings SET ${set} WHERE ${where} RETURNING *`,vals);
  if(!r.rows.length)return res.status(404).json({error:'Booking not found or not permitted'});
  res.json(r.rows[0]);
}));

app.post('/api/bookings/:id/start', auth, roles('partner','admin'), asyncRoute(async(req,res)=>{
  const r=await q(`UPDATE bookings SET status='in_progress',started_at=now() WHERE id=$1 ${req.user.role==='partner'?'AND partner_id=$2':''} RETURNING *`,
    req.user.role==='partner'?[req.params.id,req.user.sub]:[req.params.id]);
  if(!r.rows.length)return res.status(404).json({error:'Booking not found'});
  res.json(r.rows[0]);
}));

app.post('/api/bookings/:id/complete', auth, roles('partner','admin'), asyncRoute(async(req,res)=>{
  const r=await q(`UPDATE bookings SET status='completed',completed_at=now(),after_photo_url=COALESCE($2,after_photo_url),partner_notes=COALESCE($3,partner_notes)
    WHERE id=$1 ${req.user.role==='partner'?'AND partner_id=$4':''} RETURNING *`,
    req.user.role==='partner'
      ? [req.params.id,req.body.after_photo_url || null,req.body.partner_notes || null,req.user.sub]
      : [req.params.id,req.body.after_photo_url || null,req.body.partner_notes || null]);
  if(!r.rows.length)return res.status(404).json({error:'Booking not found'});
  res.json(r.rows[0]);
}));

/* ---------- PARTNERS ---------- */

app.get('/api/partners', auth, roles('admin'), asyncRoute(async(_,res)=>{
  const r=await q(`
    SELECT p.*,COALESCE(x.job_count,0)::int AS current_jobs
    FROM partners p
    LEFT JOIN (
      SELECT partner_id,count(*) job_count FROM bookings
      WHERE status IN ('scheduled','assigned','in_progress') GROUP BY partner_id
    ) x ON x.partner_id=p.id ORDER BY p.full_name
  `);
  res.json(r.rows);
}));

app.post('/api/partners', auth, roles('admin'), asyncRoute(async(req,res)=>{
  const {full_name,phone,email,employee_code,status}=req.body;
  if(!full_name || !phone)return res.status(400).json({error:'full_name and phone are required'});
  const r=await q(`INSERT INTO partners(full_name,phone,email,employee_code,status,rating,jobs_completed)
    VALUES($1,$2,$3,$4,$5,0,0) RETURNING *`,
    [full_name,phone,email || null,employee_code || null,status || 'active']);
  res.status(201).json(r.rows[0]);
}));

app.patch('/api/partners/:id', auth, roles('admin'), asyncRoute(async(req,res)=>{
  const fields=['full_name','phone','email','employee_code','status','rating','jobs_completed'].filter(k=>Object.hasOwn(req.body,k));
  if(!fields.length)return res.status(400).json({error:'No fields to update'});
  const vals=fields.map(k=>req.body[k]); const set=fields.map((k,i)=>`${k}=$${i+1}`).join(',');
  vals.push(req.params.id);
  const r=await q(`UPDATE partners SET ${set} WHERE id=$${vals.length} RETURNING *`,vals);
  if(!r.rows.length)return res.status(404).json({error:'Partner not found'});
  res.json(r.rows[0]);
}));

app.post('/api/bookings/:id/assign-partner', auth, roles('admin'), asyncRoute(async(req,res)=>{
  const {partner_id}=req.body;
  if(!partner_id)return res.status(400).json({error:'partner_id is required'});
  const r=await q(`UPDATE bookings SET partner_id=$1,status='assigned' WHERE id=$2 RETURNING *`,[partner_id,req.params.id]);
  if(!r.rows.length)return res.status(404).json({error:'Booking not found'});
  res.json(r.rows[0]);
}));

/* ---------- RATINGS ---------- */

app.post('/api/ratings', auth, asyncRoute(async(req,res)=>{
  const {booking_id,rating,comment}=req.body;
  if(!booking_id || !rating)return res.status(400).json({error:'booking_id and rating are required'});
  if(Number(rating)<1 || Number(rating)>5)return res.status(400).json({error:'rating must be between 1 and 5'});
  const b=await q('SELECT * FROM bookings WHERE id=$1 AND customer_id=$2',[booking_id,req.user.sub]);
  if(!b.rows.length)return res.status(404).json({error:'Booking not found'});
  const r=await q(`INSERT INTO ratings(booking_id,customer_id,partner_id,rating,comment)
    VALUES($1,$2,$3,$4,$5) RETURNING *`,
    [booking_id,req.user.sub,b.rows[0].partner_id || null,Number(rating),comment || null]);
  res.status(201).json(r.rows[0]);
}));

/* ---------- NOTIFICATIONS ---------- */

app.get('/api/notifications', auth, asyncRoute(async(req,res)=>{
  const r=await q(`SELECT * FROM notifications WHERE customer_id=$1 OR partner_id=$1 ORDER BY created_at DESC`,[req.user.sub]);
  res.json(r.rows);
}));

app.patch('/api/notifications/:id/read', auth, asyncRoute(async(req,res)=>{
  const r=await q(`UPDATE notifications SET read_at=now() WHERE id=$1 AND (customer_id=$2 OR partner_id=$2) RETURNING *`,[req.params.id,req.user.sub]);
  if(!r.rows.length)return res.status(404).json({error:'Notification not found'});
  res.json(r.rows[0]);
}));

/* ---------- PAYMENTS ---------- */

app.get('/api/payments', auth, asyncRoute(async(req,res)=>{
  const r=await q('SELECT * FROM payments WHERE customer_id=$1 ORDER BY created_at DESC',[req.user.sub]);
  res.json(r.rows);
}));

app.post('/api/payments/order', auth, asyncRoute(async(req,res)=>{
  const {subscription_id,booking_id,amount}=req.body;
  if(!amount)return res.status(400).json({error:'amount is required'});
  if(!razorpay)return res.status(503).json({error:'Razorpay is not configured'});
  const order=await razorpay.orders.create({amount:Math.round(Number(amount)*100),currency:'INR',receipt:`ccb_${Date.now()}`});
  const r=await q(`INSERT INTO payments(customer_id,subscription_id,booking_id,amount,currency,status,payment_method,razorpay_order_id)
    VALUES($1,$2,$3,$4,'INR','created','razorpay',$5) RETURNING *`,
    [req.user.sub,subscription_id || null,booking_id || null,Number(amount),order.id]);
  res.status(201).json({order,payment:r.rows[0]});
}));

app.post('/api/payments/verify', auth, asyncRoute(async(req,res)=>{
  const {razorpay_order_id,razorpay_payment_id,payment_id,status='paid'}=req.body;
  const id=payment_id;
  const r=await q(`UPDATE payments SET razorpay_payment_id=$1,status=$2 WHERE id=$3 AND customer_id=$4 RETURNING *`,
    [razorpay_payment_id || null,status,id,req.user.sub]);
  if(!r.rows.length)return res.status(404).json({error:'Payment not found'});
  res.json(r.rows[0]);
}));

/* ---------- DASHBOARDS ---------- */

app.get('/api/dashboard', auth, asyncRoute(async(req,res)=>{
  if(req.user.role==='admin'){
    const [customers,subscriptions,bookings,partners,apartments,revenue] = await Promise.all([
      q(`SELECT count(*)::int count FROM customers WHERE role='customer'`),
      q(`SELECT count(*)::int count FROM subscriptions WHERE status='active'`),
      q(`SELECT count(*)::int count FROM bookings WHERE scheduled_date >= current_date`),
      q(`SELECT count(*)::int count FROM partners WHERE status='active'`),
      q(`SELECT count(*)::int count FROM apartments WHERE status IS NULL OR status <> 'inactive'`),
      q(`SELECT COALESCE(sum(amount),0) total FROM payments WHERE status='paid'`)
    ]);
    return res.json({
      customers:customers.rows[0].count, active_subscriptions:subscriptions.rows[0].count,
      upcoming_bookings:bookings.rows[0].count, active_partners:partners.rows[0].count,
      active_apartments:apartments.rows[0].count, revenue:Number(revenue.rows[0].total)
    });
  }
  const [vehicles,subscriptions,bookings,unread] = await Promise.all([
    q('SELECT count(*)::int count FROM vehicles WHERE customer_id=$1',[req.user.sub]),
    q(`SELECT count(*)::int count FROM subscriptions WHERE customer_id=$1 AND status='active'`,[req.user.sub]),
    q(`SELECT count(*)::int count FROM bookings WHERE customer_id=$1 AND scheduled_date >= current_date`,[req.user.sub]),
    q(`SELECT count(*)::int count FROM notifications WHERE customer_id=$1 AND read_at IS NULL`,[req.user.sub])
  ]);
  res.json({vehicles:vehicles.rows[0].count,active_subscriptions:subscriptions.rows[0].count,upcoming_bookings:bookings.rows[0].count,unread_notifications:unread.rows[0].count});
}));

/* ---------- UPLOADS ---------- */

app.post('/api/uploads', auth, upload.single('file'), (req,res)=>{
  if(!req.file)return res.status(400).json({error:'file is required'});
  res.status(201).json({filename:req.file.filename,original_name:req.file.originalname,path:`/uploads/${req.file.filename}`});
});
app.use('/uploads', express.static(uploadDir));

app.use((req,res)=>res.status(404).json({error:'Route not found',path:req.path}));
app.use((err,req,res,next)=>{
  console.error(err);
  res.status(500).json({error:'Internal server error',detail:process.env.NODE_ENV==='production' ? undefined : err.message});
});

app.listen(PORT,()=>console.log(`CarCareBay API listening on :${PORT}`));
