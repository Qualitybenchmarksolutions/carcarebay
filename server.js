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
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL?.includes('supabase.co') ? { rejectUnauthorized: false } : undefined });
const origins = (process.env.CORS_ORIGINS || '*').split(',').map(s => s.trim());
app.use(cors({ origin: (o, cb) => cb(null, !o || origins.includes('*') || origins.includes(o)) }));
app.use(express.json({ limit: '5mb' }));

const uploadDir = path.resolve(process.env.STORAGE_DIR || './uploads');
fs.mkdirSync(uploadDir, { recursive: true });
const upload = multer({ dest: uploadDir });
const razorpay = process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET
  ? new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET }) : null;

const q = (text, params = []) => pool.query(text, params);
const sign = u => jwt.sign({ sub: u.id, role: u.role, name: u.full_name }, process.env.JWT_SECRET, { expiresIn: '7d' });
function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    if (!h.startsWith('Bearer ')) throw new Error('Missing token');
    req.user = jwt.verify(h.slice(7), process.env.JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Unauthorized' }); }
}
const roles = (...rs) => (req, res, next) => rs.includes(req.user.role) ? next() : res.status(403).json({ error: 'Forbidden' });
const bad = (res, msg) => res.status(400).json({ error: msg });

async function ensureAuthTable() {
  await q(`CREATE TABLE IF NOT EXISTS auth_credentials (
    customer_id uuid PRIMARY KEY REFERENCES customers(id) ON DELETE CASCADE,
    password_hash text NOT NULL,
    created_at timestamptz DEFAULT now()
  )`);
}

app.get('/health', async (_, res) => {
  try { await q('SELECT 1'); await ensureAuthTable(); res.json({ ok: true, service: 'CarCareBay API', database: 'postgresql' }); }
  catch (e) { console.error(e); res.status(503).json({ ok: false, error: 'Database unavailable' }); }
});

app.get('/api/plans', async (_, res) => {
  try { const { rows } = await q(`SELECT id,name,description,monthly_price,monthly_price*100 AS price_paise,COALESCE(wash_credits,0) AS included_exterior,COALESCE(interior_credits,0) AS included_interior,active FROM service_plans WHERE active=true ORDER BY monthly_price`); res.json(rows); }
  catch (e) { console.error(e); res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/register', async (req, res) => {
  const { name, full_name, phone, email, password, apartment_id } = req.body;
  const customerName = full_name || name;
  if (!customerName || !phone || !password) return bad(res, 'Name, phone and password required');
  try {
    await ensureAuthTable();
    const exists = await q('SELECT id FROM customers WHERE phone=$1 LIMIT 1', [phone]);
    if (exists.rowCount) return res.status(409).json({ error: 'Phone already registered' });
    const hash = await bcrypt.hash(password, 10);
    const c = await q(`INSERT INTO customers(full_name,phone,email,apartment_id,role,status) VALUES($1,$2,$3,$4,'customer','active') RETURNING *`, [customerName, phone, email || null, apartment_id || null]);
    await q('INSERT INTO auth_credentials(customer_id,password_hash) VALUES($1,$2)', [c.rows[0].id, hash]);
    const user = c.rows[0]; res.status(201).json({ token: sign(user), user });
  } catch (e) { console.error(e); res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  const { phone, password } = req.body;
  if (!phone || !password) return bad(res, 'Phone number and password required');
  try {
    await ensureAuthTable();
    const r = await q(`SELECT c.*,a.password_hash FROM customers c JOIN auth_credentials a ON a.customer_id=c.id WHERE c.phone=$1 LIMIT 1`, [phone]);
    if (!r.rowCount || !(await bcrypt.compare(password, r.rows[0].password_hash))) return res.status(401).json({ error: 'Invalid phone or password' });
    const user = r.rows[0]; delete user.password_hash; res.json({ token: sign(user), user });
  } catch (e) { console.error(e); res.status(500).json({ error: e.message }); }
});

app.get('/api/me', auth, async (req, res) => {
  try { const { rows } = await q('SELECT * FROM customers WHERE id=$1', [req.user.sub]); if (!rows[0]) return res.status(404).json({ error: 'Customer not found' }); res.json(rows[0]); }
  catch(e){res.status(500).json({error:e.message});}
});

app.get('/api/vehicles', auth, async (req,res)=>{ try { const {rows}=await q('SELECT * FROM vehicles WHERE customer_id=$1 ORDER BY created_at DESC',[req.user.sub]); res.json(rows); } catch(e){res.status(500).json({error:e.message});} });
app.post('/api/vehicles', auth, async (req,res)=>{
  const { make, model, registration_number, color, vehicle_type, parking_bay_id } = req.body;
  if (!registration_number || !make || !model) return bad(res,'Make, model and registration number required');
  try { const {rows}=await q(`INSERT INTO vehicles(customer_id,parking_bay_id,registration_number,make,model,color,vehicle_type) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,[req.user.sub,parking_bay_id||null,registration_number,make,model,color||null,vehicle_type||'car']); res.status(201).json(rows[0]); }
  catch(e){res.status(500).json({error:e.message});}
});
app.patch('/api/vehicles/:id', auth, async (req,res)=>{ try { const fields=['registration_number','make','model','color','vehicle_type','parking_bay_id']; const vals=[]; const sets=[]; for(const f of fields){if(req.body[f]!==undefined){vals.push(req.body[f]);sets.push(`${f}=$${vals.length}`)}} if(!sets.length)return bad(res,'No fields to update'); vals.push(req.params.id,req.user.sub); const {rows}=await q(`UPDATE vehicles SET ${sets.join(',')} WHERE id=$${vals.length-1} AND customer_id=$${vals.length} RETURNING *`,vals); if(!rows[0])return res.status(404).json({error:'Vehicle not found'});res.json(rows[0]); }catch(e){res.status(500).json({error:e.message});} });
app.delete('/api/vehicles/:id', auth, async (req,res)=>{try{const r=await q('DELETE FROM vehicles WHERE id=$1 AND customer_id=$2 RETURNING id',[req.params.id,req.user.sub]);if(!r.rowCount)return res.status(404).json({error:'Vehicle not found'});res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});

app.get('/api/apartments', async (_,res)=>{try{const {rows}=await q(`SELECT a.*,COUNT(DISTINCT p.id)::int AS parking_bays FROM apartments a LEFT JOIN parking_bays p ON p.apartment_id=a.id GROUP BY a.id ORDER BY a.name`);res.json(rows);}catch(e){res.status(500).json({error:e.message});}});
app.post('/api/apartments', auth, roles('admin'), async(req,res)=>{const {name,address,city,pincode,total_cars,status}=req.body;if(!name)return bad(res,'Name required');try{const {rows}=await q(`INSERT INTO apartments(name,address,city,pincode,total_cars,status) VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,[name,address||null,city||'Bengaluru',pincode||null,total_cars||0,status||'active']);res.status(201).json(rows[0]);}catch(e){res.status(500).json({error:e.message});}});

app.get('/api/apartments/:id/parking-bays', async(req,res)=>{try{const {rows}=await q('SELECT * FROM parking_bays WHERE apartment_id=$1 ORDER BY tower,floor,bay_number',[req.params.id]);res.json(rows);}catch(e){res.status(500).json({error:e.message});}});
app.post('/api/parking-bays', auth, roles('admin'), async(req,res)=>{const {apartment_id,tower,floor,bay_number,status}=req.body;if(!apartment_id||!bay_number)return bad(res,'Apartment and bay number required');try{const {rows}=await q(`INSERT INTO parking_bays(apartment_id,tower,floor,bay_number,status) VALUES($1,$2,$3,$4,$5) RETURNING *`,[apartment_id,tower||null,floor||null,bay_number,status||'available']);res.status(201).json(rows[0]);}catch(e){res.status(500).json({error:e.message});}});

app.get('/api/subscriptions', auth, async(req,res)=>{try{const {rows}=await q(`SELECT s.*,p.name AS plan_name,p.monthly_price,p.wash_credits,p.interior_credits,v.registration_number,v.make,v.model FROM subscriptions s JOIN service_plans p ON p.id=s.plan_id JOIN vehicles v ON v.id=s.vehicle_id WHERE s.customer_id=$1 ORDER BY s.created_at DESC`,[req.user.sub]);res.json(rows);}catch(e){res.status(500).json({error:e.message});}});
app.post('/api/subscriptions', auth, async(req,res)=>{const {vehicle_id,plan_id,start_date,end_date}=req.body;if(!vehicle_id||!plan_id)return bad(res,'Vehicle and plan required');try{const v=await q('SELECT id FROM vehicles WHERE id=$1 AND customer_id=$2',[vehicle_id,req.user.sub]);if(!v.rowCount)return res.status(404).json({error:'Vehicle not found'});const p=await q('SELECT id FROM service_plans WHERE id=$1 AND active=true',[plan_id]);if(!p.rowCount)return res.status(404).json({error:'Plan not found'});const {rows}=await q(`INSERT INTO subscriptions(customer_id,vehicle_id,plan_id,status,start_date,end_date) VALUES($1,$2,$3,'active',$4,$5) RETURNING *`,[req.user.sub,vehicle_id,plan_id,start_date||new Date().toISOString().slice(0,10),end_date||null]);res.status(201).json(rows[0]);}catch(e){res.status(500).json({error:e.message});}});

app.get('/api/bookings', auth, async(req,res)=>{try{const {rows}=await q(`SELECT b.*,v.registration_number,v.make,v.model,a.name AS apartment_name,pb.tower,pb.floor,pb.bay_number,pt.full_name AS partner_name FROM bookings b LEFT JOIN vehicles v ON v.id=b.vehicle_id LEFT JOIN apartments a ON a.id=b.apartment_id LEFT JOIN parking_bays pb ON pb.id=b.parking_bay_id LEFT JOIN partners pt ON pt.id=b.partner_id WHERE b.customer_id=$1 ORDER BY b.created_at DESC`,[req.user.sub]);res.json(rows);}catch(e){res.status(500).json({error:e.message});}});
app.post('/api/bookings', auth, async(req,res)=>{const {vehicle_id,apartment_id,parking_bay_id,service_type,scheduled_date,scheduled_time,customer_notes}=req.body;if(!vehicle_id||!service_type||!scheduled_date||!scheduled_time)return bad(res,'Vehicle, service type, date and time required');try{const v=await q('SELECT id,parking_bay_id FROM vehicles WHERE id=$1 AND customer_id=$2',[vehicle_id,req.user.sub]);if(!v.rowCount)return res.status(404).json({error:'Vehicle not found'});const bay=parking_bay_id||v.rows[0].parking_bay_id;let apt=apartment_id||null;if(!apt&&bay){const ar=await q('SELECT apartment_id FROM parking_bays WHERE id=$1',[bay]);apt=ar.rows[0]?.apartment_id||null;}const {rows}=await q(`INSERT INTO bookings(customer_id,vehicle_id,apartment_id,parking_bay_id,service_type,scheduled_date,scheduled_time,status,customer_notes) VALUES($1,$2,$3,$4,$5,$6,$7,'scheduled',$8) RETURNING *`,[req.user.sub,vehicle_id,apt,bay,service_type,scheduled_date,scheduled_time,customer_notes||null]);res.status(201).json(rows[0]);}catch(e){res.status(500).json({error:e.message});}});
app.patch('/api/bookings/:id', auth, async(req,res)=>{try{const allowed=['status','customer_notes','scheduled_date','scheduled_time'];const vals=[];const sets=[];for(const f of allowed){if(req.body[f]!==undefined){vals.push(req.body[f]);sets.push(`${f}=$${vals.length}`)}}if(!sets.length)return bad(res,'No fields to update');vals.push(req.params.id,req.user.sub);const {rows}=await q(`UPDATE bookings SET ${sets.join(',')} WHERE id=$${vals.length-1} AND customer_id=$${vals.length} RETURNING *`,vals);if(!rows[0])return res.status(404).json({error:'Booking not found'});res.json(rows[0]);}catch(e){res.status(500).json({error:e.message});}});

app.get('/api/partner/jobs', auth, roles('partner','admin'), async(req,res)=>{try{const where=req.user.role==='admin'?'':' AND b.partner_id=$1';const params=req.user.role==='admin'?[]:[req.user.sub];const {rows}=await q(`SELECT b.*,c.full_name AS customer_name,c.phone AS customer_phone,v.registration_number,v.make,v.model,a.name AS apartment_name,pb.tower,pb.floor,pb.bay_number FROM bookings b JOIN customers c ON c.id=b.customer_id JOIN vehicles v ON v.id=b.vehicle_id LEFT JOIN apartments a ON a.id=b.apartment_id LEFT JOIN parking_bays pb ON pb.id=b.parking_bay_id WHERE 1=1${where} ORDER BY b.scheduled_date,b.scheduled_time`,params);res.json(rows);}catch(e){res.status(500).json({error:e.message});}});
app.patch('/api/partner/jobs/:id', auth, roles('partner','admin'), async(req,res)=>{const {status,partner_notes,before_photo_url,after_photo_url}=req.body;try{const {rows}=await q(`UPDATE bookings SET status=COALESCE($1,status),partner_notes=COALESCE($2,partner_notes),before_photo_url=COALESCE($3,before_photo_url),after_photo_url=COALESCE($4,after_photo_url),started_at=CASE WHEN $1='in_progress' AND started_at IS NULL THEN now() ELSE started_at END,completed_at=CASE WHEN $1='completed' THEN now() ELSE completed_at END,partner_id=CASE WHEN $5='admin' THEN partner_id ELSE $6 END WHERE id=$7 ${req.user.role==='admin'?'':'AND partner_id=$6'} RETURNING *`,[status||null,partner_notes||null,before_photo_url||null,after_photo_url||null,req.user.role,req.user.sub,req.params.id]);if(!rows[0])return res.status(404).json({error:'Job not found'});res.json(rows[0]);}catch(e){res.status(500).json({error:e.message});}});

app.post('/api/ratings', auth, async(req,res)=>{const {booking_id,rating,comment}=req.body;if(!booking_id||!rating)return bad(res,'Booking and rating required');if(Number(rating)<1||Number(rating)>5)return bad(res,'Rating must be 1 to 5');try{const b=await q('SELECT partner_id FROM bookings WHERE id=$1 AND customer_id=$2',[booking_id,req.user.sub]);if(!b.rowCount)return res.status(404).json({error:'Booking not found'});const {rows}=await q(`INSERT INTO ratings(booking_id,customer_id,partner_id,rating,comment) VALUES($1,$2,$3,$4,$5) RETURNING *`,[booking_id,req.user.sub,b.rows[0].partner_id||null,rating,comment||null]);res.status(201).json(rows[0]);}catch(e){res.status(500).json({error:e.message});}});

app.get('/api/dashboard', auth, roles('admin'), async(_,res)=>{try{const [c,s,b,r,p,a]=await Promise.all([q("SELECT COUNT(*)::int AS count FROM customers WHERE role='customer'"),q("SELECT COUNT(*)::int AS count FROM subscriptions WHERE status='active'"),q('SELECT COUNT(*)::int AS count FROM bookings'),q('SELECT COALESCE(AVG(rating),0)::numeric(10,2) AS average FROM ratings'),q("SELECT COALESCE(SUM(monthly_price),0)::numeric(12,2) AS monthly_plan_value FROM service_plans WHERE active=true"),q('SELECT COUNT(*)::int AS count FROM apartments')]);res.json({customers:c.rows[0].count,active_subscriptions:s.rows[0].count,bookings:b.rows[0].count,average_rating:r.rows[0].average,active_plan_value:p.rows[0].monthly_plan_value,apartments:a.rows[0].count});}catch(e){res.status(500).json({error:e.message});}});

app.post('/api/uploads', auth, upload.single('file'), async(req,res)=>{if(!req.file)return bad(res,'File required');res.status(201).json({filename:req.file.filename,original_name:req.file.originalname,path:req.file.path});});

app.get('/api/notifications', auth, async(req,res)=>{try{const {rows}=await q(`SELECT * FROM notifications WHERE customer_id=$1 OR partner_id=$1 ORDER BY created_at DESC LIMIT 100`,[req.user.sub]);res.json(rows);}catch(e){res.status(500).json({error:e.message});}});
app.patch('/api/notifications/:id/read', auth, async(req,res)=>{try{const {rows}=await q(`UPDATE notifications SET read_at=now() WHERE id=$1 AND (customer_id=$2 OR partner_id=$2) RETURNING *`,[req.params.id,req.user.sub]);if(!rows[0])return res.status(404).json({error:'Notification not found'});res.json(rows[0]);}catch(e){res.status(500).json({error:e.message});}});

app.get('/api/payments', auth, async(req,res)=>{try{const {rows}=await q('SELECT * FROM payments WHERE customer_id=$1 ORDER BY created_at DESC',[req.user.sub]);res.json(rows);}catch(e){res.status(500).json({error:e.message});}});
app.post('/api/payments/order', auth, async(req,res)=>{const {subscription_id,booking_id,amount}=req.body;if(!amount)return bad(res,'Amount required');try{let order=null;if(razorpay){order=await razorpay.orders.create({amount:Math.round(Number(amount)*100),currency:'INR',receipt:`ccb_${Date.now()}`});}const {rows}=await q(`INSERT INTO payments(customer_id,subscription_id,booking_id,amount,currency,status,payment_method,razorpay_order_id) VALUES($1,$2,$3,$4,'INR','created','razorpay',$5) RETURNING *`,[req.user.sub,subscription_id||null,booking_id||null,amount,order?.id||null]);res.status(201).json({payment:rows[0],order});}catch(e){res.status(500).json({error:e.message});}});

app.use((_,res)=>res.status(404).json({error:'Route not found'}));
app.listen(PORT,()=>console.log(`CarCareBay API listening on :${PORT}`));
