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
app.use(express.json({ limit: '10mb' }));

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

async function ensureApartmentLocationColumns() {
  await q(`ALTER TABLE apartments ADD COLUMN IF NOT EXISTS latitude numeric`);
  await q(`ALTER TABLE apartments ADD COLUMN IF NOT EXISTS longitude numeric`);
  await q(`ALTER TABLE apartments ADD COLUMN IF NOT EXISTS google_place_id text`);
  await q(`ALTER TABLE customers ADD COLUMN IF NOT EXISTS profile_photo_url text`);
}
ensureApartmentLocationColumns().catch(e => console.error('apartment location setup failed:', e.message));

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

app.patch('/api/me', auth, asyncRoute(async (req, res) => {
  const allowed=['full_name','email','profile_photo_url'];
  const fields=allowed.filter(k=>Object.prototype.hasOwnProperty.call(req.body,k));
  if(!fields.length)return res.status(400).json({error:'No fields to update'});
  const vals=fields.map(k=>req.body[k]);
  const set=fields.map((k,i)=>`${k}=$${i+1}`).join(',');
  vals.push(req.user.sub);
  const r=await q(`UPDATE customers SET ${set} WHERE id=$${vals.length} RETURNING *`,vals);
  if(!r.rows.length)return res.status(404).json({error:'Customer not found'});
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
  const { name, address, city, pincode, total_cars, status, latitude, longitude, google_place_id } = req.body;
  if (!name) return res.status(400).json({ error: 'name is required' });
  const r = await q(`
    INSERT INTO apartments(name,address,city,pincode,total_cars,status,latitude,longitude,google_place_id)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *
  `, [name,address || null,city || null,pincode || null,Number(total_cars || 0),status || 'active',
      latitude == null ? null : Number(latitude), longitude == null ? null : Number(longitude), google_place_id || null]);
  res.status(201).json(r.rows[0]);
}));

app.patch('/api/apartments/:id', auth, roles('admin'), asyncRoute(async (req,res)=>{
  const allowed=['name','address','city','pincode','total_cars','status','latitude','longitude','google_place_id'];
  const fields=allowed.filter(k=>Object.hasOwn(req.body,k));
  if(!fields.length) return res.status(400).json({error:'No fields to update'});
  const vals=fields.map(k=>['latitude','longitude'].includes(k) && req.body[k] !== null ? Number(req.body[k]) : req.body[k]);
  const set=fields.map((k,i)=>`${k}=$${i+1}`).join(',');
  vals.push(req.params.id);
  const r=await q(`UPDATE apartments SET ${set} WHERE id=$${vals.length} RETURNING *`,vals);
  if(!r.rows.length)return res.status(404).json({error:'Apartment not found'});
  res.json(r.rows[0]);
}));

/* ---------- GOOGLE APARTMENT MAPPING ---------- */

app.post('/api/admin/apartments/search-google', auth, roles('admin'), asyncRoute(async (req,res)=>{
  const query=String(req.body.query || '').trim();
  if(!query)return res.status(400).json({error:'query is required'});
  if(!process.env.GOOGLE_MAPS_API_KEY)return res.status(503).json({error:'GOOGLE_MAPS_API_KEY is not configured on Render'});
  const response=await fetch('https://places.googleapis.com/v1/places:searchText',{
    method:'POST',
    headers:{
      'Content-Type':'application/json',
      'X-Goog-Api-Key':process.env.GOOGLE_MAPS_API_KEY,
      'X-Goog-FieldMask':'places.id,places.displayName,places.formattedAddress,places.location,places.types'
    },
    body:JSON.stringify({textQuery:query,maxResultCount:10,languageCode:'en',regionCode:'IN'})
  });
  const data=await response.json();
  if(!response.ok)return res.status(response.status).json({error:data.error?.message || 'Google Places search failed'});
  res.json({places:(data.places || []).map(p=>({
    place_id:p.id,
    name:p.displayName?.text || '',
    address:p.formattedAddress || '',
    latitude:p.location?.latitude,
    longitude:p.location?.longitude,
    types:p.types || []
  }))});
}));

app.get('/admin/apartments-map', (req,res)=>{
  res.type('html').send(`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>CarCareBay - Map Apartments</title>
  <style>body{font-family:Arial,sans-serif;max-width:900px;margin:30px auto;padding:0 16px;background:#f7f8fa;color:#172033}h1{margin-bottom:6px}.card{background:#fff;border:1px solid #ddd;border-radius:14px;padding:18px;margin:14px 0;box-shadow:0 2px 8px #0000000b}input,select,button{font-size:16px;padding:11px;border-radius:9px;border:1px solid #ccc}input{width:100%;box-sizing:border-box;margin:6px 0 10px}button{cursor:pointer;background:#111827;color:#fff;border:0;margin:4px}.muted{color:#687385}.result{border:1px solid #ddd;border-radius:10px;padding:12px;margin:8px 0}.ok{color:#087f5b}.err{color:#b42318}.row{display:flex;gap:8px;flex-wrap:wrap}.row>*{flex:1;min-width:180px}</style></head><body>
  <h1>CarCareBay Apartment Mapping</h1><div class="muted">Search Google Places and save the verified coordinates to a CarCareBay apartment.</div>
  <div class="card"><h3>1. Admin login</h3><div class="row"><input id="phone" placeholder="Admin phone"><input id="password" type="password" placeholder="Admin password"></div><button onclick="login()">Sign in</button><span id="loginMsg"></span></div>
  <div class="card"><h3>2. Select CarCareBay apartment</h3><select id="apt" style="width:100%;padding:11px"></select><div id="aptInfo" class="muted" style="margin-top:8px"></div></div>
  <div class="card"><h3>3. Search Google</h3><input id="query" placeholder="e.g. Prestige Lakeside Habitat, Varthur, Bengaluru"><button onclick="searchPlaces()">Search</button><div id="results"></div></div>
  <script>
  let token='', apartments=[];
  const $=id=>document.getElementById(id);
  async function login(){let r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({phone:$('phone').value,password:$('password').value})});let d=await r.json();if(!r.ok){$('loginMsg').innerHTML='<span class="err"> '+(d.error||'Login failed')+'</span>';return}token=d.token;$('loginMsg').innerHTML='<span class="ok"> Signed in</span>';loadApartments()}
  async function loadApartments(){let r=await fetch('/api/apartments',{headers:{Authorization:'Bearer '+token}});apartments=await r.json();$('apt').innerHTML=apartments.map(a=>'<option value="'+a.id+'">'+esc(a.name)+'</option>').join('');updateInfo();}
  $('apt').onchange=updateInfo;function updateInfo(){let a=apartments.find(x=>x.id===$('apt').value);$('aptInfo').textContent=a?(a.address||'')+' | '+(a.latitude!=null?a.latitude+', '+a.longitude:'Not mapped yet'):''}
  async function searchPlaces(){if(!token){alert('Sign in first');return}let r=await fetch('/api/admin/apartments/search-google',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},body:JSON.stringify({query:$('query').value})});let d=await r.json();if(!r.ok){$('results').innerHTML='<div class="err">'+esc(d.error||'Search failed')+'</div>';return} $('results').innerHTML=(d.places||[]).map((p,i)=>'<div class="result"><b>'+esc(p.name)+'</b><div>'+esc(p.address)+'</div><div class="muted">'+p.latitude+', '+p.longitude+'</div><button onclick="mapPlace('+i+')">Map this apartment</button></div>').join('');window.places=d.places||[]}
  async function mapPlace(i){let p=window.places[i],id=$('apt').value;if(!id){alert('Select an apartment first');return}let r=await fetch('/api/apartments/'+id,{method:'PATCH',headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},body:JSON.stringify({address:p.address,latitude:p.latitude,longitude:p.longitude,google_place_id:p.place_id})});let d=await r.json();if(!r.ok){alert(d.error||'Could not map');return}alert('Apartment mapped successfully');loadApartments()}
  function esc(s){return String(s||'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
  </script></body></html>`);
});

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
  const pr=await q('SELECT * FROM service_plans WHERE id=$1 AND active=true',[plan_id]);
  if(!pr.rows.length)return res.status(404).json({error:'Plan not found'});

  // A membership is paid for once at the account level and its wash credits are shared
  // across every vehicle belonging to that customer. The selected vehicle is retained
  // only as the subscription's anchor vehicle for compatibility with the existing schema.
  const existing=await q(`SELECT * FROM subscriptions WHERE customer_id=$1 AND status='active' ORDER BY created_at DESC LIMIT 1`,[req.user.sub]);
  if(existing.rows.length){
    const current=existing.rows[0];
    if(String(current.plan_id)===String(plan_id)){
      const updated=(await q(`UPDATE subscriptions SET vehicle_id=$1, razorpay_subscription_id=COALESCE($2,razorpay_subscription_id) WHERE id=$3 RETURNING *`,[vehicle_id,razorpay_subscription_id || null,current.id])).rows[0];
      return res.json(updated);
    }
    const updated=(await q(`UPDATE subscriptions SET vehicle_id=$1, plan_id=$2, razorpay_subscription_id=COALESCE($3,razorpay_subscription_id) WHERE id=$4 RETURNING *`,[vehicle_id,plan_id,razorpay_subscription_id || null,current.id])).rows[0];

    const start=String(current.start_date || new Date().toISOString().slice(0,10)).slice(0,10);
    const end=current.end_date ? String(current.end_date).slice(0,10) : null;
    const countR=await q(`SELECT count(*)::int AS count FROM bookings WHERE customer_id=$1 AND status<>'cancelled' AND scheduled_date >= $2::date AND ($3::date IS NULL OR scheduled_date <= $3::date)`,[req.user.sub,start,end]);
    const total=Number(countR.rows[0].count||0), allowance=Number(pr.rows[0].wash_credits||0), excess=Math.max(0,total-allowance);
    if(excess>0){
      await q(`UPDATE bookings SET status='cancelled', customer_notes=COALESCE(customer_notes,'') || CASE WHEN COALESCE(customer_notes,'')='' THEN 'Cancelled automatically after account plan change.' ELSE ' Cancelled automatically after account plan change.' END WHERE id IN (
        SELECT id FROM bookings WHERE customer_id=$1 AND status IN ('scheduled','assigned') AND scheduled_date >= CURRENT_DATE ORDER BY scheduled_date DESC, scheduled_time DESC, created_at DESC LIMIT $2
      )`,[req.user.sub,excess]);
    }
    return res.json(updated);
  }

  const startValue=start_date || new Date().toISOString().slice(0,10);
  const r=await q(`
    INSERT INTO subscriptions(customer_id,vehicle_id,plan_id,status,start_date,end_date,razorpay_subscription_id)
    VALUES($1,$2,$3,'active',$4,COALESCE($5::date,($4::date + INTERVAL '1 month' - INTERVAL '1 day')::date),$6) RETURNING *
  `,[req.user.sub,vehicle_id,plan_id,startValue,end_date || null,razorpay_subscription_id || null]);
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

app.get('/api/availability', auth, asyncRoute(async(req,res)=>{
  const {vehicle_id,date}=req.query;
  if(!vehicle_id || !date)return res.status(400).json({error:'vehicle_id and date are required'});
  const vr=await q('SELECT id FROM vehicles WHERE id=$1 AND customer_id=$2',[vehicle_id,req.user.sub]);
  if(!vr.rows.length)return res.status(404).json({error:'Vehicle not found'});
  if(!/^\d{4}-\d{2}-\d{2}$/.test(String(date)))return res.status(400).json({error:'date must be YYYY-MM-DD'});

  // Pilot operating window. This can later be configured per apartment.
  const openingHour=10, closingHour=17, serviceMinutes=60;
  const partnerR=await q(`SELECT count(*)::int AS count FROM partners WHERE status='active'`);
  const activeStaff=Number(partnerR.rows[0]?.count||0);
  const jobsR=await q(`
    SELECT scheduled_date,scheduled_time
    FROM bookings
    WHERE scheduled_date=$1::date
      AND status IN ('scheduled','assigned','in_progress')
  `,[date]);
  const jobs=jobsR.rows.map(r=>{
    const [h,m]=String(r.scheduled_time).slice(0,5).split(':').map(Number);
    return h*60+m;
  });
  const existingR=await q(`
    SELECT scheduled_date,scheduled_time
    FROM bookings
    WHERE customer_id=$1 AND vehicle_id=$2 AND status<>'cancelled'
      AND (scheduled_date + scheduled_time) >= ($3::date - interval '1 day')
      AND (scheduled_date + scheduled_time) < ($3::date + interval '1 day' + interval '1 day')
  `,[req.user.sub,vehicle_id,date]);
  const existingVehicleTimes=existingR.rows.map(r=>({
    date:String(r.scheduled_date).slice(0,10),
    minutes:Number(String(r.scheduled_time).slice(0,2))*60+Number(String(r.scheduled_time).slice(3,5))
  }));

  const parts=new Intl.DateTimeFormat('en-GB',{timeZone:'Asia/Kolkata',hour:'2-digit',minute:'2-digit',hour12:false}).formatToParts(new Date());
  const nowHour=Number(parts.find(x=>x.type==='hour')?.value||0);
  const nowMinute=Number(parts.find(x=>x.type==='minute')?.value||0);
  const nowParts=new Intl.DateTimeFormat('en-GB',{timeZone:'Asia/Kolkata',year:'numeric',month:'2-digit',day:'2-digit'}).formatToParts(new Date());
  const todayParts=`${nowParts.find(x=>x.type==='year')?.value}-${nowParts.find(x=>x.type==='month')?.value}-${nowParts.find(x=>x.type==='day')?.value}`;
  const currentMinutes=nowHour*60+nowMinute;
  const slots=[];
  for(let hour=openingHour;hour<closingHour;hour++){
    const slotMinutes=hour*60;
    const time=`${String(hour).padStart(2,'0')}:00`;
    let available=true,reason=null;
    if(String(date)===todayParts && slotMinutes<=currentMinutes){available=false;reason='past';}
    const overlappingStaff=jobs.filter(start=>Math.abs(start-slotMinutes)<serviceMinutes).length;
    const [cy,cm,cd]=String(date).split('-').map(Number);
    const candidateMs=Date.UTC(cy,cm-1,cd,Math.floor(slotMinutes/60),slotMinutes%60);
    const vehicleBookings=existingVehicleTimes.map(x=>{
      const [y,m,d]=x.date.split('-').map(Number);
      const hh=Math.floor(x.minutes/60), mm=x.minutes%60;
      return Date.UTC(y,m-1,d,hh,mm);
    });
    const sameSlot=vehicleBookings.some(startMs=>startMs===candidateMs);
    if(available && sameSlot){available=false;reason='already_booked';}
    if(available && activeStaff<=0){available=false;reason='staff_unavailable';}
    if(available && overlappingStaff>=activeStaff){available=false;reason='staff_unavailable';}
    if(available && vehicleBookings.some(startMs=>candidateMs>startMs && candidateMs<startMs+4*60*60*1000)){available=false;reason='vehicle_window';}
    slots.push({time,label:new Date(2000,0,1,hour,0).toLocaleTimeString('en-IN',{hour:'numeric',minute:'2-digit'}),available,reason});
  }
  res.json({date,active_staff:activeStaff,service_minutes:serviceMinutes,operating_hours:{open:`${String(openingHour).padStart(2,'0')}:00`,close:`${String(closingHour).padStart(2,'0')}:00`},slots});
}));

app.post('/api/bookings', auth, asyncRoute(async(req,res)=>{
  const {vehicle_id,apartment_id,parking_bay_id,service_type,scheduled_date,scheduled_time,customer_notes}=req.body;
  if(!vehicle_id || !service_type || !scheduled_date || !scheduled_time)return res.status(400).json({error:'vehicle_id, service_type, scheduled_date and scheduled_time are required'});
  const vr=await q('SELECT * FROM vehicles WHERE id=$1 AND customer_id=$2',[vehicle_id,req.user.sub]);
  if(!vr.rows.length)return res.status(404).json({error:'Vehicle not found'});

  // Membership is account-level. One customer account has one shared wash allowance across all vehicles.
  const subR=await q(`SELECT s.*,p.name AS plan_name,p.wash_credits FROM subscriptions s JOIN service_plans p ON p.id=s.plan_id WHERE s.customer_id=$1 AND s.status='active' ORDER BY s.created_at DESC LIMIT 1`,[req.user.sub]);
  if(!subR.rows.length)return res.status(409).json({error:'Please activate a membership plan before booking'});
  const sub=subR.rows[0];
  // A vehicle needs a 4-hour service window before its NEXT booking.
  // Important: this is forward-looking only. An existing booking at 10:00 AM
  // blocks 10:00 AM through 1:59 PM, but it does NOT block an earlier booking
  // such as 8:00 AM. This keeps past/earlier times independent of a later job.
  const candidateTs = `($2::date + $3::time)`;
  const existingSlot=await q(`
    SELECT id, scheduled_date, scheduled_time
    FROM bookings
    WHERE customer_id=$1
      AND vehicle_id=$4
      AND status<>'cancelled'
      AND (scheduled_date + scheduled_time) <= ${candidateTs}
      AND (scheduled_date + scheduled_time) + interval '4 hours' > ${candidateTs}
    ORDER BY scheduled_date DESC, scheduled_time DESC
    LIMIT 1
  `,[req.user.sub,scheduled_date,scheduled_time,vehicle_id]);
  if(existingSlot.rows.length){
    const b=existingSlot.rows[0];
    return res.status(409).json({error:`This vehicle already has a booking at ${String(b.scheduled_time).slice(0,5)} on ${String(b.scheduled_date).slice(0,10)}. The next booking for this vehicle must be at least 4 hours later.`});
  }
  const maxBookingDate = new Date();
  maxBookingDate.setHours(0,0,0,0);
  maxBookingDate.setDate(maxBookingDate.getDate()+15);
  const requestedDateObj = new Date(`${scheduled_date}T00:00:00`);
  if(Number.isNaN(requestedDateObj.getTime()) || requestedDateObj > maxBookingDate || requestedDateObj < new Date(new Date().setHours(0,0,0,0)))return res.status(409).json({error:'Bookings can be made only within the next 15 days.'});
  const requestedHour=Number(String(scheduled_time).slice(0,2));
  const requestedMinute=Number(String(scheduled_time).slice(3,5));
  const requestedMinutes=requestedHour*60+requestedMinute;
  if(!Number.isFinite(requestedMinutes) || requestedMinutes<10*60 || requestedMinutes>=17*60)return res.status(409).json({error:'Bookings are available between 10:00 AM and 5:00 PM. Please choose an available slot.'});
  const staffR=await q(`SELECT count(*)::int AS count FROM partners WHERE status='active'`);
  const activeStaff=Number(staffR.rows[0]?.count||0);
  if(activeStaff<=0)return res.status(409).json({error:'No CarCare staff are available for booking right now. Please choose another time.'});
  const staffConflict=await q(`
    SELECT count(*)::int AS count
    FROM bookings
    WHERE scheduled_date=$1::date
      AND status IN ('scheduled','assigned','in_progress')
      AND abs(extract(epoch FROM ((scheduled_date + scheduled_time) - ($2::date + $3::time)))) < 3600
  `,[scheduled_date,scheduled_date,scheduled_time]);
  if(Number(staffConflict.rows[0]?.count||0)>=activeStaff)return res.status(409).json({error:'All CarCare staff are already booked around this time. Please choose an available slot.'});
  const countR=await q(`SELECT count(*)::int AS count FROM bookings WHERE customer_id=$1 AND status<>'cancelled' AND scheduled_date >= $2::date AND ($3::date IS NULL OR scheduled_date <= $3::date)`,[req.user.sub,sub.start_date,sub.end_date || null]);
  const used=Number(countR.rows[0].count||0), allowance=Number(sub.wash_credits||0);
  if(used>=allowance)return res.status(409).json({error:`Your ${sub.plan_name} plan has used all ${allowance} exterior wash credits. Please switch to a higher plan.`});
  const r=await q(`
    INSERT INTO bookings(customer_id,vehicle_id,apartment_id,parking_bay_id,service_type,scheduled_date,scheduled_time,status,customer_notes)
    VALUES($1,$2,$3,$4,$5,$6,$7,'scheduled',$8) RETURNING *
  `,[req.user.sub,vehicle_id,apartment_id || null,parking_bay_id || vr.rows[0].parking_bay_id || null,service_type,scheduled_date,scheduled_time,customer_notes || null]);
  res.status(201).json(r.rows[0]);
}));

app.patch('/api/bookings/:id', auth, asyncRoute(async(req,res)=>{
  const fields=['parking_bay_id','service_type','scheduled_date','scheduled_time','status','customer_notes','partner_notes','partner_id','before_photo_url','after_photo_url','started_at','completed_at'].filter(k=>Object.hasOwn(req.body,k));
  if(!fields.length)return res.status(400).json({error:'No fields to update'});
  const existing=(await q('SELECT * FROM bookings WHERE id=$1',[req.params.id])).rows[0];
  if(!existing)return res.status(404).json({error:'Booking not found'});
  if(req.user.role==='customer' && existing.customer_id!==req.user.sub)return res.status(404).json({error:'Booking not found or not permitted'});
  if(req.user.role==='partner' && existing.partner_id!==req.user.sub)return res.status(404).json({error:'Booking not found or not permitted'});

  if(req.user.role==='customer' && (Object.hasOwn(req.body,'scheduled_date') || Object.hasOwn(req.body,'scheduled_time') || Object.hasOwn(req.body,'vehicle_id'))){
    const newDate=req.body.scheduled_date || existing.scheduled_date;
    const newTime=req.body.scheduled_time || existing.scheduled_time;
    // Apply the same forward-only 4-hour rule when modifying a booking.
    const candidateTs = `($2::date + $3::time)`;
    const conflict=await q(`
      SELECT id, scheduled_date, scheduled_time
      FROM bookings
      WHERE customer_id=$1
        AND vehicle_id=$4
        AND status<>'cancelled'
        AND id<>$5
        AND (scheduled_date + scheduled_time) <= ${candidateTs}
        AND (scheduled_date + scheduled_time) + interval '4 hours' > ${candidateTs}
      ORDER BY scheduled_date DESC, scheduled_time DESC
      LIMIT 1
    `,[req.user.sub,newDate,newTime,req.body.vehicle_id || existing.vehicle_id,req.params.id]);
    if(conflict.rows.length){
      const b=conflict.rows[0];
      return res.status(409).json({error:`This vehicle already has a booking at ${String(b.scheduled_time).slice(0,5)} on ${String(b.scheduled_date).slice(0,10)}. The next booking for this vehicle must be at least 4 hours later.`});
    }
        const maxBookingDate = new Date();
    maxBookingDate.setHours(0,0,0,0);
    maxBookingDate.setDate(maxBookingDate.getDate()+15);
    const requestedDateObj = new Date(`${newDate}T00:00:00`);
    if(Number.isNaN(requestedDateObj.getTime()) || requestedDateObj > maxBookingDate || requestedDateObj < new Date(new Date().setHours(0,0,0,0)))return res.status(409).json({error:'Bookings can be made only within the next 15 days.'});
    const requestedHour=Number(String(newTime).slice(0,2));
    const requestedMinute=Number(String(newTime).slice(3,5));
    const requestedMinutes=requestedHour*60+requestedMinute;
    if(!Number.isFinite(requestedMinutes) || requestedMinutes<10*60 || requestedMinutes>=17*60)return res.status(409).json({error:'Bookings are available between 10:00 AM and 5:00 PM. Please choose an available slot.'});
const staffR=await q(`SELECT count(*)::int AS count FROM partners WHERE status='active'`);
    const activeStaff=Number(staffR.rows[0]?.count||0);
    if(activeStaff<=0)return res.status(409).json({error:'No CarCare staff are available for booking right now. Please choose another time.'});
    const staffConflict=await q(`
      SELECT count(*)::int AS count
      FROM bookings
      WHERE scheduled_date=$1::date
        AND status IN ('scheduled','assigned','in_progress')
        AND id<>$4
        AND abs(extract(epoch FROM ((scheduled_date + scheduled_time) - ($2::date + $3::time)))) < 3600
    `,[newDate,newDate,newTime,req.params.id]);
    if(Number(staffConflict.rows[0]?.count||0)>=activeStaff)return res.status(409).json({error:'All CarCare staff are already booked around this time. Please choose an available slot.'});
    const vehicleId=req.body.vehicle_id || existing.vehicle_id;
    const subR=await q(`SELECT s.*,p.name AS plan_name,p.wash_credits FROM subscriptions s JOIN service_plans p ON p.id=s.plan_id WHERE s.customer_id=$1 AND s.status='active' ORDER BY s.created_at DESC LIMIT 1`,[req.user.sub]);
    if(!subR.rows.length)return res.status(409).json({error:'Please activate a membership plan before modifying this booking'});
    const sub=subR.rows[0];
    const countR=await q(`SELECT count(*)::int AS count FROM bookings WHERE customer_id=$1 AND status<>'cancelled' AND scheduled_date >= $2::date AND ($3::date IS NULL OR scheduled_date <= $3::date)`,[req.user.sub,sub.start_date,sub.end_date || null]);
    const used=Number(countR.rows[0].count||0);
    if(used>Number(sub.wash_credits||0))return res.status(409).json({error:`Your ${sub.plan_name} plan does not have enough wash credits for this booking.`});
  }

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

app.post('/api/uploads/base64', auth, asyncRoute(async (req,res)=>{
  const {base64,mime,name} = req.body || {};
  if(!base64) return res.status(400).json({error:'base64 image data is required'});
  const clean=String(base64).replace(/^data:[^;]+;base64,/,'');
  if(clean.length > 8 * 1024 * 1024) return res.status(413).json({error:'Image is too large. Please choose a smaller photo.'});
  const ext=(String(name||'profile.jpg').split('.').pop()||'jpg').toLowerCase().replace(/[^a-z0-9]/g,'') || 'jpg';
  const filename=`profile-${req.user.sub}-${Date.now()}.${ext}`;
  const filePath=path.join(uploadDir,filename);
  fs.writeFileSync(filePath,Buffer.from(clean,'base64'));
  const pathUrl=`/uploads/${filename}`;
  res.status(201).json({filename,path:pathUrl,url:`${req.protocol}://${req.get('host')}${pathUrl}`});
}));

app.post('/api/uploads', auth, upload.single('file'), (req,res)=>{
  if(!req.file)return res.status(400).json({error:'file is required'});
  const pathUrl=`/uploads/${req.file.filename}`;
  res.status(201).json({filename:req.file.filename,original_name:req.file.originalname,path:pathUrl,url:`${req.protocol}://${req.get('host')}${pathUrl}`});
});
app.use('/uploads', express.static(uploadDir));

app.use((req,res)=>res.status(404).json({error:'Route not found',path:req.path}));
app.use((err,req,res,next)=>{
  console.error(err);
  res.status(500).json({error:'Internal server error',detail:process.env.NODE_ENV==='production' ? undefined : err.message});
});

app.listen(PORT,()=>console.log(`CarCareBay API listening on :${PORT}`));
