CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS users (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), phone TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('customer','partner','admin')), password_hash TEXT, active BOOLEAN NOT NULL DEFAULT TRUE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS apartments (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL, city TEXT NOT NULL DEFAULT 'Bengaluru',
 address TEXT, total_cars INT NOT NULL DEFAULT 0, revenue_share_pct NUMERIC(5,2) NOT NULL DEFAULT 10,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS parking_bays (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), apartment_id UUID NOT NULL REFERENCES apartments(id) ON DELETE CASCADE,
 tower TEXT, floor TEXT, bay_number TEXT, UNIQUE(apartment_id,tower,floor,bay_number)
);
CREATE TABLE IF NOT EXISTS vehicles (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), customer_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 make_model TEXT NOT NULL, plate TEXT UNIQUE NOT NULL, color TEXT, bay_id UUID REFERENCES parking_bays(id), created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS plans (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT UNIQUE NOT NULL, price_paise INT NOT NULL,
 included_exterior INT NOT NULL DEFAULT 0, included_interior INT NOT NULL DEFAULT 0, active BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE TABLE IF NOT EXISTS subscriptions (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), customer_id UUID NOT NULL REFERENCES users(id), plan_id UUID NOT NULL REFERENCES plans(id),
 status TEXT NOT NULL CHECK(status IN ('trialing','active','paused','cancelled','past_due')) DEFAULT 'active',
 razorpay_subscription_id TEXT, started_at TIMESTAMPTZ NOT NULL DEFAULT now(), renews_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS bookings (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), customer_id UUID NOT NULL REFERENCES users(id), vehicle_id UUID NOT NULL REFERENCES vehicles(id),
 apartment_id UUID NOT NULL REFERENCES apartments(id), bay_id UUID REFERENCES parking_bays(id), service TEXT NOT NULL,
 scheduled_at TIMESTAMPTZ NOT NULL, status TEXT NOT NULL CHECK(status IN ('scheduled','assigned','in_progress','completed','cancelled','no_show')) DEFAULT 'scheduled',
 partner_id UUID REFERENCES users(id), before_photo_url TEXT, after_photo_url TEXT, notes TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), completed_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS ratings (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), booking_id UUID UNIQUE NOT NULL REFERENCES bookings(id) ON DELETE CASCADE,
 customer_id UUID NOT NULL REFERENCES users(id), score INT NOT NULL CHECK(score BETWEEN 1 AND 5), comment TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS payments (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), customer_id UUID NOT NULL REFERENCES users(id), subscription_id UUID REFERENCES subscriptions(id),
 amount_paise INT NOT NULL, currency TEXT NOT NULL DEFAULT 'INR', status TEXT NOT NULL, razorpay_payment_id TEXT, razorpay_order_id TEXT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS notifications (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID NOT NULL REFERENCES users(id), title TEXT NOT NULL, body TEXT NOT NULL,
 read_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_bookings_partner_date ON bookings(partner_id,scheduled_at);
CREATE INDEX IF NOT EXISTS idx_bookings_customer_date ON bookings(customer_id,scheduled_at);
CREATE INDEX IF NOT EXISTS idx_vehicles_customer ON vehicles(customer_id);
INSERT INTO plans(name,price_paise,included_exterior,included_interior) VALUES
 ('Essential',39900,8,0),('Smart',59900,12,1),('Premium',79900,16,2)
ON CONFLICT(name) DO NOTHING;
