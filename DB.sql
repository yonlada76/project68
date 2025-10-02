-- =========================================
-- 0) Extensions (สำหรับ UUID/crypto)
-- =========================================
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =========================================
-- 1) ROLES (สิทธิ์ในระบบแอป)
-- =========================================
CREATE TABLE IF NOT EXISTS roles (
  id   SERIAL PRIMARY KEY,
  name VARCHAR(20) NOT NULL UNIQUE
);

INSERT INTO roles(name) VALUES ('student') ON CONFLICT (name) DO NOTHING;
INSERT INTO roles(name) VALUES ('external') ON CONFLICT (name) DO NOTHING;
INSERT INTO roles(name) VALUES ('staff') ON CONFLICT (name) DO NOTHING;
INSERT INTO roles(name) VALUES ('admin') ON CONFLICT (name) DO NOTHING;

-- =========================================
-- 2) USERS
-- =========================================
CREATE TABLE IF NOT EXISTS users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  role_id       INT  NOT NULL REFERENCES roles(id) ON UPDATE CASCADE ON DELETE RESTRICT,
  member_type   VARCHAR(10) NOT NULL,
  email         VARCHAR(255) NOT NULL,
  student_id    VARCHAR(12),
  citizen_id    VARCHAR(13),
  full_name     VARCHAR(200) NOT NULL,
  faculty       VARCHAR(100),
  phone         VARCHAR(30),
  qr_code_value TEXT,
  created_at    timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT users_member_type_check CHECK (member_type IN ('student','external','staff','admin')),
  CONSTRAINT chk_member_id_fields CHECK (
       (member_type='student'  AND student_id IS NOT NULL AND citizen_id IS NULL)
    OR (member_type='external' AND citizen_id IS NOT NULL AND student_id IS NULL)
    OR (member_type IN ('staff','admin')    AND student_id IS NULL AND citizen_id IS NULL)
  )
);

-- indexes
CREATE UNIQUE INDEX IF NOT EXISTS uidx_users_email_lower ON users (LOWER(email));
DO $$ BEGIN
  BEGIN ALTER TABLE users ADD CONSTRAINT users_student_id_key UNIQUE (student_id); EXCEPTION WHEN duplicate_table THEN END;
END $$;
DO $$ BEGIN
  BEGIN ALTER TABLE users ADD CONSTRAINT users_citizen_id_key UNIQUE (citizen_id); EXCEPTION WHEN duplicate_table THEN END;
END $$;
DO $$ BEGIN
  BEGIN ALTER TABLE users ADD CONSTRAINT users_qr_code_value_key UNIQUE (qr_code_value); EXCEPTION WHEN duplicate_table THEN END;
END $$;

CREATE INDEX IF NOT EXISTS idx_users_role    ON users(role_id);
CREATE INDEX IF NOT EXISTS idx_users_stdid   ON users(student_id);
CREATE INDEX IF NOT EXISTS idx_users_cid     ON users(citizen_id);
CREATE INDEX IF NOT EXISTS idx_users_qr      ON users(qr_code_value);

-- =========================================
-- 3) INVENTORY
-- =========================================
CREATE TABLE IF NOT EXISTS inventory (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  item_name  VARCHAR(150) NOT NULL,
  stock      INT NOT NULL DEFAULT 0,
  active     BOOLEAN NOT NULL DEFAULT TRUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT inventory_stock_check CHECK (stock >= 0)
);
CREATE INDEX IF NOT EXISTS idx_inventory_active_name ON inventory(active, item_name);
CREATE INDEX IF NOT EXISTS idx_inventory_stock       ON inventory(stock);

-- =========================================
-- 4) TRANSACTIONS (ยืม–คืน)
-- =========================================
CREATE TABLE IF NOT EXISTS transactions (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  inventory_id UUID NOT NULL REFERENCES inventory(id) ON DELETE RESTRICT,
  qty          INT  NOT NULL,
  borrow_date  DATE NOT NULL,
  return_date  DATE,
  created_at   timestamptz NOT NULL DEFAULT now(),
  escalated_at timestamptz,
  CONSTRAINT transactions_qty_check CHECK (qty > 0),
  CONSTRAINT chk_tx_dates CHECK (return_date IS NULL OR return_date >= borrow_date)
);

CREATE INDEX IF NOT EXISTS idx_tx_borrowdate ON transactions(borrow_date);
CREATE INDEX IF NOT EXISTS idx_tx_inventory  ON transactions(inventory_id);
CREATE INDEX IF NOT EXISTS idx_tx_user_open  ON transactions(user_id, return_date);
-- ห้ามมี “ค้างอุปกรณ์ชนิดเดิม” ซ้ำในคนเดียว
CREATE UNIQUE INDEX IF NOT EXISTS uidx_tx_open_per_item
  ON transactions(user_id, inventory_id)
  WHERE return_date IS NULL;

-- ===== ทริกเกอร์ปรับสต็อก (เวอร์ชันไม่หักซ้ำ) =====
-- แอปของคุณหัก/คืนสต็อกด้วยโค้ดอยู่แล้ว
-- ฟังก์ชันนี้ทำเป็น no-op เพื่อกัน “หักซ้ำ”
CREATE OR REPLACE FUNCTION adjust_stock_on_tx()
RETURNS trigger AS $$
BEGIN
  -- ไม่ปรับ stock ที่นี่ เพราะแอปทำแล้ว
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ติดตั้งทริกเกอร์ (ถ้ามีอยู่แล้วจะชี้มาหาเวอร์ชัน no-op นี้)
DROP TRIGGER IF EXISTS trg_adjust_stock_on_tx_ins ON transactions;
CREATE TRIGGER trg_adjust_stock_on_tx_ins
AFTER INSERT ON transactions
FOR EACH ROW EXECUTE FUNCTION adjust_stock_on_tx();

DROP TRIGGER IF EXISTS trg_adjust_stock_on_tx_upd ON transactions;
CREATE TRIGGER trg_adjust_stock_on_tx_upd
AFTER UPDATE OF return_date ON transactions
FOR EACH ROW EXECUTE FUNCTION adjust_stock_on_tx();

-- =========================================
-- 5) NOTIFICATIONS (In-App + กันซ้ำ)
-- =========================================
CREATE TABLE IF NOT EXISTS notifications (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type         VARCHAR(50)  NOT NULL,
  title        VARCHAR(200) NOT NULL,
  message      TEXT         NOT NULL,
  meta         JSONB,
  created_at   timestamptz NOT NULL DEFAULT now(),
  read_at      timestamptz,
  created_date DATE NOT NULL DEFAULT CURRENT_DATE
);

-- ฟังก์ชัน/ทริกเกอร์อัปเดต created_date
CREATE OR REPLACE FUNCTION set_created_date()
RETURNS trigger AS $$
BEGIN
  NEW.created_date := COALESCE(NEW.created_at::date, CURRENT_DATE);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_set_created_date ON notifications;
CREATE TRIGGER trg_set_created_date
BEFORE INSERT ON notifications
FOR EACH ROW EXECUTE FUNCTION set_created_date();

-- Indexes/Unique (อิงของจริงในฐานข้อมูลคุณ)
CREATE INDEX IF NOT EXISTS idx_notif_unread     ON notifications(user_id) WHERE read_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_notif_user_time  ON notifications(user_id, created_at DESC);

-- กันซ้ำ: ต่อ user,type,ref (ถ้ามี meta.ref)
DO $$ BEGIN
  BEGIN
    CREATE UNIQUE INDEX uq_notif_once_idx
      ON notifications(user_id, type, (meta->>'ref'))
      WHERE (meta->>'ref') IS NOT NULL;
  EXCEPTION WHEN duplicate_table THEN END;
END $$;

-- กันซ้ำแบบ “รายวัน” ต่อ ref/type
DO $$ BEGIN
  BEGIN
    CREATE UNIQUE INDEX uq_notif_daily
      ON notifications ((meta->>'ref'), type, created_date)
      WHERE type IN ('overdue_student','overdue_faculty','overdue_staff_2_6');
  EXCEPTION WHEN duplicate_table THEN END;
END $$;

-- บางระบบมีดัชนีซ้ำชื่ออื่นไว้แล้ว เผื่อไว้ (จะสร้างเฉพาะกรณีไม่มี)
DO $$ BEGIN
  BEGIN
    CREATE UNIQUE INDEX uniq_notif_user_type_ref
      ON notifications(user_id, type, (meta->>'ref'));
  EXCEPTION WHEN duplicate_table THEN END;
END $$;

-- =========================================
-- 6) FITNESS_VISITS
-- =========================================
CREATE TABLE IF NOT EXISTS fitness_visits (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  visit_date DATE NOT NULL,
  amount     INT  NOT NULL CHECK (amount >= 0),
  pay_method TEXT NOT NULL CHECK (pay_method IN ('cash','qr')),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_fitness_member ON fitness_visits(user_id);
CREATE INDEX IF NOT EXISTS idx_fitness_date   ON fitness_visits(visit_date);

-- =========================================
-- 7) USER_HOLDS (ระงับสิทธิ์ยืม)
-- =========================================
CREATE TABLE IF NOT EXISTS user_holds (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reason     TEXT NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  cleared_at timestamptz,
  cleared_by UUID REFERENCES users(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_user_holds_one_active
  ON user_holds(user_id) WHERE cleared_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_user_holds_active
  ON user_holds(user_id) WHERE cleared_at IS NULL;

-- =========================================
-- 8) Overdue VIEWs (cron ใช้)
-- =========================================
CREATE OR REPLACE VIEW overdue_2_6_days AS
SELECT
  t.id          AS tx_id,
  t.user_id,
  t.inventory_id,
  i.item_name,
  t.qty,
  (CURRENT_DATE - t.borrow_date::date) AS days_overdue
FROM transactions t
JOIN inventory i ON i.id = t.inventory_id
WHERE t.return_date IS NULL
  AND (CURRENT_DATE - t.borrow_date::date) BETWEEN 2 AND 6;

CREATE OR REPLACE VIEW overdue_7_plus AS
SELECT
  t.id          AS tx_id,
  t.user_id,
  t.inventory_id,
  i.item_name,
  t.qty,
  (CURRENT_DATE - t.borrow_date::date) AS days_overdue
FROM transactions t
JOIN inventory i ON i.id = t.inventory_id
WHERE t.return_date IS NULL
  AND (CURRENT_DATE - t.borrow_date::date) >= 7;

-- =========================================
-- 9) (ออปชัน) Seed เจ้าหน้าที่ทดสอบ 1 คน
--    เปลี่ยนอีเมลตามต้องการก่อนรัน
-- =========================================
DO $$
DECLARE
  staff_role_id INT;
  uid UUID := gen_random_uuid();
BEGIN
  SELECT id INTO staff_role_id FROM roles WHERE name='staff' LIMIT 1;
  IF NOT EXISTS (SELECT 1 FROM users WHERE LOWER(email) = LOWER('staff@example.com')) THEN
    INSERT INTO users(id, role_id, member_type, email, full_name)
    VALUES (uid, staff_role_id, 'staff', 'staff@example.com', 'Test Staff');
  END IF;
END $$;

-- =========================================
-- 10) ชุดคิวรีตรวจสุขภาพ (comment ไว้ให้ copy ไปใช้)
-- =========================================
-- -- Active holds
-- SELECT uh.id, u.full_name, u.email, uh.reason, uh.created_at
-- FROM user_holds uh JOIN users u ON u.id=uh.user_id
-- WHERE uh.cleared_at IS NULL ORDER BY uh.created_at DESC;
--
-- -- ปลด hold ทั้งหมดของผู้ใช้ (แทน <USER_UUID>)
-- -- UPDATE user_holds SET cleared_at = now(), cleared_by = NULL
-- -- WHERE user_id = '<USER_UUID>'::uuid AND cleared_at IS NULL;
--
-- -- รายการค้างคืนของผู้ใช้
-- -- SELECT t.id, i.item_name, t.qty, t.borrow_date, t.escalated_at
-- -- FROM transactions t JOIN inventory i ON i.id=t.inventory_id
-- -- WHERE t.user_id='<USER_UUID>'::uuid AND t.return_date IS NULL
-- -- ORDER BY t.borrow_date DESC;
--
-- -- แจ้งเตือนล่าสุดของผู้ใช้
-- -- SELECT id, type, title, (meta->>'ref') AS ref, created_at, read_at
-- -- FROM notifications WHERE user_id='<USER_UUID>'::uuid
-- -- ORDER BY created_at DESC LIMIT 50;
--
-- -- รายการค้าง 2–6 วัน และ 7+ วัน ตอนนี้
-- -- SELECT * FROM overdue_2_6_days ORDER BY days_overdue DESC;
-- -- SELECT * FROM overdue_7_plus   ORDER BY days_overdue DESC;
