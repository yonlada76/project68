-- ต้องเปิดส่วนขยายสำหรับ gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 1) ROLES
CREATE TABLE IF NOT EXISTS roles (
  id   SERIAL PRIMARY KEY,
  name VARCHAR(20) UNIQUE NOT NULL  -- student, external, staff, admin
);

INSERT INTO roles(name) VALUES ('student'), ('external'), ('staff'), ('admin')
ON CONFLICT DO NOTHING;

-- 2) USERS
DROP TABLE IF EXISTS users CASCADE;
CREATE TABLE users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  role_id       INT NOT NULL REFERENCES roles(id) ON UPDATE CASCADE ON DELETE RESTRICT,
  member_type   VARCHAR(10) NOT NULL CHECK (member_type IN ('student','external','staff','admin')),
  email         VARCHAR(255) NOT NULL,
  student_id    VARCHAR(12) UNIQUE,
  citizen_id    VARCHAR(13) UNIQUE,
  full_name     VARCHAR(200) NOT NULL,
  faculty       VARCHAR(100),
  phone         VARCHAR(30),
  qr_code_value TEXT UNIQUE,
  created_at    timestamptz NOT NULL DEFAULT now(),

  -- กฎสอดคล้องระหว่างประเภทสมาชิกกับฟิลด์ ID
  CONSTRAINT chk_member_id_fields CHECK (
    (member_type = 'student'  AND student_id IS NOT NULL AND citizen_id IS NULL) OR
    (member_type = 'external' AND citizen_id IS NOT NULL AND student_id IS NULL) OR
    (member_type IN ('staff','admin') AND student_id IS NULL AND citizen_id IS NULL)
  )
);

-- เคส-อินซิสทีฟ ยูนีคอีเมล
CREATE UNIQUE INDEX uidx_users_email_lower ON users (LOWER(email));

-- ดัชนีช่วยค้นหา
CREATE INDEX idx_users_qr    ON users(qr_code_value);
CREATE INDEX idx_users_role  ON users(role_id);
CREATE INDEX idx_users_stdid ON users(student_id);
CREATE INDEX idx_users_cid   ON users(citizen_id);
-- ========== INVENTORY ==========
CREATE TABLE IF NOT EXISTS inventory (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  item_name  VARCHAR(150) NOT NULL,
  stock      INT NOT NULL DEFAULT 0 CHECK (stock >= 0),
  active     BOOLEAN NOT NULL DEFAULT TRUE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_inventory_active_name ON inventory(active, item_name);
CREATE INDEX IF NOT EXISTS idx_inventory_stock       ON inventory(stock);

-- ========== TRANSACTIONS (ยืม/คืน) ==========
CREATE TABLE IF NOT EXISTS transactions (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  inventory_id  UUID NOT NULL REFERENCES inventory(id) ON DELETE RESTRICT,
  qty           INT  NOT NULL CHECK (qty > 0),
  borrow_date   date NOT NULL,
  return_date   date,
  created_at    timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT chk_tx_dates CHECK (return_date IS NULL OR return_date >= borrow_date)
);

-- ไม่ให้มี “รายการค้าง” ซ้ำต่อคู่ (user, item)
CREATE UNIQUE INDEX IF NOT EXISTS uidx_tx_open_per_item
  ON transactions(user_id, inventory_id)
  WHERE return_date IS NULL;

CREATE INDEX IF NOT EXISTS idx_tx_user_open      ON transactions(user_id, return_date);
CREATE INDEX IF NOT EXISTS idx_tx_inventory      ON transactions(inventory_id);
CREATE INDEX IF NOT EXISTS idx_tx_borrowdate     ON transactions(borrow_date);

-- ========== NOTIFICATIONS ==========
CREATE TABLE IF NOT EXISTS notifications (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type        VARCHAR(50)  NOT NULL,   -- 'borrow','return','overdue_student','overdue_faculty'
  title       VARCHAR(200) NOT NULL,
  message     TEXT         NOT NULL,
  meta        JSONB,
  created_at  timestamptz  NOT NULL DEFAULT now(),
  read_at     timestamptz
);

CREATE INDEX IF NOT EXISTS idx_notif_user_time  ON notifications(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notif_unread     ON notifications(user_id) WHERE read_at IS NULL;

ALTER TABLE notifications
ADD COLUMN created_date date;

ALTER TABLE notifications
ALTER COLUMN created_date SET DEFAULT (CURRENT_DATE);


CREATE UNIQUE INDEX IF NOT EXISTS uq_notif_overdue_daily
ON notifications ( (meta->>'ref'), type, created_date )
WHERE type IN ('overdue_student','overdue_faculty','overdue_staff_2_6');

-- ========== FITNESS VISITS ==========
CREATE TABLE IF NOT EXISTS fitness_visits (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  visit_date  date NOT NULL,
  amount      INT  NOT NULL CHECK (amount >= 0),
  pay_method  TEXT NOT NULL CHECK (pay_method IN ('cash','qr')),
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_fitness_member ON fitness_visits(user_id);
CREATE INDEX IF NOT EXISTS idx_fitness_date   ON fitness_visits(visit_date);

-- ========== VIEW: ค้างคืน ==========
CREATE OR REPLACE VIEW overdue_2_6_days AS
SELECT
  t.id            AS tx_id,
  t.user_id,
  t.inventory_id,
  t.qty,
  t.borrow_date,
  (CURRENT_DATE - t.borrow_date) AS days_overdue,
  i.item_name
FROM transactions t
JOIN inventory i ON i.id = t.inventory_id
WHERE t.return_date IS NULL
  AND (CURRENT_DATE - t.borrow_date) BETWEEN 2 AND 6
ORDER BY t.borrow_date ASC;

CREATE OR REPLACE VIEW overdue_7_plus AS
SELECT
  t.id            AS tx_id,
  t.user_id,
  t.inventory_id,
  t.qty,
  t.borrow_date,
  (CURRENT_DATE - t.borrow_date) AS days_overdue,
  i.item_name
FROM transactions t
JOIN inventory i ON i.id = t.inventory_id
WHERE t.return_date IS NULL
  AND (CURRENT_DATE - t.borrow_date) >= 7
ORDER BY t.borrow_date ASC;

-- ========== FUNCTION: push_notification ==========
CREATE OR REPLACE FUNCTION push_notification(
  p_user UUID,
  p_type TEXT,
  p_title TEXT,
  p_msg TEXT,
  p_meta JSONB DEFAULT '{}'::jsonb
) RETURNS VOID AS $$
BEGIN
  INSERT INTO notifications(user_id, type, title, message, meta)
  VALUES (p_user, p_type, p_title, p_msg, p_meta);
END;
$$ LANGUAGE plpgsql;

-- ========== TRIGGER: จัดการสต็อกเมื่อยืม/คืน ==========
CREATE OR REPLACE FUNCTION adjust_stock_on_tx()
RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    -- ยืม -> ตัดสต็อก
    UPDATE inventory
       SET stock = stock - NEW.qty
     WHERE id = NEW.inventory_id;
    IF (SELECT stock FROM inventory WHERE id = NEW.inventory_id) < 0 THEN
      RAISE EXCEPTION 'Stock would go negative for inventory %', NEW.inventory_id;
    END IF;
    RETURN NEW;
  ELSIF TG_OP = 'UPDATE' THEN
    -- คืน -> เติมสต็อก (เมื่อ return_date ถูกตั้งค่า)
    IF OLD.return_date IS NULL AND NEW.return_date IS NOT NULL THEN
      UPDATE inventory
         SET stock = stock + NEW.qty
       WHERE id = NEW.inventory_id;
    END IF;
    RETURN NEW;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_adjust_stock_on_tx_ins ON transactions;
CREATE TRIGGER trg_adjust_stock_on_tx_ins
AFTER INSERT ON transactions
FOR EACH ROW EXECUTE FUNCTION adjust_stock_on_tx();

DROP TRIGGER IF EXISTS trg_adjust_stock_on_tx_upd ON transactions;
CREATE TRIGGER trg_adjust_stock_on_tx_upd
AFTER UPDATE OF return_date ON transactions
FOR EACH ROW EXECUTE FUNCTION adjust_stock_on_tx();




INSERT INTO users (id, role_id, member_type, email, full_name)
VALUES (gen_random_uuid(), (SELECT id FROM roles WHERE name='staff'), 'staff', 'staff@example.com', 'เจ้าหน้าที่');




-- สร้าง unique index/constraint สำหรับ "ห้ามซ้ำต่อ user,type,ref"
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes WHERE indexname = 'uq_notif_once'
  ) THEN
    CREATE UNIQUE INDEX uq_notif_once
      ON notifications (user_id, type, (meta->>'ref'));
  END IF;
END $$;


///////
กันซ้ำ
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_indexes
    WHERE schemaname = 'public'
      AND indexname = 'uidx_notif_user_type_ref'
  ) THEN
    EXECUTE
      'CREATE UNIQUE INDEX uidx_notif_user_type_ref
         ON notifications (user_id, type, (meta->>''ref''))';
  END IF;
END$$;


-- กันแจ้งซ้ำต่อ (user,type,meta.ref)
CREATE UNIQUE INDEX IF NOT EXISTS uniq_notif_user_type_ref
ON notifications (user_id, type, (meta->>'ref'))
WHERE (meta ? 'ref');


--ต้องแก้ SQL ที่ /history ให้ดึงฟิลด์ days_overdue มาด้วย เช่น:--
(CASE WHEN t.return_date IS NULL 
      THEN (CURRENT_DATE - t.borrow_date::date) 
      ELSE 0 END) AS days_overdue

--เพิ่มคอลัมน์ escalated_at ให้ตาราง transactions
ALTER TABLE transactions
  ADD COLUMN IF NOT EXISTS escalated_at timestamptz;

--สร้างตาราง user_holds (เก็บสถานะ “ระงับการยืม”)
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS user_holds (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reason     text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  cleared_at timestamptz NULL,
  cleared_by uuid NULL REFERENCES users(id)
);
-- index เร็วขึ้นสำหรับเช็ก hold ที่ยังไม่เคลียร์
CREATE INDEX IF NOT EXISTS ix_user_holds_active
  ON user_holds(user_id)
  WHERE cleared_at IS NULL;

-- 1) เพิ่มคอลัมน์ที่ใช้บอกว่าเคลียร์ hold แล้วหรือยัง
ALTER TABLE user_holds
  ADD COLUMN IF NOT EXISTS cleared_at timestamptz,
  ADD COLUMN IF NOT EXISTS cleared_by uuid REFERENCES users(id);

-- 2) สร้าง (หรือสร้างใหม่) index สำหรับเช็ก hold ที่ยังไม่ถูกเคลียร์
DROP INDEX IF EXISTS ix_user_holds_active;
CREATE INDEX ix_user_holds_active
  ON user_holds(user_id)
  WHERE cleared_at IS NULL;
