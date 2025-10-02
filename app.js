// app.js (ESM) — aligned to schema: users.id UUID, transactions.user_id UUID, inventory.id UUID, fitness_visits.user_id UUID
// ===== 1) imports =====
import express from 'express';
import path from 'path';
import pkg from 'pg';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';
import QRCode from 'qrcode';
import session from 'express-session';
import nodemailer from 'nodemailer';

const { Pool } = pkg;

// ===== 2) PATH/APP BASICS =====
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const app  = express();
const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;

// ===== 3) DB: create pool FIRST =====
const pool = new Pool({
  user: process.env.PGUSER        || 'postgres',
  host: process.env.PGHOST        || 'localhost',
  database: process.env.PGDATABASE|| 'projectdb',
  password: process.env.PGPASSWORD|| '1234',
  port: Number(process.env.PGPORT || 5432),
});

// ===== DEBUG WRAPPER: log SQL เมื่อ error =====
const _pgQuery = pool.query.bind(pool);
pool.query = async (text, params=[]) => {
  try { return await _pgQuery(text, params); }
  catch (e) {
    console.error('\n[PG ERROR]', e.code, e.message);
    console.error('SQL  :\n' + text);
    console.error('PARAM:', params);
    throw e;
  }
};

// === DB bootstrap: created_date + triggers + unique indexes ===
async function initDb() {
  // ให้ใช้ gen_random_uuid() ได้
  await pool.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto`);

  // 1) notifications.created_date + trigger
  await pool.query(`ALTER TABLE notifications ADD COLUMN IF NOT EXISTS created_date date`);
  await pool.query(`
    CREATE OR REPLACE FUNCTION set_created_date()
    RETURNS trigger AS $$
    BEGIN
      NEW.created_date := COALESCE(NEW.created_at::date, CURRENT_DATE);
      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;
  `);
  await pool.query(`DROP TRIGGER IF EXISTS trg_set_created_date ON notifications`);
  await pool.query(`
    CREATE TRIGGER trg_set_created_date
    BEFORE INSERT ON notifications
    FOR EACH ROW
    EXECUTE FUNCTION set_created_date()
  `);
  await pool.query(`UPDATE notifications SET created_date = created_at::date WHERE created_date IS NULL`);

  // 2) กันส่งซ้ำ (รายวัน) ต่อ ref/type
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS uq_notif_daily
      ON notifications ((meta->>'ref'), type, created_date)
      WHERE type IN ('overdue_student','overdue_faculty','overdue_staff_2_6')
  `);

  // 3) กันส่งซ้ำต่อรายการ (แจ้ง staff) : user_id + type + meta.ref
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS uq_notif_once_idx
      ON notifications (user_id, type, (meta->>'ref'))
      WHERE (meta->>'ref') IS NOT NULL
  `);

  // 4) ธง escalated_at ใน transactions (ส่งถึงคณะแล้ว)
  await pool.query(`ALTER TABLE transactions ADD COLUMN IF NOT EXISTS escalated_at timestamptz`);

  // 5) ตารางระงับสิทธิ์การยืม (active = cleared_at IS NULL)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_holds (
      id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reason      text NOT NULL,
      created_at  timestamptz NOT NULL DEFAULT now(),
      cleared_at  timestamptz
    )
  `);

  // ดัชนีสำหรับ active holds (ใช้ cleared_at เท่านั้น!)
  await pool.query(`
    CREATE INDEX IF NOT EXISTS ix_user_holds_active
      ON user_holds(user_id)
      WHERE cleared_at IS NULL
  `);

  // มีได้แค่ 1 active hold ต่อคน
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS uq_user_holds_one_active
      ON user_holds(user_id)
      WHERE cleared_at IS NULL
  `);
}

/* =========================
 * 3) EMAIL
 * ========================= */
const MAIL_FROM = process.env.MAIL_FROM || 'noreply@example.com';
const STAFF_ALERT_EMAIL = process.env.STAFF_ALERT_EMAIL || 'staff@example.com';

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: Number(process.env.SMTP_PORT || 465),
  secure: true,
  auth: {
    user: process.env.SMTP_USER || 'your@gmail.com',
    pass: process.env.SMTP_PASS || 'app-password-here'
  }
});

async function sendMail(to, subject, html) {
  try { await transporter.sendMail({ from: MAIL_FROM, to, subject, html }); }
  catch (e) { console.warn('sendMail error:', e?.message || e); }
}

/* =========================
 * 4) HELPERS
 * ========================= */
// normalize code (qr/url/student_id/citizen_id/uuid)
function normalizeCode(raw) {
  if (!raw) return '';
  let s = String(raw).trim();
  try { s = decodeURIComponent(s); } catch {}
  if (/^https?:\/\//i.test(s)) {
    try {
      const u = new URL(s);
      const m = u.searchParams.get('member');
      if (m) return m.trim();
      const last = u.pathname.split('/').filter(Boolean).pop();
      if (last) return last.trim();
    } catch {}
  }
  s = s.replace(/\s+/g,'').replace(/-/g,'');
  const m13 = s.match(/\b\d{13}\b/); if (m13) return m13[0];
  const m12 = s.match(/\b\d{12}\b/); if (m12) return m12[0];
  return s;
}

const isUUID = (s) => /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(s));

// ค้นสมาชิกจาก uuid / qr / student_id / citizen_id
async function findMemberByAny(raw) {
  if (!raw) return null;
  let code = normalizeCode(raw);
  const sql = `
  SELECT id, full_name, member_type, email, student_id, citizen_id, qr_code_value, faculty
    FROM users
   WHERE $1::text = id::text
      OR $1::text = COALESCE(qr_code_value,'')
      OR $1::text = COALESCE(student_id,'')
      OR $1::text = COALESCE(citizen_id,'')
   LIMIT 1
`;
  const r = await pool.query(sql, [code]);
  return r.rowCount ? r.rows[0] : null;
}

// ดึง user จาก id หรือ code
async function getUserById(idOrCode) {
  const r = await pool.query(
    `SELECT id, email, full_name, faculty, member_type, student_id, citizen_id, qr_code_value
       FROM users
      WHERE id::text = $1::text
   OR $1::text = COALESCE(student_id,'')
   OR $1::text = COALESCE(citizen_id,'')
   OR $1::text = COALESCE(qr_code_value,'')
      LIMIT 1`,
    [String(idOrCode)]
  );
  return r.rowCount ? r.rows[0] : null;
}

// in-app notification
// in-app notification (ปรับให้ไม่ล้มถ้าชน unique index)
async function pushNotif(userIdOrCode, type, title, message, meta = null) {
  let uid = null;
  if (isUUID(userIdOrCode)) uid = userIdOrCode;
  else {
    const u = await getUserById(userIdOrCode);
    uid = u?.id || null;
  }
  if (!uid) { console.warn('pushNotif: cannot resolve', userIdOrCode); return; }

  await pool.query(
    `INSERT INTO notifications (user_id, type, title, message, meta)
     VALUES ($1::uuid, $2, $3, $4, $5::jsonb)
     ON CONFLICT DO NOTHING`,
    [uid, type, title, message, meta ? JSON.stringify(meta) : null]
  );
}

// notify user (in-app + email)
async function notifyUser({ userIdOrCode, type, title, message, meta, emailSubject, emailHtml }) {
  const u = await getUserById(userIdOrCode);
  if (!u) return;
  try { await pushNotif(u.id, type, title, message, meta); }
  catch (e) { console.warn('notifyUser in-app error', e?.message || e); }
  if (u.email && emailSubject) {
    await sendMail(u.email, emailSubject, emailHtml || `<p>${message}</p>`);
  }
}

// ตรวจว่าบัญชีถูกระงับสิทธิ์ยืมหรือไม่ (มี hold ที่ยังไม่ปิด)
async function hasActiveHold(userId) {
  const r = await pool.query(
    `SELECT 1 FROM user_holds WHERE user_id = $1::uuid AND cleared_at IS NULL LIMIT 1`,
    [userId]
  );
  return r.rowCount > 0;
}
// --- เคลียร์ระงับสิทธิ์ทั้งหมดของผู้ใช้ (ถ้ามี) ---
async function clearActiveHolds(userId, note='') {
  const r = await pool.query(
    `UPDATE user_holds
        SET cleared_at = now(),
            reason = COALESCE(reason,'') ||
                     CASE WHEN $2::text <> '' THEN ' | cleared: '||$2 ELSE '' END
      WHERE user_id = $1::uuid
        AND cleared_at IS NULL
      RETURNING id`,
    [userId, note]
  );
  return r.rowCount > 0; // true ถ้ามีการปลดจริง
}

// --- ยังมีรายการยืมที่ค้าง (return_date IS NULL) อยู่ไหม ---
async function hasOpenTransactions(userId) {
  const r = await pool.query(
    `SELECT 1
       FROM transactions
      WHERE user_id = $1::uuid
        AND return_date IS NULL
      LIMIT 1`,
    [userId]
  );
  return r.rowCount > 0;
}

// กันแจ้งซ้ำต่อรายการยืม (meta.ref) สำหรับแจ้งเจ้าหน้าที่
async function pushNotifOnce(userId, type, title, message, meta = null) {
  if (!userId) return;
  const metaJson = meta ? JSON.stringify(meta) : null;

  try {
    await pool.query(
      `INSERT INTO notifications (user_id, type, title, message, meta)
       VALUES ($1::uuid, $2, $3, $4, $5::jsonb)`,
      [userId, type, title, message, metaJson]
    );
  } catch (e) {
    // ถ้าชน unique index (มีแจ้งรายการนี้ไปแล้ว) ให้เงียบ ๆ ผ่าน
    if (e?.code === '23505') return;
    throw e;
  }
}

// notify all staff (in-app + email) — กันแจ้งซ้ำด้วย pushNotifOnce
async function notifyStaff({ type, title, message, meta, emailSubject, emailHtml }) {
  try {
    const staffRows = (await pool.query(
      `SELECT u.id, u.email
         FROM users u
         JOIN roles r ON r.id = u.role_id
        WHERE r.name IN ('staff','admin')`
    )).rows;

    for (const s of staffRows) {
      await pushNotifOnce(s.id, type, title, message, meta); // กันซ้ำด้วย meta.ref
      if (s.email && emailSubject) {
        await sendMail(s.email, emailSubject, emailHtml || `<p>${message}</p>`);
      }
    }

    // กล่องอีเมลรวมสำหรับเวร/หัวหน้า (ถ้าตั้งค่าไว้)
    if (STAFF_ALERT_EMAIL && emailSubject) {
      await sendMail(STAFF_ALERT_EMAIL, emailSubject, emailHtml || `<p>${message}</p>`);
    }
  } catch (e) {
    console.warn('notifyStaff error', e?.message || e);
  }
}

// ===== ปรับฟังก์ชัน getHistoryData =====
async function getHistoryData({ userId = null, from = null, to = null }) {
  // Borrow / Return
  const wT = [], pT = [];
  if (userId) { pT.push(userId); wT.push(`t.user_id = $${pT.length}::uuid`); }
  if (from)   { pT.push(from);   wT.push(`t.borrow_date >= $${pT.length}::date`); }
  if (to)     { pT.push(to);     wT.push(`t.borrow_date <= $${pT.length}::date`); }

  const sqlBorrow = `
    SELECT
      t.id,
      u.full_name, u.member_type, u.student_id, u.citizen_id,
      i.item_name,
      t.qty, t.borrow_date, t.return_date,
      t.escalated_at           -- << เพิ่มบรรทัดนี้
    FROM transactions t
    LEFT JOIN users u     ON u.id = t.user_id
    LEFT JOIN inventory i ON i.id = t.inventory_id
    ${wT.length ? 'WHERE ' + wT.join(' AND ') : ''}
    ORDER BY t.borrow_date DESC, t.created_at DESC NULLS LAST
  `;
  const borrowRows = (await pool.query(sqlBorrow, pT)).rows;

  // Fitness (เดิม)
  const wF = [], pF = [];
  if (userId) { pF.push(userId); wF.push(`f.user_id = $${pF.length}::uuid`); }
  if (from)   { pF.push(from);   wF.push(`f.visit_date >= $${pF.length}::date`); }
  if (to)     { pF.push(to);     wF.push(`f.visit_date <= $${pF.length}::date`); }

  const sqlFit = `
    SELECT
      f.id, u.full_name, u.member_type, u.student_id, u.citizen_id,
      f.visit_date, f.amount, f.pay_method
    FROM fitness_visits f
    LEFT JOIN users u ON u.id = f.user_id
    ${wF.length ? 'WHERE ' + wF.join(' AND ') : ''}
    ORDER BY f.visit_date DESC, f.created_at DESC
  `;
  const fitnessRows = (await pool.query(sqlFit, pF)).rows;

  return { borrowRows, fitnessRows };
}

/* =========================
 * 5) APP MIDDLEWARES
 * ========================= */
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESS_SECRET || 'CHANGE_ME_SECRET',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000*60*60*24*7 } // 7 วัน
}));

/* =========================
 * 6) AUTH MIDDLEWARES
 * ========================= */
function isStaff(req, res, next) {
  const u = req.session?.user;
  if (u && (u.role === 'staff' || u.type === 'staff' || u.member_type === 'staff')) return next();
  return res.redirect('/staff-login');
  
}
function requireMember(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}
function redirectIfLoggedIn(req, res, next) {
  if (req.session.user) {
    const type = req.session.user.type;
    return res.redirect(type === 'student' ? '/student-home' : '/external-home');
  }
  next();
}

/* =========================
 * 7) STAFF LOGIN (DEMO)
 * ========================= */
// แทนที่ handler เดิมทั้งบล็อก
app.get('/staff-login', (req, res) => res.render('staff-login', { error: null }));

app.post('/staff-login', async (req, res) => {
  const { email } = req.body || {};
  const sql = `
    SELECT u.id, u.full_name, r.name AS role
    FROM users u
    JOIN roles r ON r.id = u.role_id
    WHERE LOWER(u.email) = LOWER($1) AND r.name IN ('staff','admin')
    LIMIT 1
  `;
  const r = await pool.query(sql, [email]);
  if (!r.rowCount) return res.render('staff-login', { error: 'ไม่มีสิทธิ์หรืออีเมลไม่ถูกต้อง' });

  const row = r.rows[0];
  req.session.user   = { id: row.id, name: row.full_name, role: row.role };
  req.session.userId = row.id;                    // สำคัญ: ให้ /api/notifications หาเจอ
  return res.redirect('/staff-home');
});

/* =========================
 * 8) BASIC PAGES
 * ========================= */
app.get('/', redirectIfLoggedIn, (req, res) => res.render('index'));
app.get('/register/student',  redirectIfLoggedIn, (req, res) => res.render('register-student'));
app.get('/register/external', redirectIfLoggedIn, (req, res) => res.render('register-external'));
app.get('/inventory', isStaff, (req, res) => res.redirect('/staff/inventory'));
app.get('/staff-home', isStaff, async (req, res) => {
  const inv = (await pool.query(`SELECT id,item_name,stock,active FROM inventory ORDER BY item_name`)).rows;
  res.render('staff-home', { user: req.session.user, inventory: inv });
});

/* =========================
 * 9) Notifications API
 * ========================= */
app.get('/api/notifications', async (req, res) => {
  const userId = req.session?.userId || req.session?.user?.id;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });

  const limit = Math.min(parseInt(req.query.limit || '20', 10), 100);
  const since = req.query.since ? new Date(req.query.since) : null;

  try {
    let rows;
    if (since && !isNaN(since)) {
  const r = await pool.query(
    `SELECT id, type, title, message, meta, created_at, read_at
       FROM notifications
      WHERE user_id = $1::uuid
        AND created_at >= ($2::timestamptz - interval '5 seconds')
      ORDER BY created_at DESC
      LIMIT $3::int`,
    [userId, since.toISOString(), limit]
  );
  rows = r.rows;
} else {
  const r = await pool.query(
    `SELECT id, type, title, message, meta, created_at, read_at
       FROM notifications
      WHERE user_id = $1::uuid
      ORDER BY created_at DESC
      LIMIT $2::int`,
    [userId, limit]
  );
  rows = r.rows;
}
    // ให้ client ใช้ now จากเซิร์ฟเวอร์เสมอ เพื่อลด clock drift
    res.json({ items: rows, now: new Date().toISOString() });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/notifications/mark-read', async (req, res) => {
  const userId = req.session?.userId || req.session?.user?.id;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const ids = Array.isArray(req.body?.ids) ? req.body.ids : [];
  if (ids.length === 0) return res.json({ ok: true });

  try {
    await pool.query(
      `UPDATE notifications
          SET read_at = now()
        WHERE user_id = $1::uuid
          AND id = ANY($2::uuid[])
          AND read_at IS NULL`,
      [userId, ids]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/notifications/overdue/student', isStaff, async (req, res) => {
  try {
    const { tx_id } = req.body;

    const q = await pool.query(`
      SELECT t.id, t.user_id, t.borrow_date, t.return_date, t.qty,
             i.item_name,
             (CURRENT_DATE - t.borrow_date::date) AS days_overdue
      FROM transactions t
      JOIN inventory i ON i.id = t.inventory_id
      WHERE t.id::text = $1::text
      LIMIT 1
    `, [tx_id]);

    if (!q.rowCount)   return res.status(404).json({ error: 'not found' });
    const r = q.rows[0];
    if (r.return_date) return res.status(400).json({ error: 'already returned' });

    const d = Number(r.days_overdue || 0);
    if (d < 2)         return res.status(400).json({ error: 'not overdue enough' });

    const msg = `รายการยืม ${r.item_name} เกินกำหนดมาแล้ว ${d} วัน กรุณานำมาคืน`;
      
    // พยายาม INSERT ก่อน
    try {
      await pool.query(`
        INSERT INTO notifications (user_id, type, title, message, meta)
        VALUES (
          $1::uuid,
          'overdue_student',
          'เกินกำหนดต้องคืนอุปกรณ์',
          $2::text,
          jsonb_build_object(
            'ref', $3::text,
            'days_overdue', $4::int,
            'item', $5::text,
            'qty', $6::int
          )
        )
      `, [r.user_id, msg, r.id, d, r.item_name, r.qty]);

      return res.json({ ok: true, status: 'inserted' });
    } catch (e) {
      // ถ้ามีอยู่แล้ว (unique index รายวันชน) → อัปเดตให้กลายเป็น "ใหม่ตอนนี้" แทน
      if (e?.code === '23505') {
        await pool.query(`
          UPDATE notifications
             SET created_at = now(),       -- ให้ลำดับ/ toast เป็นรายการใหม่
                 read_at   = NULL,         -- รีเซ็ตให้ยังไม่อ่าน
                 message   = $2::text
           WHERE user_id = $1::uuid
             AND type    = 'overdue_student'
             AND (meta->>'ref') = $3::text
             AND created_date = CURRENT_DATE
        `, [r.user_id, msg, r.id]);

        return res.json({ ok: true, status: 'updated' });
      }
      throw e;
    }
  } catch (e) {
    console.error('POST /notifications/overdue/student error:', e);
    return res.status(500).json({ error: 'server error' });
  }
});

/* =========================
 * 10) BORROW FLOW
 * ========================= */
app.get('/borrow', isStaff, async (req, res) => {
  try {
    const success = (req.query.success || '').trim();
    const tx      = (req.query.tx || '').trim();

    const raw = (req.query.member || '').trim();
    if (!raw) return res.redirect('/staff-home');

    const m = await findMemberByAny(raw);
    if (!m) {
      return res.render('borrow', {
        member: null, loans: [], inventory: [], message: 'ไม่พบข้อมูลสมาชิก',
        success, tx
      });
    }

    const loans = (await pool.query(
      `SELECT i.item_name AS name, t.qty, t.borrow_date
         FROM transactions t
         JOIN inventory i ON i.id = t.inventory_id
        WHERE t.user_id = $1::uuid
          AND t.return_date IS NULL
        ORDER BY t.borrow_date DESC`,
      [m.id]
    )).rows;

    const inventory = (await pool.query(
      `SELECT id, item_name AS name, stock
         FROM inventory
        WHERE active = TRUE AND stock > 0
        ORDER BY item_name ASC`
    )).rows;

    return res.render('borrow', {
      member: m, loans, inventory, message: null, success, tx
    });
  } catch (e) {
    console.error('GET /borrow error:', e);
    return res.render('borrow', {
      member: null, loans: [], inventory: [], message: 'เกิดข้อผิดพลาดในการโหลดหน้า',
      success: '', tx: ''
    });
  }
});

// ยืมอุปกรณ์ (มีเช็ก hold)
app.post('/borrow/submit', isStaff, async (req, res) => {
  try {
    const user_id      = (req.body.member_id || '').trim();     // uuid ของผู้ใช้
    const inventory_id = (req.body.inventory_id || '').trim();  // uuid ของอุปกรณ์
    const qty          = parseInt(req.body.qty, 10);
    const borrow_date  = (req.body.borrow_date || '').trim();

    // ตรวจความถูกต้องของข้อมูลที่ส่งมา
    if (!user_id || !inventory_id || !Number.isInteger(qty) || qty <= 0 || !borrow_date) {
      return res.status(400).send('ข้อมูลไม่ครบหรือไม่ถูกต้อง');
    }

    // ถ้ามี hold ห้ามยืม
if (await hasActiveHold(user_id)) {
  return res.status(403).send('บัญชีนี้ถูกระงับการยืมชั่วคราว (ส่งเรื่องถึงคณะ/ค้างคืนเกินกำหนด)');
}


    // เช็กสต็อกอุปกรณ์
    const invRes = await pool.query(
      `SELECT id, item_name, stock FROM inventory WHERE id = $1::uuid LIMIT 1`,
      [inventory_id]
    );
    if (!invRes.rowCount) return res.status(404).send('ไม่พบอุปกรณ์');
    const inv = invRes.rows[0];
    if (Number(inv.stock) < qty) {
      return res.status(400).send(`สต็อกไม่พอ (คงเหลือ ${inv.stock})`);
    }

    // ทำธุรกรรมยืม + หักสต็อก
    const client = await pool.connect();
    const txId = randomUUID();

    try {
      await client.query('BEGIN');

      await client.query(
        `INSERT INTO transactions (id, user_id, inventory_id, qty, borrow_date)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5::date)`,
        [txId, user_id, inventory_id, qty, borrow_date]
      );

      await client.query(
        `UPDATE inventory SET stock = stock - $1 WHERE id = $2::uuid`,
        [qty, inventory_id]
      );

      await client.query('COMMIT');
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch {}
      client.release();
      console.error('TX borrow error:', e);
      return res.status(500).send('บันทึกไม่สำเร็จ');
    }
    client.release();

    // แจ้งนักศึกษา + อีเมล
    const msg = `คุณได้ยืม ${inv.item_name} จำนวน ${qty} ชิ้น วันที่ ${borrow_date}`;
    await notifyUser({
      userIdOrCode: user_id,
      type: 'borrow_created',
      title: 'ยืนยันการยืมอุปกรณ์',
      message: msg,
      meta: { ref: txId, goto: `/history#tx=${txId}` },
      emailSubject: 'ยืนยันการยืมอุปกรณ์',
      emailHtml: `<p>${msg}</p><p>รหัสรายการ: ${txId}</p>`
    });

    return res.redirect('/staff-home');
  } catch (e) {
    console.error('POST /borrow/submit error:', e);
    return res.status(500).send('server error');
  }
});


/* =========================
 * 11) RETURN / FITNESS
 * ========================= */
app.get('/return', isStaff, async (req, res) => {
  const code = (req.query.member || '').trim();
  if (!code) return res.render('return', { step:'scan', member:'', borrows:[] });

  const member = await findMemberByAny(code);
  if (!member) return res.render('return', { step:'scan', member:'', borrows:[], error:'ไม่พบสมาชิก' });

  const r = await pool.query(
    `SELECT t.id AS tx_id, i.item_name, t.qty, t.borrow_date
       FROM transactions t
       JOIN inventory i ON i.id=t.inventory_id
      WHERE t.user_id = $1::uuid
        AND t.return_date IS NULL
      ORDER BY t.borrow_date DESC`,
    [member.id]
  );

  res.render('return', { step:'list', member, borrows:r.rows });
});

// ยืมอุปกรณ์ (มีเช็ก hold + รองรับเพิ่มจำนวนในแถวเดิม)
app.post('/borrow/submit', isStaff, async (req, res) => {
  try {
    const user_id      = (req.body.member_id || '').trim();     // UUID ผู้ใช้
    const inventory_id = (req.body.inventory_id || '').trim();  // UUID อุปกรณ์
    const qtyReq       = parseInt(req.body.qty, 10);             // จำนวนที่ต้องการยืม "เพิ่ม"
    const borrow_date  = (req.body.borrow_date || '').trim();    // YYYY-MM-DD

    // ตรวจอินพุต
    if (!user_id || !inventory_id || !Number.isInteger(qtyReq) || qtyReq <= 0 || !borrow_date) {
      return res.status(400).send('ข้อมูลไม่ครบหรือไม่ถูกต้อง');
    }

    // ถูกระงับสิทธิ์อยู่หรือไม่
    if (await hasActiveHold(user_id)) {
      return res.status(403).send('บัญชีนี้ถูกระงับการยืมชั่วคราว (ส่งเรื่องถึงคณะ/ค้างคืนเกินกำหนด)');
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // 1) ล็อกอุปกรณ์ไว้ก่อน เพื่อตรวจสต็อก
      const invRes = await client.query(
        `SELECT id, item_name, stock
           FROM inventory
          WHERE id = $1::uuid
          FOR UPDATE`,
        [inventory_id]
      );
      if (!invRes.rowCount) {
        await client.query('ROLLBACK'); client.release();
        return res.status(404).send('ไม่พบอุปกรณ์');
      }
      const inv = invRes.rows[0];

      // 2) มีรายการค้างของ user+item นี้อยู่ไหม (ล็อกแถว)
      const openRes = await client.query(
        `SELECT id, qty
           FROM transactions
          WHERE user_id = $1::uuid
            AND inventory_id = $2::uuid
            AND return_date IS NULL
          FOR UPDATE`,
        [user_id, inventory_id]
      );

      if (openRes.rowCount) {
        // ----- กรณีมีแถวค้างอยู่: เพิ่ม qty เข้าแถวเดิม -----
        const tx = openRes.rows[0];

        // เช็กสต็อกพอสำหรับ "qtyReq ที่เพิ่ม" ไหม
        if (Number(inv.stock) < qtyReq) {
          await client.query('ROLLBACK'); client.release();
          return res.status(400).send(`สต็อกไม่พอ (คงเหลือ ${inv.stock})`);
        }

        // เพิ่มจำนวนในแถวค้าง + หักสต็อกตามส่วนเพิ่ม
        await client.query(
          `UPDATE transactions
              SET qty = qty + $1
            WHERE id = $2::uuid`,
          [qtyReq, tx.id]
        );
        await client.query(
          `UPDATE inventory
              SET stock = stock - $1
            WHERE id = $2::uuid`,
          [qtyReq, inventory_id]
        );

        await client.query('COMMIT');
        client.release();

        // แจ้งเตือนผู้ใช้ (ข้อความระบุว่าเพิ่มจำนวนในรายการเดิม)
        const msg = `เพิ่มจำนวนการยืม ${inv.item_name} อีก ${qtyReq} ชิ้น (รวมอยู่ในรายการค้างเดิม) วันที่ ${borrow_date}`;
        await notifyUser({
          userIdOrCode: user_id,
          type: 'borrow_created',
          title: 'ปรับปรุงรายการยืม',
          message: msg,
          meta: { ref: tx.id, goto: `/history#tx=${tx.id}` },
          emailSubject: 'ปรับปรุงรายการยืมอุปกรณ์',
          emailHtml: `<p>${msg}</p><p>รหัสรายการ: ${tx.id}</p>`
        });

        return res.redirect('/staff-home');

      } else {
        // ----- กรณีไม่มีแถวค้าง: สร้างแถวใหม่ -----
        // เช็กสต็อกพอกับ qtyReq หรือไม่ (แม้มี trigger ก็ควรเช็กก่อน)
        if (Number(inv.stock) < qtyReq) {
          await client.query('ROLLBACK'); client.release();
          return res.status(400).send(`สต็อกไม่พอ (คงเหลือ ${inv.stock})`);
        }

        const txId = randomUUID();

        // INSERT แถวใหม่ — ไม่ต้องลด stock เอง ปล่อยให้ trigger หลัง INSERT จัดการ
        await client.query(
          `INSERT INTO transactions (id, user_id, inventory_id, qty, borrow_date)
           VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5::date)`,
          [txId, user_id, inventory_id, qtyReq, borrow_date]
        );

        await client.query('COMMIT');
        client.release();

        // แจ้งเตือนผู้ใช้
        const msg = `คุณได้ยืม ${inv.item_name} จำนวน ${qtyReq} ชิ้น วันที่ ${borrow_date}`;
        await notifyUser({
          userIdOrCode: user_id,
          type: 'borrow_created',
          title: 'ยืนยันการยืมอุปกรณ์',
          message: msg,
          meta: { ref: txId, goto: `/history#tx=${txId}` },
          emailSubject: 'ยืนยันการยืมอุปกรณ์',
          emailHtml: `<p>${msg}</p><p>รหัสรายการ: ${txId}</p>`
        });

        return res.redirect('/staff-home');
      }
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch {}
      client.release();

      // ถ้าพลาดด้วยเหตุผลอื่นให้บอกแบบอ่านง่าย
      console.error('TX borrow error:', e);
      if (e?.code === '23505') {
        return res.status(409).send('มีรายการค้างเดิมของอุปกรณ์นี้อยู่แล้ว');
      }
      return res.status(500).send('บันทึกไม่สำเร็จ');
    }
  } catch (e) {
    console.error('POST /borrow/submit error:', e);
    return res.status(500).send('server error');
  }
});



app.get('/fitness', isStaff, async (req, res) => {
  try {
    const raw = (req.query.member || '').trim();
    if (!raw) return res.render('fitness', { member: null });

    const m = await findMemberByAny(raw);
    return res.render('fitness', { member: m || null });
  } catch (e) {
    console.error('GET /fitness error:', e);
    return res.render('fitness', { member: null });
  }
});

app.post('/fitness/submit', isStaff, async (req, res) => {
  try {
    const user_id     = (req.body.member_id || '').trim();      // UUID
    const member_type = (req.body.member_type || '').trim();    // 'student' | 'external'
    const visit_date  = (req.body.visit_date || '').trim();     // YYYY-MM-DD
    const pay_method  = (req.body.pay_method || 'cash').trim(); // 'cash' | 'qr'

    if (!user_id || !visit_date || !member_type) return res.status(400).send('ข้อมูลไม่ครบ');
    if (!['student','external'].includes(member_type)) return res.status(400).send('member_type ไม่ถูกต้อง');
    if (!['cash','qr'].includes(pay_method)) return res.status(400).send('วิธีชำระเงินไม่ถูกต้อง');

    const amount = (member_type === 'student') ? 5 : 30;

    const check = await pool.query(
      'SELECT id, full_name, member_type FROM users WHERE id = $1::uuid LIMIT 1',
      [user_id]
    );
    if (!check.rowCount) return res.status(404).send('ไม่พบบัญชีสมาชิก');

    await pool.query(
      `INSERT INTO fitness_visits (user_id, visit_date, amount, pay_method)
       VALUES ($1::uuid, $2::date, $3::int, $4)`,
      [user_id, visit_date, amount, pay_method]
    );

    try {
      await pushNotif(
        user_id,
        'fitness_visit',
        'เข้าใช้ฟิตเน็ตสำเร็จ',
        `คุณได้เข้าใช้ฟิตเน็ตวันที่ ${visit_date} ชำระ ${amount} บาท (${pay_method === 'qr' ? 'สแกน QR' : 'เงินสด'})`,
        { goto: '/history?tab=fitness', amount, visit_date, pay_method }
      );
    } catch (e) { console.warn('pushNotif (fitness) failed:', e?.message || e); }

    return res.redirect('/staff-home?ok=fitness');
  } catch (e) {
    console.error('POST /fitness/submit error:', e);
    return res.status(500).send('server error');
  }
});

/* =========================
 * 12) MEMBER AREA
 * ========================= */
app.get('/login', (req, res) => {
  if (req.session?.user) {
    const t = req.session.user.type;
    return res.redirect(t === 'student' ? '/student-home' : '/external-home');
  }
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const email = (req.body.email || '').trim();
  const code  = (req.body.code  || '').trim();

  if (!email || !code) return res.render('login', { error: 'กรอกอีเมลและรหัสให้ครบ' });

  try {
    const { rows } = await pool.query(
  `SELECT id, member_type, email, student_id, citizen_id, qr_code_value
     FROM users
    WHERE LOWER(email) = LOWER($1::text)
  AND ($2::text = COALESCE(student_id,'')
   OR  $2::text = COALESCE(citizen_id,'')
   OR  $2::text = COALESCE(qr_code_value,''))  
    LIMIT 1`,
  [email, code]
);


    if (!rows.length) return res.render('login', { error: 'ไม่พบบัญชีหรือรหัสไม่ถูกต้อง' });

    const u = rows[0];
    req.session.user   = { id: u.id, type: u.member_type };
    req.session.userId = u.id;
    return res.redirect(u.member_type === 'student' ? '/student-home' : '/external-home');
  } catch (e) {
    console.error(e);
    return res.render('login', { error: 'เกิดข้อผิดพลาด กรุณาลองใหม่' });
  }
});

app.post('/logout', (req, res) => { req.session.destroy(() => res.redirect('/login')); });

// app.get('/student-home', ...) — แก้ SELECT ให้มี id
app.get('/student-home', requireMember, async (req, res) => {
  if (req.session.user.type !== 'student') return res.redirect('/external-home');
  const id = req.session.user.id;
  const { rows } = await pool.query(
    `SELECT id, full_name, email, student_id, faculty, qr_code_value
       FROM users
      WHERE id = $1::uuid AND member_type='student'`,
    [id]
  );
  if (!rows.length) return res.status(404).send('ไม่พบนักศึกษา');
  res.render('student-home', { user: rows[0] });
});


app.get('/external-home', requireMember, async (req, res) => {
  if (req.session.user.type !== 'external') return res.redirect('/student-home');
  const id = req.session.user.id;
  const { rows } = await pool.query(
    `SELECT full_name,email,citizen_id,qr_code_value
       FROM users WHERE id = $1::uuid AND member_type='external'`, [id]
  );
  if (!rows.length) return res.status(404).send('ไม่พบบุคคลภายนอก');
  res.render('external-home', { 
    user: { full_name: rows[0].full_name, email: rows[0].email, external_id: rows[0].citizen_id, qr_code_value: rows[0].qr_code_value }
  });
});

/* =========================
 * 13) REGISTER
 * ========================= */
app.post('/register/student', redirectIfLoggedIn, async (req, res) => {
  const { email, student_id, full_name, faculty, phone } = req.body;

  if (!email?.endsWith('@mail.rmutk.ac.th')) return res.status(400).send('อีเมลต้องเป็น @mail.rmutk.ac.th');
  if (!/^[0-9]{12}$/.test(student_id || '')) return res.status(400).send('รหัสนักศึกษาต้องเป็นตัวเลข 12 หลัก');

  const uid = randomUUID();
  const check = await pool.query(`SELECT id FROM users WHERE LOWER(email)=LOWER($1) OR student_id=$2`, [email, student_id]);
  if (check.rows.length) return res.status(400).send('อีเมลหรือรหัสนักศึกษานี้ถูกใช้สมัครแล้ว');

  try {
    await pool.query(
      `INSERT INTO users
        (id, role_id, member_type, email, student_id, full_name, faculty, phone, qr_code_value)
       VALUES
        ($1, (SELECT id FROM roles WHERE name = 'student'), 'student',
         $2, $3, $4, $5, $6, $7)`,
      [uid, email, student_id, full_name, faculty, phone, student_id]
    );
    req.session.user   = { id: uid, type: 'student' };
    req.session.userId = uid;
    res.redirect('/student-home');
  } catch (err) {
    console.error(err);
    if (err.code === '23505') return res.status(400).send('รหัสนักศึกษาหรืออีเมลนี้ถูกใช้สมัครแล้ว');
    res.status(500).send('สมัครสมาชิกนักศึกษาไม่สำเร็จ');
  }
});

app.post('/register/external', redirectIfLoggedIn, async (req, res) => {
  const { email, citizen_id, full_name, phone } = req.body;
  if (!/^[0-9]{13}$/.test(citizen_id || '')) return res.status(400).send('เลขบัตรประชาชนต้องเป็นตัวเลข 13 หลัก');

  const uid = randomUUID();
  const check = await pool.query(`SELECT id FROM users WHERE LOWER(email)=LOWER($1) OR citizen_id=$2`, [email, citizen_id]);
  if (check.rows.length) return res.status(400).send('อีเมลหรือเลขบัตรประชาชนนี้ถูกใช้สมัครแล้ว');

  try {
    await pool.query(
      `INSERT INTO users
        (id, role_id, member_type, email, citizen_id, full_name, phone, qr_code_value)
       VALUES
        ($1, (SELECT id FROM roles WHERE name = 'external'), 'external',
         $2, $3, $4, $5, $6)`,
      [uid, email, citizen_id, full_name, phone, citizen_id]
    );
    req.session.user   = { id: uid, type: 'external' };
    req.session.userId = uid;
    res.redirect('/external-home');
  } catch (err) {
    console.error(err);
    if (err.code === '23505') return res.status(400).send('เลขบัตรประชาชนหรืออีเมลนี้ถูกใช้สมัครแล้ว');
    res.status(500).send('สมัครสมาชิกบุคคลภายนอกไม่สำเร็จ');
  }
});

/* =========================
 * 14) INVENTORY (STAFF)
 * ========================= */
app.get('/staff/inventory', isStaff, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, item_name, stock, active
         FROM inventory
        ORDER BY active DESC, item_name ASC`
    );
    res.render('inventory', { items: rows, success: req.query.ok || null, error: null });
  } catch (e) {
    console.error('inventory error:', e);
    res.render('inventory', { items: [], success: null, error: 'โหลดรายการไม่สำเร็จ' });
  }
});

app.get('/staff/inventory/new', isStaff, (req, res) => {
  res.render('inventory-new', { error: null, success: null, form: { name: '', stock: '' } });
});

app.post('/staff/inventory/new', isStaff, async (req, res) => {
  const name  = (req.body.name || '').trim();
  const stock = parseInt(req.body.stock, 10);

  if (!name || Number.isNaN(stock) || stock < 0) {
    return res.render('inventory-new', { error: 'กรุณากรอกข้อมูลให้ถูกต้อง', success: null, form: { name, stock: req.body.stock } });
  }
  try {
    const dup = await pool.query('SELECT 1 FROM inventory WHERE LOWER(item_name)=LOWER($1) LIMIT 1',[name]);
    if (dup.rowCount) {
      return res.render('inventory-new', { error: 'มีชื่ออุปกรณ์นี้อยู่แล้ว', success: null, form: { name, stock: req.body.stock } });
    }
    await pool.query('INSERT INTO inventory (id, item_name, stock, active) VALUES ($1::uuid, $2, $3, TRUE)',[randomUUID(), name, stock]);
    return res.redirect('/staff/inventory?ok=created');
  } catch (e) {
    console.error('insert inventory error:', e);
    return res.render('inventory-new', { error: e.detail || 'เพิ่มอุปกรณ์ไม่สำเร็จ', success: null, form: { name, stock: req.body.stock } });
  }
});

app.post('/staff/inventory/adjust', isStaff, async (req, res) => {
  const id = (req.body.id || '').trim();
  const delta = Number(req.body.delta || 0);
  try {
    await pool.query('BEGIN');
    const cur = await pool.query(`SELECT stock FROM inventory WHERE id=$1::uuid FOR UPDATE`, [id]);
    if (!cur.rowCount) { await pool.query('ROLLBACK'); return res.redirect('/staff/inventory?ok=notfound'); }
    const next = Number(cur.rows[0].stock) + delta;
    if (next < 0) { await pool.query('ROLLBACK'); return res.redirect('/staff/inventory?ok=stock_underflow'); }
    await pool.query(`UPDATE inventory SET stock=$1 WHERE id=$2::uuid`, [next, id]);
    await pool.query('COMMIT');
    return res.redirect('/staff/inventory?ok=updated');
  } catch (e) {
    try { await pool.query('ROLLBACK'); } catch {}
    console.error('ADJUST error', e);
    return res.redirect('/staff/inventory?ok=error');
  }
});

app.post('/staff/inventory/toggle/:id', isStaff, async (req, res) => {
  const id = (req.params.id || '').trim();
  try {
    await pool.query(`UPDATE inventory SET active = NOT active WHERE id=$1::uuid`, [id]);
    return res.redirect('/staff/inventory?ok=toggled');
  } catch (e) {
    console.error('TOGGLE error', e);
    return res.redirect('/staff/inventory?ok=error');
  }
});

app.post('/staff/inventory/:id/edit', isStaff, async (req, res) => {
  const id     = (req.params.id || '').trim();
  const name   = (req.body.name || '').trim();
  const stock  = Number(req.body.stock || 0);
  const active = !!req.body.active;

  if (!name || !Number.isInteger(stock) || stock < 0) return res.redirect('/staff/inventory?ok=error');

  try {
    const dup = await pool.query(
      `SELECT 1 FROM inventory WHERE LOWER(item_name)=LOWER($1) AND id<>$2::uuid LIMIT 1`,
      [name, id]
    );
    if (dup.rowCount) return res.redirect('/staff/inventory?ok=dup');

    await pool.query(
      `UPDATE inventory SET item_name=$1, stock=$2, active=$3 WHERE id=$4::uuid`,
      [name, stock, active, id]
    );
    return res.redirect('/staff/inventory?ok=updated');
  } catch (e) {
    console.error('EDIT error', e);
    return res.redirect('/staff/inventory?ok=error');
  }
});

app.post('/staff/inventory/:id/delete', isStaff, async (req, res) => {
  const id = (req.params.id || '').trim();
  try {
    await pool.query(`DELETE FROM inventory WHERE id=$1::uuid`, [id]);
    return res.redirect('/staff/inventory?ok=deleted');
  } catch (e) {
    console.error('DELETE error', e);
    if (e.code === '23503') return res.redirect('/staff/inventory?ok=fk');
    return res.redirect('/staff/inventory?ok=error');
  }
});

/* =========================
 * 15) QR IMAGE
 * ========================= */
app.get('/qrcode/:value', async (req, res) => {
  res.type('png');
  QRCode.toFileStream(res, req.params.value, { width: 600, margin: 1 });
});

/* =========================
 * 16) CRON: เตือนค้างคืน (ทุกวัน 08:00)
 * ========================= */
async function runOverdueJob() {
  console.log('[CRON] overdue check start', new Date().toISOString());

  // 2–6 วัน
  const dueSoon = (await pool.query(`SELECT * FROM overdue_2_6_days`)).rows;
  console.log(`[CRON] dueSoon rows = ${dueSoon.length}`);

  for (const r of dueSoon) {
    try {
      const msgUser = `รายการยืม ${r.item_name} × ${r.qty} ค้างคืนมาแล้ว ${r.days_overdue} วัน กรุณานำมาคืนโดยเร็ว`;
      await notifyUser({
        userIdOrCode: r.user_id,
        type: 'overdue_student',
        title: 'แจ้งเตือนค้างคืนอุปกรณ์',
        message: msgUser,
        meta: { ref: r.tx_id, tx_id: r.tx_id, goto: `/history#tx=${r.tx_id}` },
        emailSubject: 'แจ้งเตือนค้างคืนอุปกรณ์',
        emailHtml: `<p>${msgUser}</p><p>รหัสรายการ: ${r.tx_id}</p>`
      });

      // ✅ แจ้ง "เจ้าหน้าที่" พร้อมข้อมูลครบ + ลิงก์ไปดูประวัติของนักศึกษา
      await notifyStaff({
        type: 'overdue_staff_2_6',
        title: 'รายการค้างคืน 2–6 วัน',
        message: `มีนักศึกษาค้างคืน ${r.item_name} × ${r.qty} ${r.days_overdue} วัน`,
        meta: {
          ref: r.tx_id,                  // ใช้เป็น tx_id
          tx_id: r.tx_id,
          user_id: r.user_id,
          item: r.item_name,
          qty: r.qty,
          days_overdue: r.days_overdue,
          history_url: `/staff/history?member=${encodeURIComponent(r.user_id)}` // เปิดประวัติได้ทันที
        },
        emailSubject: '[แจ้งเตือน] ค้างคืน 2–6 วัน',
        emailHtml: `<p>มีนักศึกษาค้างคืน ${r.item_name} × ${r.qty} ${r.days_overdue} วัน</p>
                    <p><a href="/staff/history?member=${encodeURIComponent(r.user_id)}">เปิดประวัติสมาชิก</a></p>`
      });
    } catch (e) {
      console.error(`[CRON] dueSoon FAIL tx=${r.tx_id}`, e);
    }
  }

  // ≥7 วัน
  const over7 = (await pool.query(`SELECT * FROM overdue_7_plus`)).rows;
  console.log(`[CRON] over7 rows = ${over7.length}`);

  for (const r of over7) {
    try {
      const u = await getUserById(r.user_id);
      const msg = `นักศึกษา ${u?.full_name || r.user_id} ค้างคืน ${r.item_name} × ${r.qty} เป็นเวลา ${r.days_overdue} วัน`;
      const printUrl = `/reports/overdue/print?tx=${encodeURIComponent(r.tx_id)}`;

      await notifyStaff({
        type: 'overdue_staff', // หมายถึง ≥7 วัน
        title: 'รายการค้างคืนเกิน 7 วัน',
        message: `${msg}. เอกสารสำหรับส่งคณะ: ${printUrl}`,
        meta: {
          ref: r.tx_id,
          tx_id: r.tx_id,
          user_id: u?.id || r.user_id,
          item: r.item_name,
          qty: r.qty,
          days_overdue: r.days_overdue,
          print_url: printUrl,                                  // ปุ่มพิมพ์
          history_url: `/staff/history?member=${encodeURIComponent(r.user_id)}` // ปุ่มไปหน้าประวัติ
        },
        emailSubject: '[แจ้งเตือน] ค้างคืนเกิน 7 วัน',
        emailHtml: `<p>${msg}</p>
        <p><a href="${printUrl}">เปิดเอกสารสำหรับพิมพ์</a> |
        <a href="/staff/history?member=${encodeURIComponent(r.user_id)}">เปิดประวัติสมาชิก</a></p>`
      });
    } catch (e) {
      console.error(`[CRON] over7 FAIL tx=${r.tx_id}`, e);
    }
  }
}

/* =========================
 * 17) Report print (7+ days)
 * ========================= */

// พิมพ์เอกสาร + ปุ่มบันทึก "ส่งถึงคณะแล้ว"
app.get('/reports/overdue/print', isStaff, async (req, res) => {
  try {
    const tx = (req.query.tx || '').trim();
    if (!tx) return res.status(400).send('missing tx');

    const r = await pool.query(
      `SELECT t.id, t.user_id, t.inventory_id, t.qty, t.borrow_date,
              i.item_name, (CURRENT_DATE - t.borrow_date::date) AS days_overdue,
              t.escalated_at
         FROM transactions t
         JOIN inventory i ON i.id = t.inventory_id
        WHERE t.id = $1::uuid AND t.return_date IS NULL
        LIMIT 1`,
      [tx]
    );
    if (!r.rowCount) return res.status(404).send('not found');

    const row = r.rows[0];
    const u = await getUserById(row.user_id);

    const html = `
<!doctype html>
<html lang="th"><head>
<meta charset="utf-8">
<title>หนังสือแจ้งค้างคืน – ${u?.full_name || '-'}</title>
<style>
  body{font-family:Tahoma, sans-serif; line-height:1.6; margin:36px}
  .title{font-size:20px; font-weight:700; text-align:center; margin-bottom:8px}
  .sub{color:#555; text-align:center; margin-bottom:24px}
  .box{border:1px solid #ccc; padding:16px; border-radius:8px}
  .muted{color:#666}
  .sign{margin-top:32px}
  .noprint .btn{margin-left:8px}
  @media print {.noprint{display:none}}
</style>
</head><body>
  <div class="noprint" style="text-align:right;margin-bottom:8px;">
    <button onclick="window.print()">🖨️ พิมพ์เอกสาร</button>
    <button id="btnMarkSent" data-tx="${row.id}" class="btn" style="background:#ffc107;border:none;padding:8px 12px;border-radius:6px;">
      ✔️ ทำเครื่องหมายส่งถึงคณะแล้ว
    </button>
    <span id="markMsg" style="color:#198754;display:${row.escalated_at ? 'inline' : 'none'};margin-left:6px;">
      (บันทึกแล้ว)
    </span>
  </div>

  <div class="title">หนังสือแจ้งค้างคืนอุปกรณ์กีฬา</div>
  <div class="sub">รหัสรายการ: ${row.id}</div>

  <div class="box">
    <p>เรียน คณะ${u?.faculty || '(ไม่ระบุ)'}</p>
    <p>ตามที่นักศึกษา <strong>${u?.full_name || '-'}</strong> (อีเมล: ${u?.email || '-'}) ได้ทำการยืมอุปกรณ์
      <strong>${row.item_name}</strong> จำนวน <strong>${row.qty}</strong> ชิ้น เมื่อวันที่ <strong>${new Date(row.borrow_date).toLocaleDateString('th-TH')}</strong>
      บัดนี้ครบกำหนดและเกินกำหนดมาแล้ว <strong>${row.days_overdue}</strong> วัน แต่ยังไม่ได้ทำการคืนอุปกรณ์แต่อย่างใด</p>
    <p>จึงใคร่ขอความอนุเคราะห์ให้แจ้งเตือนนักศึกษา เพื่อดำเนินการคืนอุปกรณ์โดยเร็ว</p>
    <p class="muted">เอกสารนี้จัดทำโดยระบบยืม–คืนอุปกรณ์กีฬาและฟิตเนส</p>
  </div>

  <div class="sign">
    <p>ลงชื่อ................................................. เจ้าหน้าที่ผู้รับผิดชอบ</p>
    <p>วันที่........../........../............</p>
  </div>

  <script>
    const btn = document.getElementById('btnMarkSent');
    if (btn) {
      btn.addEventListener('click', async () => {
        const tx = btn.dataset.tx;
        const old = btn.innerHTML;
        btn.disabled = true; btn.innerHTML = 'กำลังบันทึก...';
        try{
          const resp = await fetch('/reports/overdue/mark-sent', {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ tx })
          });
          const data = await resp.json().catch(()=>({}));
          if(!resp.ok) throw new Error(data?.error || ('HTTP '+resp.status));
          btn.style.background = '#198754'; btn.style.color='#fff';
          btn.innerHTML = 'บันทึกว่า: ส่งถึงคณะแล้ว';
          const msg = document.getElementById('markMsg'); if (msg) msg.style.display='inline';

          // ✅ กลับไปหน้า staff/history เพื่อให้เห็นสถานะเปลี่ยน
          setTimeout(() => { window.location.href = '/staff/history'; }, 600);
        }catch(e){
          alert('บันทึกล้มเหลว: ' + (e.message || e));
          btn.disabled = false; btn.innerHTML = old;
        }
      });
    }
  </script>
</body></html>`;
    res.send(html);
  } catch (e) {
    console.error('print report error:', e);
    res.status(500).send('server error');
  }
});

// บันทึกสถานะว่า "ส่งถึงคณะแล้ว" + ใส่ hold + แจ้งเตือน
app.post('/reports/overdue/mark-sent', isStaff, async (req, res) => {
  try {
    const tx = (req.body?.tx || '').trim();
    if (!tx) return res.status(400).json({ error: 'missing tx' });

    const r = await pool.query(
      `SELECT t.id, t.user_id, t.inventory_id, t.qty, t.borrow_date, t.return_date, t.escalated_at,
              i.item_name, (CURRENT_DATE - t.borrow_date::date) AS days_overdue
         FROM transactions t
         JOIN inventory i ON i.id = t.inventory_id
        WHERE t.id = $1::uuid
        LIMIT 1`,
      [tx]
    );
    if (!r.rowCount)   return res.status(404).json({ error: 'not found' });
    const row = r.rows[0];
    if (row.return_date) return res.status(400).json({ error: 'already returned' });

    // ทำเครื่องหมาย escalated_at
    if (!row.escalated_at) {
      await pool.query(`UPDATE transactions SET escalated_at = now() WHERE id = $1::uuid`, [tx]);
    }

    // สร้าง hold ถ้ายังไม่มี
    if (!await hasActiveHold(row.user_id)) {
      await pool.query(
        `INSERT INTO user_holds (user_id, reason) VALUES ($1::uuid, $2::text)`,
        [row.user_id, `ค้างคืนเกิน 7 วัน: TX ${row.id} - ${row.item_name} × ${row.qty}`]
      );
    }

    // แจ้งนักศึกษา
    await notifyUser({
      userIdOrCode: row.user_id,
      type: 'overdue_faculty',
      title: 'ส่งเรื่องถึงคณะแล้ว',
      message: `รายการยืม ${row.item_name} × ${row.qty} เกินกำหนด ${row.days_overdue} วัน ระบบได้ส่งหนังสือถึงคณะแล้ว และระงับการยืมชั่วคราวจนกว่าจะจัดการคืนเรียบร้อย`,
      meta: { ref: row.id, goto: '/history' },
      emailSubject: 'แจ้งเตือน: ส่งเรื่องค้างคืนถึงคณะ',
      emailHtml: `<p>รายการยืม ${row.item_name} × ${row.qty} เกินกำหนด ${row.days_overdue} วัน</p>
                  <p>ขณะนี้ได้ส่งหนังสือแจ้งถึงคณะแล้ว และระบบได้ระงับสิทธิ์การยืมชั่วคราว</p>`
    });
    

    // แจ้งเจ้าหน้าที่รวม
    await notifyStaff({
      type: 'hold_created',
      title: 'บันทึกส่งถึงคณะ & ระงับสิทธิ์',
      message: `TX ${row.id} (${row.item_name} × ${row.qty}) ถูกทำเครื่องหมายส่งถึงคณะแล้ว และระงับสิทธิ์นักศึกษาในการยืม`,
      meta: { ref: row.id, user_id: row.user_id }
    });

    return res.json({ ok: true });
  } catch (e) {
    console.error('mark-sent error:', e);
    return res.status(500).json({ error: 'server error' });
  }
});

/* =========================
 * 18) HISTORY (staff + member)
 * ========================= */
// นักศึกษา: เห็นของตัวเองเท่านั้น
app.get('/history', requireMember, async (req, res) => {
  if (req.session.user.type !== 'student') return res.redirect('/staff/history');
  const userId = req.session.user.id;
  const { borrowRows, fitnessRows } = await getHistoryData({ userId });
  return res.render('history/student', { borrowRows, fitnessRows });
});

// เจ้าหน้าที่: ค้นหา+ส่งแจ้งเตือนได้
app.get('/staff/history', isStaff, async (req, res) => {
  const filters = {
    member: (req.query.member || '').trim(),
    from:   (req.query.from   || '').trim(),
    to:     (req.query.to     || '').trim(),
  };
  let member = null; let userId = null;
  if (filters.member) {
    member = await findMemberByAny(filters.member);
    userId = member?.id || null;
  }
  const { borrowRows, fitnessRows } = await getHistoryData({
    userId, from: filters.from, to: filters.to
  });
  return res.render('history/staff', { filters, member, borrowRows, fitnessRows });
});


// รายชื่อสมาชิก
app.get('/members', async (req, res) => {
  try {
    const rows = (await pool.query(
      `SELECT id, full_name, member_type, student_id, citizen_id, email, created_at
         FROM users
        ORDER BY created_at DESC
        LIMIT 100`
    )).rows;
    res.render('members', { members: rows });
  } catch (e) {
    console.error('GET /members error:', e);
    res.render('members', { members: [], info: 'เกิดข้อผิดพลาดในการโหลดรายชื่อ' });
  }
});

app.get("/equipment", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, item_name, stock, active
         FROM inventory
        ORDER BY item_name ASC`
    );
    res.render("equipment", { inventory: result.rows });
  } catch (err) {
    console.error(err);
    res.render("equipment", { inventory: [] });
  }
});

/* =========================
 * 19) START
 * ========================= */
initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
  })
  .catch(err => {
    console.error('DB init failed:', err.code, err.message);
    process.exit(1);
  });

