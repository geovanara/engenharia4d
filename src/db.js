// src/db.js
const mysql = require('mysql2');

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'engenharia4d'
});

connection.connect((err) => {
  if (err) {
    console.error('Erro ao conectar:', err);
  } else {
    console.log('Conectado ao MySQL 🚀');
  }
});

module.exports = connection;
/*

// --- Migrações defensivas ---
function ensureColumn(table, column, type) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!cols.some(c => c.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}`);
  }
}

try {
  ensureColumn('users', 'status', 'TEXT');
  ensureColumn('users', 'access_expires_at', 'TEXT'); 
  ensureColumn('users', 'plan', 'TEXT');
  ensureColumn('users', 'session_token', 'TEXT');
  ensureColumn('users', 'session_issued_at', 'TEXT');
  // NOVO: preferências
  ensureColumn('users', 'mdf_mm', 'INTEGER');
  ensureColumn('users', 'travessa_mm', 'INTEGER');

  ensureColumn('payments', 'plan', 'TEXT');
  ensureColumn('payments', 'provider_tx', 'TEXT');
  ensureColumn('payments', 'paid_at', 'TEXT');
} catch (_) {}

// --- Mappers ---
const mapUser = r => r && ({
  id: r.id,
  name: r.name,
  company: r.company,
  email: r.email,
  password_hash: r.password_hash,
  plan: r.plan,
  status: r.status,
  access_expires_at: r.access_expires_at,
  session_token: r.session_token,
  session_issued_at: r.session_issued_at,
  mdf_mm: r.mdf_mm,
  travessa_mm: r.travessa_mm,
  created_at: r.created_at,
  updated_at: r.updated_at
});

const mapPayment = r => r && ({
  id: r.id,
  user_id: r.user_id,
  provider: r.provider,
  order_ref: r.order_ref,
  amount_cents: r.amount_cents,
  status: r.status,
  plan: r.plan,
  provider_tx: r.provider_tx,
  created_at: r.created_at,
  paid_at: r.paid_at
});

// --- Users ---
function createUser({ name, company, email, password_hash, plan }) {
  const info = db.prepare(`
    INSERT INTO users (name, company, email, password_hash, plan, status, created_at)
    VALUES (?, ?, ?, ?, ?, 'pending', datetime('now'))
  `).run(name, company || null, email, password_hash || null, plan || null);
  return info.lastInsertRowid;
}

const getUserById    = id    => mapUser(db.prepare(`SELECT * FROM users WHERE id=?`).get(id));
const getUserByEmail = email => mapUser(db.prepare(`SELECT * FROM users WHERE email=?`).get(email));

function activateUser(user_id, expiresISO) {
  db.prepare(`
    UPDATE users
       SET status='active', access_expires_at=?, updated_at=datetime('now')
     WHERE id=?
  `).run(expiresISO, user_id);
}

// Atualizar (com checagem de e-mail único)
// (ampliado para aceitar mdf_mm e travessa_mm)
function updateUser(id, { name, company, email, plan, status, access_expires_at, mdf_mm, travessa_mm }) {
  if (email) {
    const other = db.prepare(`SELECT id FROM users WHERE email=? AND id<>?`).get(email, id);
    if (other) {
      const err = new Error('EMAIL_TAKEN');
      err.code = 'EMAIL_TAKEN';
      throw err;
    }
  }
  const _plan   = (plan === 'mensal' || plan === 'anual') ? plan : null;
  const allowedStatus = new Set(['pending', 'active', 'inactive', 'vitalicio']);
  const _status = allowedStatus.has(status) ? status : null;

  // higieniza preferências
  const allowedMdf = new Set([6, 15, 18]);
  const _mdf = Number.isInteger(mdf_mm) && allowedMdf.has(mdf_mm) ? mdf_mm : null;
  const _trav = Number.isInteger(travessa_mm) && travessa_mm > 0 && travessa_mm < 10000 ? travessa_mm : null;

  db.prepare(`
    UPDATE users SET
      name = COALESCE(?, name),
      company = ?,
      email = COALESCE(?, email),
      plan = COALESCE(?, plan),
      status = COALESCE(?, status),
      access_expires_at = COALESCE(?, access_expires_at),
      mdf_mm = COALESCE(?, mdf_mm),
      travessa_mm = COALESCE(?, travessa_mm),
      updated_at = datetime('now')
    WHERE id=?
  `).run(
    name || null,
    (company || null),
    email || null,
    _plan,
    _status,
    (access_expires_at || null),
    _mdf,
    _trav,
    id
  );
  return getUserById(id);
}

// Atualiza apenas a senha (hash)
function updateUserPassword(id, password_hash) {
  db.prepare(`
    UPDATE users
       SET password_hash = ?, updated_at = datetime('now')
     WHERE id = ?
  `).run(password_hash, id);
  return getUserById(id);
}

// Sessão única por usuário
function setUserSession(user_id, token) {
  db.prepare(`
    UPDATE users
       SET session_token = ?, session_issued_at = datetime('now'), updated_at = datetime('now')
     WHERE id = ?
  `).run(token, user_id);
}

function clearUserSession(user_id) {
  db.prepare(`
    UPDATE users
       SET session_token = NULL, session_issued_at = NULL, updated_at = datetime('now')
     WHERE id = ?
  `).run(user_id);
}

function deleteUser(id) {
  db.prepare(`DELETE FROM users WHERE id=?`).run(id);
  return true;
}
function deleteUsers(ids = []) {
  const stmt = db.prepare(`DELETE FROM users WHERE id=?`);
  const trans = db.transaction((arr) => { arr.forEach(id => stmt.run(id)); });
  trans(ids);
  return true;
}

// --- Payments ---
function createPayment({ user_id, provider, order_ref, amount_cents, plan }) {
  db.prepare(`
    INSERT INTO payments (user_id, provider, order_ref, amount_cents, status, plan, created_at)
    VALUES (?, ?, ?, ?, 'pending', ?, datetime('now'))
  `).run(user_id, provider || 'link', order_ref, amount_cents, plan || null);
  return order_ref;
}

const getPaymentByOrderRef = ref => mapPayment(db.prepare(`SELECT * FROM payments WHERE order_ref=?`).get(ref));

const getPendingPaymentForUser = uid => mapPayment(db.prepare(`
  SELECT * FROM payments
   WHERE user_id=? AND status='pending'
   ORDER BY datetime(created_at) DESC
   LIMIT 1
`).get(uid));

function markPaymentPaid(order_ref, provider_tx) {
  db.prepare(`
    UPDATE payments
       SET status='paid', provider_tx=?, paid_at=datetime('now')
     WHERE order_ref=?
  `).run(provider_tx || null, order_ref);
}

// --- Auditoria de exclusões ---
function recordDeletion({ user_id = null, email = null, actor = 'user' } = {}) {
  db.prepare(`
    INSERT INTO audit_deletions (user_id, user_email, actor)
    VALUES (?, ?, ?)
  `).run(user_id, email || null, actor);
}

// --- Estatísticas (Relatório) ---
function countAllUsers() {
  const r = db.prepare(`SELECT COUNT(*) AS n FROM users`).get();
  return r?.n || 0;
}

function countActiveNow() {
  // vitalício OU (active com validade futura)
  const r = db.prepare(`
    SELECT COUNT(*) AS n
      FROM users
     WHERE status='vitalicio'
        OR (status='active' AND COALESCE(access_expires_at,'') <> '' AND datetime(access_expires_at) > datetime('now'))
  `).get();
  return r?.n || 0;
}

function countInactiveNow() {
  // total - ativos agora
  return Math.max(0, countAllUsers() - countActiveNow());
}

function countPlan(plan) {
  const r = db.prepare(`SELECT COUNT(*) AS n FROM users WHERE plan = ?`).get(plan);
  return r?.n || 0;
}

function getDeletionSummary() {
  const byAdmin = db.prepare(`SELECT COUNT(*) AS n FROM audit_deletions WHERE actor='admin'`).get()?.n || 0;
  const byUser  = db.prepare(`SELECT COUNT(*) AS n FROM audit_deletions WHERE actor='user'`).get()?.n || 0;
  return { by_admin: byAdmin, by_user: byUser, total: byAdmin + byUser };
}

// Opcional: ajudar a pré-preencher 4D Conta (pega algum vitalício)
function getFirstVitalicio() {
  const r = db.prepare(`
    SELECT * FROM users WHERE status='vitalicio'
    ORDER BY datetime(created_at) DESC LIMIT 1
  `).get();
  return mapUser(r);
}


// --- Listas / buscas ---
function listUsers({ q = '', limit = 50 } = {}) {
  const L = Math.min(Math.max(parseInt(limit, 10) || 50, 1), 200);
  if (q) {
    const like = `%${q}%`.toLowerCase();
    const rows = db.prepare(`
      SELECT * FROM users
       WHERE LOWER(name) LIKE ? OR LOWER(email) LIKE ? OR LOWER(COALESCE(company,'')) LIKE ?
       ORDER BY datetime(created_at) DESC
       LIMIT ?
    `).all(like, like, like, L);
    return rows.map(mapUser);
  }
  const rows = db.prepare(`
    SELECT * FROM users
     ORDER BY datetime(created_at) DESC
     LIMIT ?
  `).all(L);
  return rows.map(mapUser);
}

function searchUsers({ q = '', limit = 25, offset = 0 } = {}) {
  const L = Math.min(Math.max(parseInt(limit, 10) || 25, 1), 200);
  const O = Math.max(parseInt(offset, 10) || 0, 0);
  if (q) {
    const like = `%${q}%`.toLowerCase();
    const rows = db.prepare(`
      SELECT * FROM users
       WHERE LOWER(name) LIKE ? OR LOWER(email) LIKE ? OR LOWER(COALESCE(company,'')) LIKE ?
       ORDER BY datetime(created_at) DESC
       LIMIT ? OFFSET ?
    `).all(like, like, like, L, O);
    return rows.map(mapUser);
  }
  const rows = db.prepare(`
    SELECT * FROM users
     ORDER BY datetime(created_at) DESC
     LIMIT ? OFFSET ?
  `).all(L, O);
  return rows.map(mapUser);
}

function getPaymentsByUser(user_id) {
  const rows = db.prepare(`
    SELECT * FROM payments
     WHERE user_id=?
     ORDER BY datetime(created_at) DESC
  `).all(user_id);
  return rows.map(mapPayment);
}

function listPayments({ status = null, limit = 50 } = {}) {
  const L = Math.min(Math.max(parseInt(limit, 10) || 50, 1), 200);
  let rows;
  if (status) {
    rows = db.prepare(`
      SELECT * FROM payments
       WHERE status=?
       ORDER BY datetime(created_at) DESC
       LIMIT ?
    `).all(status, L);
  } else {
    rows = db.prepare(`
      SELECT * FROM payments
       ORDER BY datetime(created_at) DESC
       LIMIT ?
    `).all(L);
  }
  return rows.map(mapPayment);
}

module.exports = {
  createUser, getUserById, getUserByEmail, activateUser,
  createPayment, getPaymentByOrderRef, getPendingPaymentForUser, markPaymentPaid,
  listUsers, listPayments, searchUsers, getPaymentsByUser,
  updateUser, deleteUser, deleteUsers,
  updateUserPassword,
  setUserSession, clearUserSession,
  // auditoria/relatório
  recordDeletion, countAllUsers, countActiveNow, countInactiveNow, countPlan, getDeletionSummary, getFirstVitalicio,
  db, DB_PATH
};
*/