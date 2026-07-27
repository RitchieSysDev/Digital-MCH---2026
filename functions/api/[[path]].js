export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  if (!env.DB) {
    return jsonResponse({ error: 'Database binding is not configured for this Pages project.' }, 500);
  }

  await ensureSchema(env);

  const path = url.pathname.replace(/^\/api\/?/, '').toLowerCase();

  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type,Authorization' }
    });
  }

  if (path === 'register' && request.method === 'POST') {
    return registerUser(request, env);
  }

  if (path === 'login' && request.method === 'POST') {
    return loginUser(request, env);
  }

  if (path === 'me' && request.method === 'GET') {
    return getCurrentUser(request, env);
  }

  if (path === 'logout' && request.method === 'POST') {
    return logoutUser(request, env);
  }

  if (path === 'records' && request.method === 'GET') {
    return listRecords(request, env);
  }

  if (path === 'records' && request.method === 'POST') {
    return saveRecord(request, env);
  }

  if (path === 'admin/users' && request.method === 'GET') {
    return adminUsers(request, env);
  }

  return jsonResponse({ error: 'Route not found.' }, 404);
}

async function ensureSchema(env) {
  const schema = `
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS auth_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT UNIQUE NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      expires_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      payload TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `;
  await env.DB.exec(schema);
}

async function registerUser(request, env) {
  const body = await readJson(request);
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');

  if (!email || !password) {
    return jsonResponse({ error: 'Email and password are required.' }, 400);
  }

  const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
  if (existing) {
    return jsonResponse({ error: 'An account already exists for this email.' }, 409);
  }

  const adminCountRow = await env.DB.prepare('SELECT COUNT(*) as count FROM users').first();
  const role = Number(adminCountRow?.count || 0) === 0 ? 'admin' : 'user';
  const passwordHash = await hashText(password);

  const result = await env.DB.prepare('INSERT INTO users (email, password_hash, role, created_at) VALUES (?, ?, ?, datetime("now"))')
    .bind(email, passwordHash, role)
    .run();

  const user = { id: result.lastInsertRowid, email, role };
  const token = await issueToken(env, user.id);
  return jsonResponse({ user, token }, 201);
}

async function loginUser(request, env) {
  const body = await readJson(request);
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');

  if (!email || !password) {
    return jsonResponse({ error: 'Email and password are required.' }, 400);
  }

  const userRow = await env.DB.prepare('SELECT id, email, role, password_hash FROM users WHERE email = ?').bind(email).first();
  if (!userRow) {
    return jsonResponse({ error: 'Invalid login credentials.' }, 401);
  }

  const passwordHash = await hashText(password);
  if (passwordHash !== userRow.password_hash) {
    return jsonResponse({ error: 'Invalid login credentials.' }, 401);
  }

  const token = await issueToken(env, userRow.id);
  const user = { id: userRow.id, email: userRow.email, role: userRow.role };
  return jsonResponse({ user, token });
}

async function getCurrentUser(request, env) {
  const user = await getAuthenticatedUser(request, env);
  if (!user) return jsonResponse({ error: 'Authentication required.' }, 401);
  return jsonResponse({ user });
}

async function logoutUser(request, env) {
  const token = readToken(request);
  if (!token) return jsonResponse({ ok: true });
  await env.DB.prepare('DELETE FROM auth_tokens WHERE token = ?').bind(token).run();
  return jsonResponse({ ok: true });
}

async function listRecords(request, env) {
  const user = await getAuthenticatedUser(request, env);
  if (!user) return jsonResponse({ error: 'Authentication required.' }, 401);

  let rows;
  if (user.role === 'admin') {
    rows = await env.DB.prepare('SELECT id, user_id, title, payload, created_at, updated_at FROM records ORDER BY updated_at DESC').all();
  } else {
    rows = await env.DB.prepare('SELECT id, user_id, title, payload, created_at, updated_at FROM records WHERE user_id = ? ORDER BY updated_at DESC').bind(user.id).all();
  }

  const records = (rows.results || []).map((row) => ({ ...row, payload: parseJson(row.payload) }));
  return jsonResponse({ records });
}

async function saveRecord(request, env) {
  const user = await getAuthenticatedUser(request, env);
  if (!user) return jsonResponse({ error: 'Authentication required.' }, 401);

  const body = await readJson(request);
  const title = String(body.title || 'MCH record').trim();
  const payload = JSON.stringify(body.payload || {});

  const result = await env.DB.prepare('INSERT INTO records (user_id, title, payload, created_at, updated_at) VALUES (?, ?, ?, datetime("now"), datetime("now"))')
    .bind(user.id, title, payload)
    .run();

  return jsonResponse({ id: result.lastInsertRowid, ok: true });
}

async function adminUsers(request, env) {
  const user = await getAuthenticatedUser(request, env);
  if (!user || user.role !== 'admin') return jsonResponse({ error: 'Admin access required.' }, 403);

  const users = await env.DB.prepare('SELECT id, email, role, created_at FROM users ORDER BY created_at DESC').all();
  const records = await env.DB.prepare('SELECT COUNT(*) as count FROM records').first();
  return jsonResponse({ users: users.results || [], recordCount: Number(records?.count || 0) });
}

async function issueToken(env, userId) {
  const token = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7).toISOString();
  await env.DB.prepare('INSERT INTO auth_tokens (user_id, token, created_at, expires_at) VALUES (?, ?, datetime("now"), ?)')
    .bind(userId, token, expiresAt)
    .run();
  return token;
}

async function getAuthenticatedUser(request, env) {
  const token = readToken(request);
  if (!token) return null;
  const row = await env.DB.prepare(`
    SELECT u.id, u.email, u.role
    FROM auth_tokens at
    JOIN users u ON u.id = at.user_id
    WHERE at.token = ? AND at.expires_at > datetime('now')
  `).bind(token).first();

  if (!row) return null;
  return { id: row.id, email: row.email, role: row.role };
}

function readToken(request) {
  const header = request.headers.get('Authorization') || '';
  return header.startsWith('Bearer ') ? header.slice(7).trim() : '';
}

async function hashText(value) {
  const data = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

function parseJson(value) {
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization'
    }
  });
}
