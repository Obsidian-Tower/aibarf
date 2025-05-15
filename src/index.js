// Cloudflare Worker: src/index.js
// Handles CORS, signup, login, username/email availability with D1 and Web Crypto

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,HEAD,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

async function hashPassword(password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const pwBuf = enc.encode(password);
  const salted = new Uint8Array([...salt, ...pwBuf]);
  const hash = await crypto.subtle.digest('SHA-256', salted);
  const full = new Uint8Array([...salt, ...new Uint8Array(hash)]);
  return btoa(String.fromCharCode(...full));
}

async function verifyPassword(password, storedHash) {
  const enc = new TextEncoder();
  const bin = atob(storedHash);
  const full = Uint8Array.from(bin, c => c.charCodeAt(0));
  const salt = full.slice(0, 16);
  const originalHash = full.slice(16);
  const pwBuf = enc.encode(password);
  const salted = new Uint8Array([...salt, ...pwBuf]);
  const testHash = new Uint8Array(await crypto.subtle.digest('SHA-256', salted));
  return originalHash.every((b, i) => b === testHash[i]);
}

function validatePassword(password) {
  const errors = [];
  if (password.length < 8) errors.push("Password must be at least 8 characters long.");
  if (!/[a-zA-Z]/.test(password)) errors.push("Password must contain letters.");
  if (!/[0-9]/.test(password)) errors.push("Password must contain at least one number.");
  return errors;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname } = url;

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    // Username availability check
    if (pathname === '/check-username' && request.method === 'GET') {
      const name = url.searchParams.get('username');
      if (!name) {
        return new Response(JSON.stringify({ error: 'Missing username' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
        });
      }

      const exists = await env.DB.prepare('SELECT id FROM users WHERE name = ?')
        .bind(name).first();

      return new Response(JSON.stringify({ available: !exists }), {
        headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
      });
    }

    // Email availability check
    if (pathname === '/check-email' && request.method === 'GET') {
      const email = url.searchParams.get('email');
      if (!email) {
        return new Response(JSON.stringify({ error: 'Missing email' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
        });
      }

      const exists = await env.DB.prepare('SELECT id FROM users WHERE email = ?')
        .bind(email.toLowerCase()).first();

      return new Response(JSON.stringify({ available: !exists }), {
        headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
      });
    }

    // Signup
    if (pathname === '/signup' && request.method === 'POST') {
      const { name, email, password } = await request.json();
      if (!name || !email || !password) {
        return new Response(JSON.stringify({ error: 'Missing fields' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
        });
      }

      const pwdErrors = validatePassword(password);
      if (pwdErrors.length) {
        return new Response(JSON.stringify({ error: pwdErrors.join(' ') }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
        });
      }

      const emailExists = await env.DB.prepare('SELECT id FROM users WHERE email = ?')
        .bind(email).first();
      if (emailExists) {
        return new Response(JSON.stringify({ error: 'Email already in use' }), {
          status: 409,
          headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
        });
      }

      const nameExists = await env.DB.prepare('SELECT id FROM users WHERE name = ?')
        .bind(name).first();
      if (nameExists) {
        return new Response(JSON.stringify({ error: 'Username already taken' }), {
          status: 409,
          headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
        });
      }

      const userId = crypto.randomUUID();
      const passwordHash = await hashPassword(password);

      try {
        await env.DB.batch([
          env.DB.prepare('INSERT INTO users (id, email, name) VALUES (?, ?, ?)')
            .bind(userId, email, name),
          env.DB.prepare('INSERT INTO password_logins (email, password_hash, user_id) VALUES (?, ?, ?)')
            .bind(email, passwordHash, userId),
          env.DB.prepare('INSERT INTO auth_providers (provider, provider_user_id, user_id) VALUES (?, ?, ?)')
            .bind('email', email, userId)
        ]);
        return new Response(JSON.stringify({ success: true, userId }), {
          status: 201,
          headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: `Signup failed: ${e.message}` }), {
          status: 500,
          headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
        });
      }
    }

    // Login
    if (pathname === '/login' && request.method === 'POST') {
      const { email, password } = await request.json();
      if (!email || !password) {
        return new Response(JSON.stringify({ error: 'Missing credentials' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
        });
      }

      const row = await env.DB.prepare(
        'SELECT password_hash, user_id FROM password_logins WHERE email = ?'
      ).bind(email).first();

      if (!row || !(await verifyPassword(password, row.password_hash))) {
        return new Response(JSON.stringify({ error: 'Invalid credentials' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
        });
      }

      const user = await env.DB.prepare('SELECT name, email FROM users WHERE id = ?')
    .bind(row.user_id).first();

  // 1) Build a richer payload
  const payload = {
    success: true,
    user: {
      name:  user.name,
      email: user.email
    }
  };

  // 2) Return it
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
  });
}
};
