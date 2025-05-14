// Secure password hashing using Web Crypto
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
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method;

    if (method === 'POST' && path === '/signup') {
      const { name, email, password } = await req.json();
      if (!name || !email || !password) {
        return new Response(JSON.stringify({ error: 'Missing name, email, or password' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      const passwordErrors = validatePassword(password);
      if (passwordErrors.length > 0) {
        return new Response(JSON.stringify({ error: passwordErrors.join(" ") }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      const existingEmail = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
      if (existingEmail) {
        return new Response(JSON.stringify({ error: 'Email already in use' }), {
          status: 409,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      const existingName = await env.DB.prepare('SELECT id FROM users WHERE name = ?').bind(name).first();
      if (existingName) {
        return new Response(JSON.stringify({ error: 'Username already taken' }), {
          status: 409,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      const userId = crypto.randomUUID();
      const passwordHash = await hashPassword(password);

      try {
        await env.DB.batch([
          env.DB.prepare('INSERT INTO users (id, email, name) VALUES (?, ?, ?)').bind(userId, email, name),
          env.DB.prepare('INSERT INTO password_logins (email, password_hash, user_id) VALUES (?, ?, ?)').bind(email, passwordHash, userId),
          env.DB.prepare('INSERT INTO auth_providers (provider, provider_user_id, user_id) VALUES (?, ?, ?)').bind('email', email, userId)
        ]);
        return new Response(JSON.stringify({ success: true, userId }), {
          headers: { 'Content-Type': 'application/json' }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: `Signup failed: ${e.message}` }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    if (method === 'POST' && path === '/login') {
      const { email, password } = await req.json();
      if (!email || !password) {
        return new Response('Missing credentials', { status: 400 });
      }

      const row = await env.DB.prepare('SELECT password_hash, user_id FROM password_logins WHERE email = ?').bind(email).first();
      if (!row || !(await verifyPassword(password, row.password_hash))) {
        return new Response('Invalid credentials', { status: 401 });
      }

      const user = await env.DB.prepare('SELECT name FROM users WHERE id = ?').bind(row.user_id).first();
      return new Response(JSON.stringify({ name: user.name }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response('Not Found', { status: 404 });
  }
};
