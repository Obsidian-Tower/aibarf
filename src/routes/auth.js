// src/routes/auth.js
import { signJWT, verifyJWT } from '../utils/jwt.js';
import { hashPassword, verifyPassword } from '../utils/hash.js';
import { validatePassword } from '../utils/validators.js';
import { sendResetEmail, RESET_TOKEN_TTL } from '../utils/email.js';

export async function handleAuth(request, env, pathname, corsHeaders) {
  const url = new URL(request.url);
  const method = request.method;
  const headers = { 'Content-Type': 'application/json', ...corsHeaders };

  // /check-username
  if (pathname === '/check-username' && method === 'GET') {
    const name = url.searchParams.get('username');
    if (!name) {
      return new Response(JSON.stringify({ error: 'Missing username' }), { status: 400, headers });
    }
    const exists = await env.DB.prepare('SELECT id FROM users WHERE name=?').bind(name).first();
    return new Response(JSON.stringify({ available: !exists }), { headers });
  }

  // /check-email
  if (pathname === '/check-email' && method === 'GET') {
    const email = url.searchParams.get('email');
    if (!email) {
      return new Response(JSON.stringify({ error: 'Missing email' }), { status: 400, headers });
    }
    const exists = await env.DB.prepare('SELECT id FROM users WHERE email=?')
      .bind(email.toLowerCase())
      .first();
    return new Response(JSON.stringify({ available: !exists }), { headers });
  }

  // /signup
  if (pathname === '/signup' && method === 'POST') {
    const { name, email, password } = await request.json();
    if (!name || !email || !password) {
      return new Response(JSON.stringify({ error: 'Missing fields' }), { status: 400, headers });
    }

    const pwErrs = validatePassword(password);
    if (pwErrs.length) {
      return new Response(JSON.stringify({ error: pwErrs.join(', ') }), { status: 400, headers });
    }

    const normalizedEmail = email.toLowerCase();
    const eExists = await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(normalizedEmail).first();
    if (eExists) {
      return new Response(JSON.stringify({ error: 'Email in use' }), { status: 409, headers });
    }

    const nExists = await env.DB.prepare('SELECT id FROM users WHERE name=?').bind(name).first();
    if (nExists) {
      return new Response(JSON.stringify({ error: 'Username taken' }), { status: 409, headers });
    }

    const userId = crypto.randomUUID();
    const hash = await hashPassword(password);
    await env.DB.batch([
      env.DB.prepare('INSERT INTO users(id,email,name,profile_image_url) VALUES(?,?,?,?)').bind(
        userId,
        normalizedEmail,
        name,
        'https://aibarf.coryzuber.workers.dev/assets/images/initial-profile-image-v1.png'
      ),
      env.DB.prepare('INSERT INTO password_logins(email,password_hash,user_id) VALUES(?,?,?)').bind(
        normalizedEmail,
        hash,
        userId
      ),
      env.DB.prepare('INSERT INTO auth_providers(provider,provider_user_id,user_id) VALUES(?,?,?)').bind(
        'email',
        normalizedEmail,
        userId
      ),
    ]);

    return new Response(JSON.stringify({ success: true, userId }), { status: 201, headers });
  }

  // /login
  if (pathname === '/login' && method === 'POST') {
    console.log('🦊 🔑 handleAuth → POST /login hit');
    let { email, password } = await request.json();
    if (!email || !password) {
      return new Response(JSON.stringify({ error: 'Missing credentials' }), { status: 400, headers });
    }

    email = email.toLowerCase();
    const row = await env.DB.prepare('SELECT password_hash,user_id FROM password_logins WHERE email=?')
      .bind(email)
      .first();

    if (!row || !(await verifyPassword(password, row.password_hash))) {
      return new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401, headers });
    }

    const nowSec = Math.floor(Date.now() / 1000);
    const payload = { sub: row.user_id, exp: nowSec + 60 * 60 * 24 * 7 };
    const token = await signJWT(payload, env.SESSION_SECRET);

    const user = await env.DB.prepare('SELECT name,email FROM users WHERE id=?').bind(row.user_id).first();

    return new Response(JSON.stringify({ user }), {
      status: 200,
      headers: {
        ...headers,
        'Set-Cookie': `session=${token}; Path=/; HttpOnly; Secure; SameSite=None`
      },
    });
  }

  // /me
  if (pathname === '/me' && method === 'GET') {
    console.log('🦊 ME handleAuth → GET /me hit');
    const cookie = request.headers.get('Cookie') || '';
    const m = cookie.match(/session=([^;]+)/);
    if (!m) return new Response(JSON.stringify({}), { status: 200, headers });

    const payload = await verifyJWT(m[1], env.SESSION_SECRET);
    if (!payload) {
      return new Response(JSON.stringify({}), {
        status: 200,
        headers: {
          ...headers,
          'Set-Cookie': `session=deleted; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None`,
        },
      });
    }

    const u = await env.DB.prepare('SELECT name, email, bio, profile_image_url FROM users WHERE id = ?')
      .bind(payload.sub)
      .first();

    if (!u) return new Response(JSON.stringify({}), { status: 200, headers });
    return new Response(JSON.stringify({ user: u }), { status: 200, headers });
  }

  // /logout
  if (pathname === '/logout' && method === 'POST') {
    console.log('🦊 handleAuth → POST /logout hit');
    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: {
        ...headers,
        'Set-Cookie': `session=deleted; Domain=.aibarf.com; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None`,
      },
    });
  }

  // /forgot-password
  if (pathname === '/forgot-password' && method === 'POST') {
    const { email } = await request.json();
    if (!email) {
      return new Response(JSON.stringify({ error: 'Missing email' }), { status: 400, headers });
    }

    const normalizedEmail = email.toLowerCase();
    const user = await env.DB.prepare('SELECT id,email FROM users WHERE email=?').bind(normalizedEmail).first();

    if (user) {
      const token = crypto.randomUUID();
      const expires = Date.now() + RESET_TOKEN_TTL;

      await env.DB.prepare('INSERT OR REPLACE INTO password_resets(user_id,token,expires) VALUES(?,?,?)')
        .bind(user.id, token, expires)
        .run();

      try {
        await sendResetEmail(env, user.email, token);
      } catch (err) {
        console.error('🔴 sendResetEmail error:', err);
        return new Response(
          JSON.stringify({ error: 'Email send failed: ' + err.message }),
          { status: 500, headers }
        );
      }
    }

    return new Response(JSON.stringify({ success: true }), { status: 200, headers });
  }

  // /reset-password
  if (pathname === '/reset-password' && method === 'POST') {
    const { token, password } = await request.json();
    if (!token || !password) {
      return new Response(JSON.stringify({ error: 'Missing token or password' }), { status: 400, headers });
    }

    const pwErrs = validatePassword(password);
    if (pwErrs.length) {
      return new Response(JSON.stringify({ error: pwErrs.join(', ') }), { status: 400, headers });
    }

    const row = await env.DB.prepare('SELECT user_id,expires FROM password_resets WHERE token=?')
      .bind(token)
      .first();

    if (!row || Date.now() > row.expires) {
      return new Response(JSON.stringify({ error: 'Invalid or expired token' }), { status: 400, headers });
    }

    const hash = await hashPassword(password);
    await env.DB.prepare('UPDATE password_logins SET password_hash=? WHERE user_id=?')
      .bind(hash, row.user_id)
      .run();

    await env.DB.prepare('DELETE FROM password_resets WHERE token=?').bind(token).run();

    return new Response(JSON.stringify({ success: true }), { status: 200, headers });
  }

  // If no auth route matched:
  return null;
}
