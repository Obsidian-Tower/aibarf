// src/index.js
// Cloudflare Worker with CORS, signup/login, cookie‑based JWT sessions, and /me + /logout

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// —————— JWT HS256 Helpers ——————
function base64url(str) {
  return btoa(str)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
async function signJWT(payload, secret) {
  const header = base64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body   = base64url(JSON.stringify(payload));
  const data   = `${header}.${body}`;
  const key    = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  const sig    = base64url(String.fromCharCode(...new Uint8Array(sigBuf)));
  return `${data}.${sig}`;
}
async function verifyJWT(token, secret) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [header, body, sig] = parts;
  const data = `${header}.${body}`;
  const key    = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  const sigBuf = Uint8Array.from(atob(sig.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
  const valid = await crypto.subtle.verify("HMAC", key, sigBuf, encoder.encode(data));
  if (!valid) return null;
  const payload = JSON.parse(atob(body.replace(/-/g, "+").replace(/_/g, "/")));
  if (payload.exp && Date.now() > payload.exp) return null;
  return payload;
}

// —————— Password Hashing ——————
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const pwBuf = encoder.encode(password);
  const salted = new Uint8Array([...salt, ...pwBuf]);
  const hashBuf = await crypto.subtle.digest("SHA-256", salted);
  const full = new Uint8Array([...salt, ...new Uint8Array(hashBuf)]);
  return btoa(String.fromCharCode(...full));
}
async function verifyPassword(password, storedHash) {
  const bin = atob(storedHash);
  const full = Uint8Array.from(bin, c => c.charCodeAt(0));
  const salt = full.slice(0,16), orig = full.slice(16);
  const pwBuf = encoder.encode(password);
  const test = new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array([...salt, ...pwBuf])));
  return orig.every((b,i) => b === test[i]);
}
function validatePassword(pw) {
  const errs = [];
  if (pw.length < 8) errs.push("At least 8 chars");
  if (!/[A-Za-z]/.test(pw)) errs.push("Must contain letters");
  if (!/[0-9]/.test(pw)) errs.push("Must contain a number");
  return errs;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname } = url;
    const headers = { "Content-Type": "application/json", ...CORS_HEADERS };

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    // —————— Username check ——————
    if (pathname === "/check-username" && request.method === "GET") {
      const name = url.searchParams.get("username");
      if (!name) return new Response(JSON.stringify({ error: "Missing username" }), { status:400, headers });
      const exists = await env.DB.prepare("SELECT id FROM users WHERE name=?").bind(name).first();
      return new Response(JSON.stringify({ available: !exists }), { headers });
    }

    // —————— Email check ——————
    if (pathname === "/check-email" && request.method === "GET") {
      const email = url.searchParams.get("email");
      if (!email) return new Response(JSON.stringify({ error: "Missing email" }), { status:400, headers });
      const exists = await env.DB.prepare("SELECT id FROM users WHERE email=?").bind(email.toLowerCase()).first();
      return new Response(JSON.stringify({ available: !exists }), { headers });
    }

    // —————— Signup ——————
    if (pathname === "/signup" && request.method === "POST") {
      const { name, email, password } = await request.json();
      if (!name||!email||!password) {
        return new Response(JSON.stringify({ error: "Missing fields" }), { status:400, headers });
      }
      const pwErrs = validatePassword(password);
      if (pwErrs.length) {
        return new Response(JSON.stringify({ error: pwErrs.join(", ") }), { status:400, headers });
      }
      const eExists = await env.DB.prepare("SELECT id FROM users WHERE email=?").bind(email).first();
      if (eExists) return new Response(JSON.stringify({ error:"Email in use" }), { status:409, headers });
      const nExists = await env.DB.prepare("SELECT id FROM users WHERE name=?").bind(name).first();
      if (nExists) return new Response(JSON.stringify({ error:"Username taken" }), { status:409, headers });

      const userId = crypto.randomUUID();
      const hash = await hashPassword(password);
      await env.DB.batch([
        env.DB.prepare("INSERT INTO users(id,email,name) VALUES(?,?,?)").bind(userId,email,name),
        env.DB.prepare("INSERT INTO password_logins(email,password_hash,user_id) VALUES(?,?,?)").bind(email,hash,userId),
        env.DB.prepare("INSERT INTO auth_providers(provider,provider_user_id,user_id) VALUES(?,?,?)").bind("email",email,userId)
      ]);
      return new Response(JSON.stringify({ success:true, userId }), { status:201, headers });
    }

    // —————— Login (issue session cookie) ——————
    if (pathname === "/login" && request.method === "POST") {
      const { email, password } = await request.json();
      if (!email||!password) return new Response(JSON.stringify({ error:"Missing credentials" }), { status:400, headers });

      const row = await env.DB.prepare(
        "SELECT password_hash,user_id FROM password_logins WHERE email=?"
      ).bind(email).first();
      if (!row||!(await verifyPassword(password, row.password_hash))) {
        return new Response(JSON.stringify({ error:"Invalid credentials" }), { status:401, headers });
      }

      // Create JWT (1 week expiry)
      const now = Date.now();
      const payload = { sub: row.user_id, exp: now + 1000*60*60*24*7 };
      const token = await signJWT(payload, env.SESSION_SECRET);

      // Fetch user info
      const user = await env.DB.prepare("SELECT name,email FROM users WHERE id=?")
        .bind(row.user_id).first();

      return new Response(JSON.stringify({ user }), {
        status: 200,
        headers: {
          ...headers,
          "Set-Cookie": `session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax`
        }
      });
    }

    // —————— /me (who am I?) ——————
    if (pathname === "/me" && request.method === "GET") {
      const cookie = request.headers.get("Cookie") || "";
      const m = cookie.match(/session=([^;]+)/);
      if (!m) return new Response(JSON.stringify({}), { status:200, headers });
      const payload = await verifyJWT(m[1], env.SESSION_SECRET);
      if (!payload) {
        // clear bad cookie
        return new Response(JSON.stringify({}), {
          status:200,
          headers: {
            ...headers,
            "Set-Cookie": `session=deleted; Path=/; Max-Age=0; HttpOnly`
          }
        });
      }
      const u = await env.DB.prepare("SELECT name,email FROM users WHERE id=?")
        .bind(payload.sub).first();
      if (!u) return new Response(JSON.stringify({}), { status:200, headers });
      return new Response(JSON.stringify({ user: u }), { status:200, headers });
    }

    // —————— Logout (clear cookie) ——————
    if (pathname === "/logout" && request.method === "POST") {
      return new Response(JSON.stringify({ success:true }), {
        status:200,
        headers: {
          ...headers,
          "Set-Cookie": `session=deleted; Path=/; Max-Age=0; HttpOnly`
        }
      });
    }

    // —————— Fallback 404 ——————
    return new Response(JSON.stringify({ error: "Not found" }), {
      status: 404,
      headers: { "Content-Type": "application/json", ...CORS_HEADERS }
    });
  }
};
