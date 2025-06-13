// src/index.js
const encoder = new TextEncoder();
// Cloudflare Worker with CORS, signup/login, cookie‑based JWT sessions, /me + /logout
// —————— Base64‑URL helpers ——————
function base64url(str) {
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function base64urlDecode(b64url) {
  let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  return atob(b64);
}

// —————— JWT HS256 Helpers ——————
async function signJWT(payload, secret) {
  const header = base64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  if (payload.exp && payload.exp > 1e12) {
    payload.exp = Math.floor(payload.exp / 1000);
  }
  const body = base64url(JSON.stringify(payload));
  const data = `${header}.${body}`;
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  const sig = base64url(String.fromCharCode(...new Uint8Array(sigBuf)));
  return `${data}.${sig}`;
}

async function verifyJWT(token, secret) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [header, body, sig] = parts;
  const data = `${header}.${body}`;
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const sigBuf = Uint8Array.from(base64urlDecode(sig), (c) => c.charCodeAt(0));
  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    sigBuf,
    encoder.encode(data)
  );
  if (!valid) return null;

  const payload = JSON.parse(base64urlDecode(body));
  const nowSec = Math.floor(Date.now() / 1000);
  if (payload.exp && nowSec > payload.exp) return null;
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
  const full = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  const salt = full.slice(0, 16),
    orig = full.slice(16);
  const pwBuf = encoder.encode(password);
  const testBuf = await crypto.subtle.digest(
    "SHA-256",
    new Uint8Array([...salt, ...pwBuf])
  );
  const test = new Uint8Array(testBuf);
  return orig.every((b, i) => b === test[i]);
}

function validatePassword(pw) {
  const errs = [];
  if (pw.length < 8) errs.push("At least 8 chars");
  if (!/[A-Za-z]/.test(pw)) errs.push("Must contain letters");
  if (!/[0-9]/.test(pw)) errs.push("Must contain a number");
  return errs;
}

// ─────────── Email Templates ───────────
const RESET_EMAIL_HTML = `<!DOCTYPE html>
<html>
  <head><meta charset="UTF-8"/><title>Password Reset</title></head>
  <body style="font-family:Arial,sans-serif;background:#f4f4f4;margin:0;padding:0">
    <div style="max-width:600px;margin:2rem auto;background:#fff;padding:1.5rem;border-radius:8px">
      <h1 style="color:#333">Password Reset Request</h1>
      <p>We got a request to reset your aibarf.com password. Click below:</p>
      <p style="text-align:center">
        <a href="{{RESET_LINK}}" 
           style="display:inline-block;padding:.75rem 1.5rem;
                  background:#2b7dfc;color:#fff;text-decoration:none;
                  border-radius:4px;font-weight:bold">
          Reset My Password
        </a>
      </p>
      <p>If that button fails, copy & paste:</p>
      <p><a href="{{RESET_LINK}}">{{RESET_LINK}}</a></p>
      <p>If you didn’t ask, ignore this email.</p>
      <p style="font-size:.8rem;color:#999;text-align:center;margin-top:2rem">
        &copy; 2025 aibarf LLC
      </p>
    </div>
  </body>
</html>`;

// ─── Password reset token TTL (1 hour) ───
const RESET_TOKEN_TTL = 1000 * 60 * 60;

const RESET_EMAIL_TEXT = `Password Reset Request

We got a request to reset your aibarf.com password.

Reset link: {{RESET_LINK}}

If you didn’t ask, you can ignore this email.

© 2025 aibarf LLC
`;
// ────────────────────────────────────────
// ─── sendResetEmail via Mailgun ───
async function sendResetEmail(env, toEmail, token) {
  const resetLink = `https://aibarf.com/reset-password.html?token=${token}`;
  const htmlBody = RESET_EMAIL_HTML.replace(/{{RESET_LINK}}/g, resetLink);
  const textBody = RESET_EMAIL_TEXT.replace(/{{RESET_LINK}}/g, resetLink);
  const auth = btoa(`api:${env.MAILGUN_API_KEY}`);

  const res = await fetch("https://api.mailgun.net/v3/mg.aibarf.com/messages", {
    method: "POST",
    headers: {
      Authorization: `Basic ${auth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      from: "no-reply@mg.aibarf.com",
      to: toEmail,
      subject: "Reset your aibarf.com password",
      text: textBody,
      html: htmlBody,
    }),
  });
  if (!res.ok) throw new Error("Mailgun failed: " + (await res.text()));
}

const ALLOWED = [
  "https://aibarf.com",
  "https://www.aibarf.com",
  "https://aibarf-auth.coryzuber.workers.dev",
];

function getCorsHeaders(request) {
  // Echo back the request’s Origin, or wildcard if none
  const origin = request.headers.get("Origin") || "*";
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname, origin } = url;
    const CORS = getCorsHeaders(request);

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS });
    }

    // JSON response headers
    const headers = { "Content-Type": "application/json", ...CORS };

    // —————— Serve R2 images via Worker proxy ——————
    if (pathname.startsWith("/images/sets/") && request.method === "GET") {
      // URL: /images/sets/{setId}/{fileName}
      const [, , , setId, fileName] = pathname.split("/");
      const key = `sets/${setId}/${fileName}`;
      const obj = await env.USER_IMAGES.get(key);
      if (!obj || !obj.body) {
        return new Response("Not found", { status: 404 });
      }
      return new Response(obj.body, {
        status: 200,
        headers: {
          "Content-Type": obj.httpMetadata.contentType,
          "Cache-Control": "public, max-age=31536000",
        },
      });
    }

    // —————— Serve Assets via Worker proxy ——————
    if (pathname.startsWith("/assets/images/") && request.method === "GET") {
      const key = pathname.slice(1); // removes the leading slash
      const obj = await env.USER_IMAGES.get(key);
      if (!obj || !obj.body) {
        return new Response("Not found", { status: 404 });
      }
      return new Response(obj.body, {
        status: 200,
        headers: {
          "Content-Type": obj.httpMetadata.contentType,
          "Cache-Control": "public, max-age=31536000",
        },
      });
    }

    // —————— Admin Upload (Password Protected) ——————
    if (pathname === "/admin/upload" && request.method === "POST") {
      const headers = { "Content-Type": "application/json", ...CORS };
      const contentType = request.headers.get("content-type") || "";

      if (!contentType.includes("multipart/form-data")) {
        return new Response(JSON.stringify({ message: "Invalid content type" }), {
          status: 400,
          headers,
        });
      }

      try {
        const formData = await request.formData();
        const password = formData.get("password");
        const file = formData.get("file");
        const filePath = formData.get("filePath");

        if (password !== "spacecat") {
          return new Response(JSON.stringify({ message: "Unauthorized: Invalid password" }), {
            status: 403,
            headers,
          });
        }

        if (!file || !filePath) {
          return new Response(JSON.stringify({ message: "Missing file or filePath" }), {
            status: 400,
            headers,
          });
        }

        const arrayBuffer = await file.arrayBuffer();
        await env.USER_IMAGES.put(filePath, arrayBuffer, {
          httpMetadata: { contentType: file.type },
        });

        return new Response(JSON.stringify({ message: `File uploaded to ${filePath}` }), {
          status: 200,
          headers,
        });
      } catch (err) {
        console.error("Admin upload error:", err);
        return new Response(JSON.stringify({ message: "Upload error" }), {
          status: 500,
          headers,
        });
      }
    }


    // —————— Username check ——————
    if (pathname === "/check-username" && request.method === "GET") {
      const name = url.searchParams.get("username");
      if (!name) {
        return new Response(JSON.stringify({ error: "Missing username" }), {
          status: 400,
          headers,
        });
      }
      const exists = await env.DB.prepare("SELECT id FROM users WHERE name=?")
        .bind(name)
        .first();
      return new Response(JSON.stringify({ available: !exists }), { headers });
    }

    // —————— Email check ——————
    if (pathname === "/check-email" && request.method === "GET") {
      const email = url.searchParams.get("email");
      if (!email) {
        return new Response(JSON.stringify({ error: "Missing email" }), {
          status: 400,
          headers,
        });
      }
      const exists = await env.DB.prepare("SELECT id FROM users WHERE email=?")
        .bind(email.toLowerCase())
        .first();
      return new Response(JSON.stringify({ available: !exists }), { headers });
    }

    // —————— Signup ——————
    if (pathname === "/signup" && request.method === "POST") {
      const { name, email, password } = await request.json();
      if (!name || !email || !password) {
        return new Response(JSON.stringify({ error: "Missing fields" }), {
          status: 400,
          headers,
        });
      }
      const pwErrs = validatePassword(password);
      if (pwErrs.length) {
        return new Response(JSON.stringify({ error: pwErrs.join(", ") }), {
          status: 400,
          headers,
        });
      }
      const normalizedEmail = email.toLowerCase();
      const eExists = await env.DB.prepare("SELECT id FROM users WHERE email=?")
        .bind(normalizedEmail)
        .first();
      if (eExists) {
        return new Response(JSON.stringify({ error: "Email in use" }), {
          status: 409,
          headers,
        });
      }
      const nExists = await env.DB.prepare("SELECT id FROM users WHERE name=?")
        .bind(name)
        .first();
      if (nExists) {
        return new Response(JSON.stringify({ error: "Username taken" }), {
          status: 409,
          headers,
        });
      }

      const userId = crypto.randomUUID();
      const hash = await hashPassword(password);
      await env.DB.batch([
        env.DB.prepare("INSERT INTO users(id,email,name,profile_image_url) VALUES(?,?,?,?)").bind(
          userId,
          normalizedEmail,
          name,
          'https://aibarf-auth.coryzuber.workers.dev/assets/images/initial-profile-image-v1.png'
        ),
        env.DB.prepare(
          "INSERT INTO password_logins(email,password_hash,user_id) VALUES(?,?,?)"
        ).bind(normalizedEmail, hash, userId),
        env.DB.prepare(
          "INSERT INTO auth_providers(provider,provider_user_id,user_id) VALUES(?,?,?)"
        ).bind("email", normalizedEmail, userId),
      ]);

      return new Response(JSON.stringify({ success: true, userId }), {
        status: 201,
        headers,
      });
    }

    // —————— Login (issue session cookie) ——————
    if (pathname === "/login" && request.method === "POST") {
      let { email, password } = await request.json();
      if (!email || !password) {
        return new Response(JSON.stringify({ error: "Missing credentials" }), {
          status: 400,
          headers,
        });
      }
      email = email.toLowerCase();
      const row = await env.DB.prepare(
        "SELECT password_hash,user_id FROM password_logins WHERE email=?"
      )
        .bind(email)
        .first();
      if (!row || !(await verifyPassword(password, row.password_hash))) {
        return new Response(JSON.stringify({ error: "Invalid credentials" }), {
          status: 401,
          headers,
        });
      }

      // Issue JWT (1 week expiry, exp in seconds)
      const nowSec = Math.floor(Date.now() / 1000);
      const payload = { sub: row.user_id, exp: nowSec + 60 * 60 * 24 * 7 };
      const token = await signJWT(payload, env.SESSION_SECRET);

      // Fetch user info
      const user = await env.DB.prepare(
        "SELECT name,email FROM users WHERE id=?"
      )
        .bind(row.user_id)
        .first();

      return new Response(JSON.stringify({ user }), {
        status: 200,
        headers: {
          ...headers,
          "Set-Cookie": `session=${token}; Domain=.coryzuber.workers.dev; Path=/; HttpOnly; Secure; SameSite=None`,
        },
      });
    }

    // ────────── /me (who am I?) ──────────
    if (pathname === "/me" && request.method === "GET") {
      const cookie = request.headers.get("Cookie") || "";
      const m = cookie.match(/session=([^;]+)/);
      if (!m) return new Response(JSON.stringify({}), { status: 200, headers });

      const payload = await verifyJWT(m[1], env.SESSION_SECRET);
      if (!payload) {
        return new Response(JSON.stringify({}), {
          status: 200,
          headers: {
            ...headers,
            "Set-Cookie": `session=deleted; Domain=.coryzuber.workers.dev; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None`,
          },
        });
      }

      // INCLUDE bio in the SELECT
      const u = await env.DB.prepare(
        "SELECT name, email, bio, profile_image_url FROM users WHERE id = ?"
      )
        .bind(payload.sub)
        .first();
      if (!u) return new Response(JSON.stringify({}), { status: 200, headers });
      return new Response(JSON.stringify({ user: u }), {
        status: 200,
        headers,
      });
    }

    // ───────── Serve Profile Images via Worker proxy ─────────
    if (pathname.startsWith("/images/profile-images/") && request.method === "GET") {
      // URL: /images/profile-images/{fileName}
      const [, , , fileName] = pathname.split("/");
      const key = `profile-images/${fileName}`;
      const obj = await env.USER_IMAGES.get(key);
      if (!obj || !obj.body) {
        return new Response("Not found", { status: 404 });
      }
      return new Response(obj.body, {
        status: 200,
        headers: {
          "Content-Type": obj.httpMetadata.contentType,
          "Cache-Control": "public, max-age=31536000",
        },
      });
    }

    // —————— Logout (clear cookie) ——————
    if (pathname === "/logout" && request.method === "POST") {
      return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: {
          ...headers,
          "Set-Cookie": `session=deleted; Domain=.coryzuber.workers.dev; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None`,
        },
      });
    }

    // —————— Forgot‑password ——————
    if (pathname === "/forgot-password" && request.method === "POST") {
      const { email } = await request.json();
      if (!email) {
        return new Response(JSON.stringify({ error: "Missing email" }), {
          status: 400,
          headers,
        });
      }

      const normalizedEmail = email.toLowerCase();
      // Lookup user by email
      const user = await env.DB.prepare(
        "SELECT id,email FROM users WHERE email=?"
      )
        .bind(normalizedEmail)
        .first();

      if (user) {
        // Generate a one‑time token and expiration
        const token = crypto.randomUUID();
        const expires = Date.now() + RESET_TOKEN_TTL;

        // Store it (creates or replaces existing)
        await env.DB.prepare(
          "INSERT OR REPLACE INTO password_resets(user_id,token,expires) VALUES(?,?,?)"
        )
          .bind(user.id, token, expires)
          .run();

        // Fire-and-forget the email send
        try {
          await sendResetEmail(env, user.email, token);
        } catch (err) {
          console.error("🔴 sendResetEmail error:", err);
          return new Response(
            JSON.stringify({ error: "Email send failed: " + err.message }),
            { status: 500, headers }
          );
        }
      }

      // Always return success (prevents email enumeration)
      return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers,
      });
    }

    // —————— Reset‑password ——————
    if (pathname === "/reset-password" && request.method === "POST") {
      const { token, password } = await request.json();
      if (!token || !password) {
        return new Response(
          JSON.stringify({ error: "Missing token or password" }),
          { status: 400, headers }
        );
      }

      // Enforce your existing strength rules
      const pwErrs = validatePassword(password);
      if (pwErrs.length) {
        return new Response(JSON.stringify({ error: pwErrs.join(", ") }), {
          status: 400,
          headers,
        });
      }

      // Look up the token and check expiration
      const row = await env.DB.prepare(
        "SELECT user_id,expires FROM password_resets WHERE token=?"
      )
        .bind(token)
        .first();

      if (!row || Date.now() > row.expires) {
        return new Response(
          JSON.stringify({ error: "Invalid or expired token" }),
          { status: 400, headers }
        );
      }

      // Hash the new password and update the login row
      const hash = await hashPassword(password);
      await env.DB.prepare(
        "UPDATE password_logins SET password_hash=? WHERE user_id=?"
      )
        .bind(hash, row.user_id)
        .run();

      // Delete the used token so it can’t be reused
      await env.DB.prepare("DELETE FROM password_resets WHERE token=?")
        .bind(token)
        .run();

      return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers,
      });
    }

    // —————— Create a new image Set ——————
    if (pathname === "/sets" && request.method === "POST") {
      // 1️⃣ authenticate
      const cookie = request.headers.get("Cookie") || "";
      const m = cookie.match(/session=([^;]+)/);
      const payload = m && (await verifyJWT(m[1], env.SESSION_SECRET));
      if (!payload) {
        return new Response(JSON.stringify({ error: "Not authenticated" }), {
          status: 401,
          headers,
        });
      }
      const userId = payload.sub;

      // 2️⃣ parse formData
      const form = await request.formData();
      const title = form.get("title");
      const description = form.get("description");
      const level = form.get("level");
      const files = form.getAll("images");
      if (!title || !description || files.length < 3) {
        return new Response(
          JSON.stringify({
            error: "Missing title/description or too few images",
          }),
          { status: 400, headers }
        );
      }

      // 3️⃣ insert into sets
      const setId = crypto.randomUUID();
      const now = Date.now();
      await env.DB.prepare(
        `
        INSERT INTO sets
          (id, title, description, level, created_at, created_by)
        VALUES (?, ?, ?, ?, ?, ?)
      `
      )
        .bind(setId, title, description, Number(level), now, userId)
        .run();

      // 4️⃣ upload + record only file_name
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const ext = file.name.split(".").pop().toLowerCase();
        const fileName = `${i + 1}.${ext}`;
        const key = `sets/${setId}/${fileName}`;

        await env.USER_IMAGES.put(key, await file.arrayBuffer(), {
          httpMetadata: { contentType: file.type },
        });

        await env.DB.prepare(
          `
          INSERT INTO images
            (id, set_id, file_name, created_at)
          VALUES (?, ?, ?, ?)
        `
        )
          .bind(crypto.randomUUID(), setId, fileName, now)
          .run();
      }

      return new Response(JSON.stringify({ id: setId }), {
        status: 201,
        headers,
      });
    }

    // —————— Public sets (only level 1–5) ——————
    if (pathname === "/public-sets" && request.method === "GET") {
      try {
        const rows = await env.DB.prepare(
          `
          SELECT
            s.id,
            s.title,
            s.level,
            u.name AS username,
            (
              SELECT file_name
              FROM images
              WHERE set_id = s.id
              ORDER BY created_at
              LIMIT 1
            ) AS firstFile,
            (
              SELECT COUNT(*)
              FROM images
              WHERE set_id = s.id
            ) AS imageCount
          FROM sets AS s
          LEFT JOIN users AS u ON u.id = s.created_by
          WHERE s.level BETWEEN 1 AND 5
          ORDER BY s.created_at DESC
        `
        ).all();

        const sets = rows.results.map(
          ({ id, title, level, username, firstFile, imageCount }) => ({
            id,
            title,
            level,
            createdBy: username || "Anonymous",
            imageCount,
            mainImageUrl: `${origin}/images/sets/${id}/${firstFile}`,
          })
        );

        return new Response(JSON.stringify({ sets }), {
          status: 200,
          headers,
        });
      } catch (err) {
        console.error("DB error in /public-sets:", err.message);
        return new Response("Internal Server Error", { status: 500 });
      }
    }

    // Updated GET /set handler with creator username
    if (
      (pathname === "/set" || pathname === "/set.html") &&
      request.method === "GET"
    ) {
      const setId = url.searchParams.get("id");
      if (!setId) {
        return new Response(JSON.stringify({ error: "Missing set ID" }), {
          status: 400,
          headers,
        });
      }

      const setRow = await env.DB.prepare(
        `
    SELECT s.id, s.title, s.description, s.level, s.created_at, s.created_by, u.name AS createdBy
    FROM sets AS s
    LEFT JOIN users AS u ON s.created_by = u.id
    WHERE s.id = ?
  `
      )
        .bind(setId)
        .first();

      if (!setRow) {
        return new Response(JSON.stringify({ error: "Not found" }), {
          status: 404,
          headers,
        });
      }

      if (setRow.level > 5 || setRow.level === 0) {
        const cookie = request.headers.get("Cookie") || "";
        const m = cookie.match(/session=([^;]+)/);
        const payload = m && (await verifyJWT(m[1], env.SESSION_SECRET));
        if (!payload) {
          return new Response(JSON.stringify({ error: "Forbidden" }), {
            status: 403,
            headers,
          });
        }
      }

      const imgs = await env.DB.prepare(
        `
    SELECT file_name FROM images WHERE set_id = ? ORDER BY created_at
  `
      )
        .bind(setId)
        .all();

      const fileNames = imgs.results.map((r) => r.file_name);

      return new Response(
        JSON.stringify({
          id: setRow.id,
          title: setRow.title,
          description: setRow.description,
          level: setRow.level,
          created_at: setRow.created_at,
          createdBy: setRow.createdBy || "Anonymous",
          images: fileNames,
        }),
        {
          status: 200,
          headers,
        }
      );
    }

    // —————— Update Profile (Enhanced) ——————
    if (pathname === "/update-profile" && request.method === "POST") {
      const cookie = request.headers.get("Cookie") || "";
      const m = cookie.match(/session=([^;]+)/);
      const payload = m && (await verifyJWT(m[1], env.SESSION_SECRET));
      if (!payload) {
        return new Response(JSON.stringify({ error: "Not authenticated" }), {
          status: 401,
          headers,
        });
      }

      const userId = payload.sub;
      const form = await request.formData();
      const username = form.get("username");
      const bio = form.get("bio");
      const profileImage = form.get("profileImage");

      // ——— Validate text fields ———
      if (username && username.length > 50) {
        return new Response(JSON.stringify({ error: "Username too long" }), { status: 400, headers });
      }
      if (bio && bio.length > 500) {
        return new Response(JSON.stringify({ error: "Bio too long" }), { status: 400, headers });
      }

      // ——— Validate profile image ———
      let profileImageUrl = null;
      if (profileImage && profileImage.name) {
        const allowedTypes = ["image/jpeg", "image/png", "image/webp"];
        const maxSize = 2 * 1024 * 1024; // 2 MB

        if (!allowedTypes.includes(profileImage.type)) {
          return new Response(JSON.stringify({ error: "Unsupported image type" }), { status: 400, headers });
        }

        const ext = profileImage.name.split(".").pop().toLowerCase();
        if (!["jpg", "jpeg", "png", "webp"].includes(ext)) {
          return new Response(JSON.stringify({ error: "Unsupported file extension" }), { status: 400, headers });
        }

        if (profileImage.size > maxSize) {
          return new Response(JSON.stringify({ error: "Image too large (2MB max)" }), { status: 400, headers });
        }

        const key = `profile-images/${userId}.${ext}`;
        await env.USER_IMAGES.put(key, await profileImage.arrayBuffer(), {
          httpMetadata: { contentType: profileImage.type },
        });

        profileImageUrl = `${origin}/images/${key}`;
      }

      // ——— Update user record ———
      const parts = [];
      const binds = [];

      if (username) { parts.push("name = ?"); binds.push(username); }
      if (bio) { parts.push("bio = ?"); binds.push(bio); }
      if (profileImageUrl) { parts.push("profile_image_url = ?"); binds.push(profileImageUrl); }

      if (parts.length > 0) {
        binds.push(userId);
        await env.DB.prepare(`UPDATE users SET ${parts.join(", ")} WHERE id = ?`).bind(...binds).run();
      }

      return new Response(JSON.stringify({ success: true }), { headers });
    }

    // —————— Fallback 404 ——————
    return new Response(JSON.stringify({ error: "Not found" }), {
      status: 404,
      headers,
    });
  },
};
// src/index.js
const encoder = new TextEncoder();
// Cloudflare Worker with CORS, signup/login, cookie‑based JWT sessions, /me + /logout
// —————— Base64‑URL helpers ——————
function base64url(str) {
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function base64urlDecode(b64url) {
  let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  return atob(b64);
}

// —————— JWT HS256 Helpers ——————
async function signJWT(payload, secret) {
  const header = base64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  if (payload.exp && payload.exp > 1e12) {
    payload.exp = Math.floor(payload.exp / 1000);
  }
  const body = base64url(JSON.stringify(payload));
  const data = `${header}.${body}`;
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  const sig = base64url(String.fromCharCode(...new Uint8Array(sigBuf)));
  return `${data}.${sig}`;
}

async function verifyJWT(token, secret) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [header, body, sig] = parts;
  const data = `${header}.${body}`;
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const sigBuf = Uint8Array.from(base64urlDecode(sig), (c) => c.charCodeAt(0));
  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    sigBuf,
    encoder.encode(data)
  );
  if (!valid) return null;

  const payload = JSON.parse(base64urlDecode(body));
  const nowSec = Math.floor(Date.now() / 1000);
  if (payload.exp && nowSec > payload.exp) return null;
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
  const full = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  const salt = full.slice(0, 16),
    orig = full.slice(16);
  const pwBuf = encoder.encode(password);
  const testBuf = await crypto.subtle.digest(
    "SHA-256",
    new Uint8Array([...salt, ...pwBuf])
  );
  const test = new Uint8Array(testBuf);
  return orig.every((b, i) => b === test[i]);
}

function validatePassword(pw) {
  const errs = [];
  if (pw.length < 8) errs.push("At least 8 chars");
  if (!/[A-Za-z]/.test(pw)) errs.push("Must contain letters");
  if (!/[0-9]/.test(pw)) errs.push("Must contain a number");
  return errs;
}

// ─────────── Email Templates ───────────
const RESET_EMAIL_HTML = `<!DOCTYPE html>
<html>
  <head><meta charset="UTF-8"/><title>Password Reset</title></head>
  <body style="font-family:Arial,sans-serif;background:#f4f4f4;margin:0;padding:0">
    <div style="max-width:600px;margin:2rem auto;background:#fff;padding:1.5rem;border-radius:8px">
      <h1 style="color:#333">Password Reset Request</h1>
      <p>We got a request to reset your aibarf.com password. Click below:</p>
      <p style="text-align:center">
        <a href="{{RESET_LINK}}" 
           style="display:inline-block;padding:.75rem 1.5rem;
                  background:#2b7dfc;color:#fff;text-decoration:none;
                  border-radius:4px;font-weight:bold">
          Reset My Password
        </a>
      </p>
      <p>If that button fails, copy & paste:</p>
      <p><a href="{{RESET_LINK}}">{{RESET_LINK}}</a></p>
      <p>If you didn’t ask, ignore this email.</p>
      <p style="font-size:.8rem;color:#999;text-align:center;margin-top:2rem">
        &copy; 2025 aibarf LLC
      </p>
    </div>
  </body>
</html>`;

// ─── Password reset token TTL (1 hour) ───
const RESET_TOKEN_TTL = 1000 * 60 * 60;

const RESET_EMAIL_TEXT = `Password Reset Request

We got a request to reset your aibarf.com password.

Reset link: {{RESET_LINK}}

If you didn’t ask, you can ignore this email.

© 2025 aibarf LLC
`;
// ────────────────────────────────────────
// ─── sendResetEmail via Mailgun ───
async function sendResetEmail(env, toEmail, token) {
  const resetLink = `https://aibarf.com/reset-password.html?token=${token}`;
  const htmlBody = RESET_EMAIL_HTML.replace(/{{RESET_LINK}}/g, resetLink);
  const textBody = RESET_EMAIL_TEXT.replace(/{{RESET_LINK}}/g, resetLink);
  const auth = btoa(`api:${env.MAILGUN_API_KEY}`);

  const res = await fetch("https://api.mailgun.net/v3/mg.aibarf.com/messages", {
    method: "POST",
    headers: {
      Authorization: `Basic ${auth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      from: "no-reply@mg.aibarf.com",
      to: toEmail,
      subject: "Reset your aibarf.com password",
      text: textBody,
      html: htmlBody,
    }),
  });
  if (!res.ok) throw new Error("Mailgun failed: " + (await res.text()));
}

const ALLOWED = [
  "https://aibarf.com",
  "https://www.aibarf.com",
  "https://aibarf-auth.coryzuber.workers.dev",
];

function getCorsHeaders(request) {
  // Echo back the request’s Origin, or wildcard if none
  const origin = request.headers.get("Origin") || "*";
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname, origin } = url;
    const CORS = getCorsHeaders(request);

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS });
    }

    // JSON response headers
    const headers = { "Content-Type": "application/json", ...CORS };

    // —————— Serve R2 images via Worker proxy ——————
    if (pathname.startsWith("/images/sets/") && request.method === "GET") {
      // URL: /images/sets/{setId}/{fileName}
      const [, , , setId, fileName] = pathname.split("/");
      const key = `sets/${setId}/${fileName}`;
      const obj = await env.USER_IMAGES.get(key);
      if (!obj || !obj.body) {
        return new Response("Not found", { status: 404 });
      }
      return new Response(obj.body, {
        status: 200,
        headers: {
          "Content-Type": obj.httpMetadata.contentType,
          "Cache-Control": "public, max-age=31536000",
        },
      });
    }

    // —————— Serve Assets via Worker proxy ——————
    if (pathname.startsWith("/assets/images/") && request.method === "GET") {
      const key = pathname.slice(1); // removes the leading slash
      const obj = await env.USER_IMAGES.get(key);
      if (!obj || !obj.body) {
        return new Response("Not found", { status: 404 });
      }
      return new Response(obj.body, {
        status: 200,
        headers: {
          "Content-Type": obj.httpMetadata.contentType,
          "Cache-Control": "public, max-age=31536000",
        },
      });
    }

    // —————— Admin Upload (Password Protected) ——————
    if (pathname === "/admin/upload" && request.method === "POST") {
      const headers = { "Content-Type": "application/json", ...CORS };
      const contentType = request.headers.get("content-type") || "";

      if (!contentType.includes("multipart/form-data")) {
        return new Response(JSON.stringify({ message: "Invalid content type" }), {
          status: 400,
          headers,
        });
      }

      try {
        const formData = await request.formData();
        const password = formData.get("password");
        const file = formData.get("file");
        const filePath = formData.get("filePath");

        if (password !== "spacecat") {
          return new Response(JSON.stringify({ message: "Unauthorized: Invalid password" }), {
            status: 403,
            headers,
          });
        }

        if (!file || !filePath) {
          return new Response(JSON.stringify({ message: "Missing file or filePath" }), {
            status: 400,
            headers,
          });
        }

        const arrayBuffer = await file.arrayBuffer();
        await env.USER_IMAGES.put(filePath, arrayBuffer, {
          httpMetadata: { contentType: file.type },
        });

        return new Response(JSON.stringify({ message: `File uploaded to ${filePath}` }), {
          status: 200,
          headers,
        });
      } catch (err) {
        console.error("Admin upload error:", err);
        return new Response(JSON.stringify({ message: "Upload error" }), {
          status: 500,
          headers,
        });
      }
    }


    // —————— Username check ——————
    if (pathname === "/check-username" && request.method === "GET") {
      const name = url.searchParams.get("username");
      if (!name) {
        return new Response(JSON.stringify({ error: "Missing username" }), {
          status: 400,
          headers,
        });
      }
      const exists = await env.DB.prepare("SELECT id FROM users WHERE name=?")
        .bind(name)
        .first();
      return new Response(JSON.stringify({ available: !exists }), { headers });
    }

    // —————— Email check ——————
    if (pathname === "/check-email" && request.method === "GET") {
      const email = url.searchParams.get("email");
      if (!email) {
        return new Response(JSON.stringify({ error: "Missing email" }), {
          status: 400,
          headers,
        });
      }
      const exists = await env.DB.prepare("SELECT id FROM users WHERE email=?")
        .bind(email.toLowerCase())
        .first();
      return new Response(JSON.stringify({ available: !exists }), { headers });
    }

    // —————— Signup ——————
    if (pathname === "/signup" && request.method === "POST") {
      const { name, email, password } = await request.json();
      if (!name || !email || !password) {
        return new Response(JSON.stringify({ error: "Missing fields" }), {
          status: 400,
          headers,
        });
      }
      const pwErrs = validatePassword(password);
      if (pwErrs.length) {
        return new Response(JSON.stringify({ error: pwErrs.join(", ") }), {
          status: 400,
          headers,
        });
      }
      const normalizedEmail = email.toLowerCase();
      const eExists = await env.DB.prepare("SELECT id FROM users WHERE email=?")
        .bind(normalizedEmail)
        .first();
      if (eExists) {
        return new Response(JSON.stringify({ error: "Email in use" }), {
          status: 409,
          headers,
        });
      }
      const nExists = await env.DB.prepare("SELECT id FROM users WHERE name=?")
        .bind(name)
        .first();
      if (nExists) {
        return new Response(JSON.stringify({ error: "Username taken" }), {
          status: 409,
          headers,
        });
      }

      const userId = crypto.randomUUID();
      const hash = await hashPassword(password);
      await env.DB.batch([
        env.DB.prepare("INSERT INTO users(id,email,name,profile_image_url) VALUES(?,?,?,?)").bind(
          userId,
          normalizedEmail,
          name,
          'https://aibarf-auth.coryzuber.workers.dev/assets/images/initial-profile-image-v1.png'
        ),
        env.DB.prepare(
          "INSERT INTO password_logins(email,password_hash,user_id) VALUES(?,?,?)"
        ).bind(normalizedEmail, hash, userId),
        env.DB.prepare(
          "INSERT INTO auth_providers(provider,provider_user_id,user_id) VALUES(?,?,?)"
        ).bind("email", normalizedEmail, userId),
      ]);

      return new Response(JSON.stringify({ success: true, userId }), {
        status: 201,
        headers,
      });
    }

    // —————— Login (issue session cookie) ——————
    if (pathname === "/login" && request.method === "POST") {
      let { email, password } = await request.json();
      if (!email || !password) {
        return new Response(JSON.stringify({ error: "Missing credentials" }), {
          status: 400,
          headers,
        });
      }
      email = email.toLowerCase();
      const row = await env.DB.prepare(
        "SELECT password_hash,user_id FROM password_logins WHERE email=?"
      )
        .bind(email)
        .first();
      if (!row || !(await verifyPassword(password, row.password_hash))) {
        return new Response(JSON.stringify({ error: "Invalid credentials" }), {
          status: 401,
          headers,
        });
      }

      // Issue JWT (1 week expiry, exp in seconds)
      const nowSec = Math.floor(Date.now() / 1000);
      const payload = { sub: row.user_id, exp: nowSec + 60 * 60 * 24 * 7 };
      const token = await signJWT(payload, env.SESSION_SECRET);

      // Fetch user info
      const user = await env.DB.prepare(
        "SELECT name,email FROM users WHERE id=?"
      )
        .bind(row.user_id)
        .first();

      return new Response(JSON.stringify({ user }), {
        status: 200,
        headers: {
          ...headers,
          "Set-Cookie": `session=${token}; Domain=.coryzuber.workers.dev; Path=/; HttpOnly; Secure; SameSite=None`,
        },
      });
    }

    // ────────── /me (who am I?) ──────────
    if (pathname === "/me" && request.method === "GET") {
      const cookie = request.headers.get("Cookie") || "";
      const m = cookie.match(/session=([^;]+)/);
      if (!m) return new Response(JSON.stringify({}), { status: 200, headers });

      const payload = await verifyJWT(m[1], env.SESSION_SECRET);
      if (!payload) {
        return new Response(JSON.stringify({}), {
          status: 200,
          headers: {
            ...headers,
            "Set-Cookie": `session=deleted; Domain=.coryzuber.workers.dev; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None`,
          },
        });
      }

      // INCLUDE bio in the SELECT
      const u = await env.DB.prepare(
        "SELECT name, email, bio, profile_image_url FROM users WHERE id = ?"
      )
        .bind(payload.sub)
        .first();
      if (!u) return new Response(JSON.stringify({}), { status: 200, headers });
      return new Response(JSON.stringify({ user: u }), {
        status: 200,
        headers,
      });
    }

    // ───────── Serve Profile Images via Worker proxy ─────────
    if (pathname.startsWith("/images/profile-images/") && request.method === "GET") {
      // URL: /images/profile-images/{fileName}
      const [, , , fileName] = pathname.split("/");
      const key = `profile-images/${fileName}`;
      const obj = await env.USER_IMAGES.get(key);
      if (!obj || !obj.body) {
        return new Response("Not found", { status: 404 });
      }
      return new Response(obj.body, {
        status: 200,
        headers: {
          "Content-Type": obj.httpMetadata.contentType,
          "Cache-Control": "public, max-age=31536000",
        },
      });
    }

    // —————— Logout (clear cookie) ——————
    if (pathname === "/logout" && request.method === "POST") {
      return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: {
          ...headers,
          "Set-Cookie": `session=deleted; Domain=.coryzuber.workers.dev; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None`,
        },
      });
    }

    // —————— Forgot‑password ——————
    if (pathname === "/forgot-password" && request.method === "POST") {
      const { email } = await request.json();
      if (!email) {
        return new Response(JSON.stringify({ error: "Missing email" }), {
          status: 400,
          headers,
        });
      }

      const normalizedEmail = email.toLowerCase();
      // Lookup user by email
      const user = await env.DB.prepare(
        "SELECT id,email FROM users WHERE email=?"
      )
        .bind(normalizedEmail)
        .first();

      if (user) {
        // Generate a one‑time token and expiration
        const token = crypto.randomUUID();
        const expires = Date.now() + RESET_TOKEN_TTL;

        // Store it (creates or replaces existing)
        await env.DB.prepare(
          "INSERT OR REPLACE INTO password_resets(user_id,token,expires) VALUES(?,?,?)"
        )
          .bind(user.id, token, expires)
          .run();

        // Fire-and-forget the email send
        try {
          await sendResetEmail(env, user.email, token);
        } catch (err) {
          console.error("🔴 sendResetEmail error:", err);
          return new Response(
            JSON.stringify({ error: "Email send failed: " + err.message }),
            { status: 500, headers }
          );
        }
      }

      // Always return success (prevents email enumeration)
      return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers,
      });
    }

    // —————— Reset‑password ——————
    if (pathname === "/reset-password" && request.method === "POST") {
      const { token, password } = await request.json();
      if (!token || !password) {
        return new Response(
          JSON.stringify({ error: "Missing token or password" }),
          { status: 400, headers }
        );
      }

      // Enforce your existing strength rules
      const pwErrs = validatePassword(password);
      if (pwErrs.length) {
        return new Response(JSON.stringify({ error: pwErrs.join(", ") }), {
          status: 400,
          headers,
        });
      }

      // Look up the token and check expiration
      const row = await env.DB.prepare(
        "SELECT user_id,expires FROM password_resets WHERE token=?"
      )
        .bind(token)
        .first();

      if (!row || Date.now() > row.expires) {
        return new Response(
          JSON.stringify({ error: "Invalid or expired token" }),
          { status: 400, headers }
        );
      }

      // Hash the new password and update the login row
      const hash = await hashPassword(password);
      await env.DB.prepare(
        "UPDATE password_logins SET password_hash=? WHERE user_id=?"
      )
        .bind(hash, row.user_id)
        .run();

      // Delete the used token so it can’t be reused
      await env.DB.prepare("DELETE FROM password_resets WHERE token=?")
        .bind(token)
        .run();

      return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers,
      });
    }

    // —————— Create a new image Set ——————
    if (pathname === "/sets" && request.method === "POST") {
      // 1️⃣ authenticate
      const cookie = request.headers.get("Cookie") || "";
      const m = cookie.match(/session=([^;]+)/);
      const payload = m && (await verifyJWT(m[1], env.SESSION_SECRET));
      if (!payload) {
        return new Response(JSON.stringify({ error: "Not authenticated" }), {
          status: 401,
          headers,
        });
      }
      const userId = payload.sub;

      // 2️⃣ parse formData
      const form = await request.formData();
      const title = form.get("title");
      const description = form.get("description");
      const level = form.get("level");
      const files = form.getAll("images");
      if (!title || !description || files.length < 3) {
        return new Response(
          JSON.stringify({
            error: "Missing title/description or too few images",
          }),
          { status: 400, headers }
        );
      }

      // 3️⃣ insert into sets
      const setId = crypto.randomUUID();
      const now = Date.now();
      await env.DB.prepare(
        `
        INSERT INTO sets
          (id, title, description, level, created_at, created_by)
        VALUES (?, ?, ?, ?, ?, ?)
      `
      )
        .bind(setId, title, description, Number(level), now, userId)
        .run();

      // 4️⃣ upload + record only file_name
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const ext = file.name.split(".").pop().toLowerCase();
        const fileName = `${i + 1}.${ext}`;
        const key = `sets/${setId}/${fileName}`;

        await env.USER_IMAGES.put(key, await file.arrayBuffer(), {
          httpMetadata: { contentType: file.type },
        });

        await env.DB.prepare(
          `
          INSERT INTO images
            (id, set_id, file_name, created_at)
          VALUES (?, ?, ?, ?)
        `
        )
          .bind(crypto.randomUUID(), setId, fileName, now)
          .run();
      }

      return new Response(JSON.stringify({ id: setId }), {
        status: 201,
        headers,
      });
    }

    // —————— Public sets (only level 1–5) ——————
    if (pathname === "/public-sets" && request.method === "GET") {
      try {
        const rows = await env.DB.prepare(
          `
          SELECT
            s.id,
            s.title,
            s.level,
            u.name AS username,
            (
              SELECT file_name
              FROM images
              WHERE set_id = s.id
              ORDER BY created_at
              LIMIT 1
            ) AS firstFile,
            (
              SELECT COUNT(*)
              FROM images
              WHERE set_id = s.id
            ) AS imageCount
          FROM sets AS s
          LEFT JOIN users AS u ON u.id = s.created_by
          WHERE s.level BETWEEN 1 AND 5
          ORDER BY s.created_at DESC
        `
        ).all();

        const sets = rows.results.map(
          ({ id, title, level, username, firstFile, imageCount }) => ({
            id,
            title,
            level,
            createdBy: username || "Anonymous",
            imageCount,
            mainImageUrl: `${origin}/images/sets/${id}/${firstFile}`,
          })
        );

        return new Response(JSON.stringify({ sets }), {
          status: 200,
          headers,
        });
      } catch (err) {
        console.error("DB error in /public-sets:", err.message);
        return new Response("Internal Server Error", { status: 500 });
      }
    }

    // Updated GET /set handler with creator username
    if (
      (pathname === "/set" || pathname === "/set.html") &&
      request.method === "GET"
    ) {
      const setId = url.searchParams.get("id");
      if (!setId) {
        return new Response(JSON.stringify({ error: "Missing set ID" }), {
          status: 400,
          headers,
        });
      }

      const setRow = await env.DB.prepare(
        `
    SELECT s.id, s.title, s.description, s.level, s.created_at, s.created_by, u.name AS createdBy
    FROM sets AS s
    LEFT JOIN users AS u ON s.created_by = u.id
    WHERE s.id = ?
  `
      )
        .bind(setId)
        .first();

      if (!setRow) {
        return new Response(JSON.stringify({ error: "Not found" }), {
          status: 404,
          headers,
        });
      }

      if (setRow.level > 5 || setRow.level === 0) {
        const cookie = request.headers.get("Cookie") || "";
        const m = cookie.match(/session=([^;]+)/);
        const payload = m && (await verifyJWT(m[1], env.SESSION_SECRET));
        if (!payload) {
          return new Response(JSON.stringify({ error: "Forbidden" }), {
            status: 403,
            headers,
          });
        }
      }

      const imgs = await env.DB.prepare(
        `
    SELECT file_name FROM images WHERE set_id = ? ORDER BY created_at
  `
      )
        .bind(setId)
        .all();

      const fileNames = imgs.results.map((r) => r.file_name);

      return new Response(
        JSON.stringify({
          id: setRow.id,
          title: setRow.title,
          description: setRow.description,
          level: setRow.level,
          created_at: setRow.created_at,
          createdBy: setRow.createdBy || "Anonymous",
          images: fileNames,
        }),
        {
          status: 200,
          headers,
        }
      );
    }

    // —————— Update Profile (Enhanced) ——————
    if (pathname === "/update-profile" && request.method === "POST") {
      const cookie = request.headers.get("Cookie") || "";
      const m = cookie.match(/session=([^;]+)/);
      const payload = m && (await verifyJWT(m[1], env.SESSION_SECRET));
      if (!payload) {
        return new Response(JSON.stringify({ error: "Not authenticated" }), {
          status: 401,
          headers,
        });
      }

      const userId = payload.sub;
      const form = await request.formData();
      const username = form.get("username");
      const bio = form.get("bio");
      const profileImage = form.get("profileImage");

      // ——— Validate text fields ———
      if (username && username.length > 50) {
        return new Response(JSON.stringify({ error: "Username too long" }), { status: 400, headers });
      }
      if (bio && bio.length > 500) {
        return new Response(JSON.stringify({ error: "Bio too long" }), { status: 400, headers });
      }

      // ——— Validate profile image ———
      let profileImageUrl = null;
      if (profileImage && profileImage.name) {
        const allowedTypes = ["image/jpeg", "image/png", "image/webp"];
        const maxSize = 2 * 1024 * 1024; // 2 MB

        if (!allowedTypes.includes(profileImage.type)) {
          return new Response(JSON.stringify({ error: "Unsupported image type" }), { status: 400, headers });
        }

        const ext = profileImage.name.split(".").pop().toLowerCase();
        if (!["jpg", "jpeg", "png", "webp"].includes(ext)) {
          return new Response(JSON.stringify({ error: "Unsupported file extension" }), { status: 400, headers });
        }

        if (profileImage.size > maxSize) {
          return new Response(JSON.stringify({ error: "Image too large (2MB max)" }), { status: 400, headers });
        }

        const key = `profile-images/${userId}.${ext}`;
        await env.USER_IMAGES.put(key, await profileImage.arrayBuffer(), {
          httpMetadata: { contentType: profileImage.type },
        });

        profileImageUrl = `${origin}/images/${key}`;
      }

      // ——— Update user record ———
      const parts = [];
      const binds = [];

      if (username) { parts.push("name = ?"); binds.push(username); }
      if (bio) { parts.push("bio = ?"); binds.push(bio); }
      if (profileImageUrl) { parts.push("profile_image_url = ?"); binds.push(profileImageUrl); }

      if (parts.length > 0) {
        binds.push(userId);
        await env.DB.prepare(`UPDATE users SET ${parts.join(", ")} WHERE id = ?`).bind(...binds).run();
      }

      return new Response(JSON.stringify({ success: true }), { headers });
    }

    // —————— Fallback 404 ——————
    return new Response(JSON.stringify({ error: "Not found" }), {
      status: 404,
      headers,
    });
  },
};
