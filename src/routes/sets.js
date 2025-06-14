// src/routes/sets.js
import { verifyJWT } from '../utils/jwt.js';

export async function handleSets(request, env, pathname, corsHeaders) {
  const url = new URL(request.url);
  const method = request.method;
  const headers = { 'Content-Type': 'application/json', ...corsHeaders };

  // /sets → POST → create set
  if (pathname === '/sets' && method === 'POST') {
    const cookie = request.headers.get('Cookie') || '';
    const m = cookie.match(/session=([^;]+)/);
    const payload = m && (await verifyJWT(m[1], env.SESSION_SECRET));
    if (!payload) {
      return new Response(JSON.stringify({ error: 'Not authenticated' }), { status: 401, headers });
    }

    const userId = payload.sub;
    const form = await request.formData();
    const title = form.get('title');
    const description = form.get('description');
    const level = form.get('level');
    const files = form.getAll('images');

    if (!title || !description || files.length < 3) {
      return new Response(JSON.stringify({ error: 'Missing title/description or too few images' }), { status: 400, headers });
    }

    const setId = crypto.randomUUID();
    const now = Date.now();

    await env.DB.prepare(
      `INSERT INTO sets (id, title, description, level, created_at, created_by)
       VALUES (?, ?, ?, ?, ?, ?)`
    )
      .bind(setId, title, description, Number(level), now, userId)
      .run();

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      const ext = file.name.split('.').pop().toLowerCase();
      const fileName = `${i + 1}.${ext}`;
      const key = `sets/${setId}/${fileName}`;

      await env.USER_IMAGES.put(key, await file.arrayBuffer(), {
        httpMetadata: { contentType: file.type },
      });

      await env.DB.prepare(
        `INSERT INTO images (id, set_id, file_name, created_at)
         VALUES (?, ?, ?, ?)`
      )
        .bind(crypto.randomUUID(), setId, fileName, now)
        .run();
    }

    return new Response(JSON.stringify({ id: setId }), { status: 201, headers });
  }

  // /public-sets → GET → list sets
  if (pathname === '/public-sets' && method === 'GET') {
    try {
      const rows = await env.DB.prepare(
        `SELECT s.id, s.title, s.level, u.name AS username,
                (SELECT file_name FROM images WHERE set_id = s.id ORDER BY created_at LIMIT 1) AS firstFile,
                (SELECT COUNT(*) FROM images WHERE set_id = s.id) AS imageCount
         FROM sets AS s
         LEFT JOIN users AS u ON u.id = s.created_by
         WHERE s.level BETWEEN 1 AND 5
         ORDER BY s.created_at DESC`
      ).all();

      const sets = rows.results.map(({ id, title, level, username, firstFile, imageCount }) => ({
        id,
        title,
        level,
        createdBy: username || 'Anonymous',
        imageCount,
        mainImageUrl: `${url.origin}/images/sets/${id}/${firstFile}`,
      }));

      return new Response(JSON.stringify({ sets }), { status: 200, headers });
    } catch (err) {
      console.error('DB error in /public-sets:', err.message);
      return new Response('Internal Server Error', { status: 500 });
    }
  }

  // /set → GET → get single set
  if ((pathname === '/set' || pathname === '/set.html') && method === 'GET') {
    const setId = url.searchParams.get('id');
    if (!setId) {
      return new Response(JSON.stringify({ error: 'Missing set ID' }), { status: 400, headers });
    }

    const setRow = await env.DB.prepare(
      `SELECT s.id, s.title, s.description, s.level, s.created_at, s.created_by, u.name AS createdBy
       FROM sets AS s
       LEFT JOIN users AS u ON s.created_by = u.id
       WHERE s.id = ?`
    )
      .bind(setId)
      .first();

    if (!setRow) {
      return new Response(JSON.stringify({ error: 'Not found' }), { status: 404, headers });
    }

    if (setRow.level > 5 || setRow.level === 0) {
      const cookie = request.headers.get('Cookie') || '';
      const m = cookie.match(/session=([^;]+)/);
      const payload = m && (await verifyJWT(m[1], env.SESSION_SECRET));
      if (!payload) {
        return new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403, headers });
      }
    }

    const imgs = await env.DB.prepare(`SELECT file_name FROM images WHERE set_id = ? ORDER BY created_at`)
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
        createdBy: setRow.createdBy || 'Anonymous',
        images: fileNames,
      }),
      { status: 200, headers }
    );
  }

  // No sets route matched
  return null;
}
