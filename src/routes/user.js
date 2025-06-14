// src/routes/user.js
import { verifyJWT } from '../utils/jwt.js';

export async function handleUser(request, env, pathname, corsHeaders) {
  // Only handle /api/u/:username
  const userMatch = pathname.match(/^\/api\/u\/([^\/]+)$/);
  if (!userMatch || request.method !== 'GET') return null;

  const username = decodeURIComponent(userMatch[1]);
  const headers = { 'Content-Type': 'application/json', ...corsHeaders };

  try {
    // Look up user by name
    const userRow = await env.DB.prepare(`
      SELECT id, name, email, bio, profile_image_url
      FROM users
      WHERE name = ?
    `).bind(username).first();

    if (!userRow) {
      return new Response(JSON.stringify({ error: 'User not found' }), {
        status: 404,
        headers
      });
    }

    // Look up public sets created by user (level 1-5)
    const rows = await env.DB.prepare(`
      SELECT
        s.id,
        s.title,
        s.level,
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
      WHERE s.created_by = ? AND s.level BETWEEN 1 AND 5
      ORDER BY s.created_at DESC
    `).bind(userRow.id).all();

    const sets = rows.results.map(row => ({
      id: row.id,
      title: row.title,
      level: row.level,
      imageCount: row.imageCount,
      mainImageUrl: `https://aibarf-auth.coryzuber.workers.dev/images/sets/${row.id}/${row.firstFile}`
    }));

    // Respond with user and their public sets
    return new Response(JSON.stringify({
      user: {
        name: userRow.name,
        email: userRow.email,
        bio: userRow.bio,
        profile_image_url: userRow.profile_image_url
      },
      sets
    }), {
      status: 200,
      headers
    });
  } catch (err) {
    console.error('Error in /api/u/:username:', err.message);
    return new Response(JSON.stringify({ error: 'Internal server error' }), {
      status: 500,
      headers
    });
  }
}
