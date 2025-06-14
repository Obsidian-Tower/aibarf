// src/routes/profile.js
import { verifyJWT } from '../utils/jwt.js';

export async function handleProfile(request, env, pathname, corsHeaders) {
  const method = request.method;
  const url = new URL(request.url);
  const origin = url.origin;
  const headers = { 'Content-Type': 'application/json', ...corsHeaders };

  // /update-profile
  if (pathname === '/update-profile' && method === 'POST') {
    const cookie = request.headers.get('Cookie') || '';
    const m = cookie.match(/session=([^;]+)/);
    const payload = m && (await verifyJWT(m[1], env.SESSION_SECRET));
    if (!payload) {
      return new Response(JSON.stringify({ error: 'Not authenticated' }), {
        status: 401,
        headers,
      });
    }

    const userId = payload.sub;
    const form = await request.formData();
    const username = form.get('username');
    const bio = form.get('bio');
    const profileImage = form.get('profileImage');

    // Validate text fields
    if (username && username.length > 50) {
      return new Response(JSON.stringify({ error: 'Username too long' }), {
        status: 400,
        headers,
      });
    }
    if (bio && bio.length > 500) {
      return new Response(JSON.stringify({ error: 'Bio too long' }), {
        status: 400,
        headers,
      });
    }

    // Validate profile image
    let profileImageUrl = null;
    if (profileImage && profileImage.name) {
      const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
      const maxSize = 2 * 1024 * 1024; // 2 MB

      if (!allowedTypes.includes(profileImage.type)) {
        return new Response(JSON.stringify({ error: 'Unsupported image type' }), {
          status: 400,
          headers,
        });
      }

      const ext = profileImage.name.split('.').pop().toLowerCase();
      if (!['jpg', 'jpeg', 'png', 'webp'].includes(ext)) {
        return new Response(JSON.stringify({ error: 'Unsupported file extension' }), {
          status: 400,
          headers,
        });
      }

      if (profileImage.size > maxSize) {
        return new Response(JSON.stringify({ error: 'Image too large (2MB max)' }), {
          status: 400,
          headers,
        });
      }

      const key = `profile-images/${userId}.${ext}`;
      await env.USER_IMAGES.put(key, await profileImage.arrayBuffer(), {
        httpMetadata: { contentType: profileImage.type },
      });

      profileImageUrl = `${origin}/images/${key}`;
    }

    // Update user record
    const parts = [];
    const binds = [];

    if (username) {
      parts.push('name = ?');
      binds.push(username);
    }
    if (bio) {
      parts.push('bio = ?');
      binds.push(bio);
    }
    if (profileImageUrl) {
      parts.push('profile_image_url = ?');
      binds.push(profileImageUrl);
    }

    if (parts.length > 0) {
      binds.push(userId);
      await env.DB.prepare(`UPDATE users SET ${parts.join(', ')} WHERE id = ?`)
        .bind(...binds)
        .run();
    }

    return new Response(JSON.stringify({ success: true }), { headers });
  }

  // No profile route matched
  return null;
}
