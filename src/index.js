// src/index.js
// Cloudflare Worker: Modular router (auth, profile, sets, images, admin) + CORS

import { getCorsHeaders } from './utils/cors.js';
import { handleAuth } from './routes/auth.js';
import { handleProfile } from './routes/profile.js';
import { handleSets } from './routes/sets.js';
import { handleImages } from './routes/images.js';
import { handleAdmin } from './routes/admin.js';
import { handleUser, handleUserPage } from './routes/user.js';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const method = request.method;
    const corsHeaders = getCorsHeaders(request);

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    // Main routing loop
    const handlers = [
      handleAuth,
      handleProfile,
      handleSets,
      handleImages,
      handleAdmin,
      handleUser,      // API: /api/u/:username
      handleUserPage,  // Fallback: /u/:username → user.html
    ];

    for (const handler of handlers) {
      const response = await handler(request, env, pathname, corsHeaders);
      if (response) return response;
    }

    // Fallback 404
    return new Response(JSON.stringify({ error: 'Not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
    });
  },
};