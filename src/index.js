// src/index.js
import { getCorsHeaders }     from './utils/cors.js';
import { handleAuth }         from './routes/auth.js';
import { handleProfile }      from './routes/profile.js';
import { handleSets }         from './routes/sets.js';
import { handleImages }       from './routes/images.js';
import { handleAdmin }        from './routes/admin.js';
import { ballsUpload }        from './routes/balls-upload.js';
import { handleUser, handleUserPage } from './routes/user.js';

export default {
  async fetch(request, env) {
    console.log('🐛 🦊 fetch', request.method, new URL(request.url).pathname);
    // 1️⃣ Compute CORS headers
    const corsHeaders = getCorsHeaders(request);

    // 2️⃣ Short-circuit preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: corsHeaders
      });
    }

    // 3️⃣ Extract path once
    const url      = new URL(request.url);
    const pathname = url.pathname;

    // 4️⃣ Run your modular route handlers
    const handlers = [
      handleUserPage,    // Page: /u/:username → user.html
      handleAuth,       // /login, /signup, /me, /logout, /forgot-password, /reset-password, etc.
      handleProfile,    // /update-profile, /check-email, /check-username
      handleSets,       // /sets, /public-sets, /set
      handleImages,     // /images/sets/*, /assets/images/*
      handleAdmin,      // /admin/upload
      handleUser,       // API: /api/u/:username
      
    ];

    for (const handler of handlers) {
      const response = await handler(request, env, pathname, corsHeaders);
      if (response) return response;
    }

    // 5️⃣ Attempt to serve any other static file from `public/`
    try {
      console.log('🦊 Attempting to serve static asset:', pathname);
      const assetResponse = await env.ASSETS.fetch(request);
      console.log('🦊 Asset response status:', assetResponse.status);
      console.log('🦊 Asset response headers:', [...assetResponse.headers.entries()]);
      
      if (assetResponse.ok) {
        console.log('🦊 Successfully serving asset:', pathname);
        return assetResponse;
      } else {
        console.log('🦊 Asset response not ok:', assetResponse.status, assetResponse.statusText);
      }
    } catch (e) {
      console.error('🦊 Asset fetch error for', pathname, ':', e.message);
    }

    // 6️⃣ Nothing matched? Return JSON 404
    return new Response(JSON.stringify({ error: 'Not found' }), {
      status: 404,
      headers: {
        'Content-Type': 'application/json',
        ...corsHeaders
      }
    });
  }
};
