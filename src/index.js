// ============================================================
// Nexus - Main Entry Point
// SECURITY: Enforces Bootstrap interception and global headers.
// ============================================================

import { handleSetupAPI } from './routes/setup.js';
import { error } from './utils/response.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // 1. Bootstrap Check
      let isInitialized = false;
      try {
        const result = await env.DB.prepare("SELECT value FROM system_settings WHERE key = 'is_initialized'").first();
        isInitialized = result && result.value === 'true';
      } catch (e) {
        isInitialized = false; // Fail-safe
      }

      if (!isInitialized) {
        if (path === '/api/setup') return handleSetupAPI(request, env);
        if (path.startsWith('/api/')) return error('ERR_NOT_INIT', 'System not initialized', 403);
        // Redirect everything else to setup.html (served as static asset)
        return Response.redirect(`${url.origin}/setup.html`, 302);
      }

      // 2. Routing (After Initialization)
      if (path === '/api/setup') return error('ERR_LOCKED', 'System already initialized', 403);
      if (path === '/api/auth/login') {
         // return handleLogin(request, env); // Next step
         return new Response('Login API ready');
      }

      // Let Cloudflare Workers handle static assets (configured in wrangler.toml)
      return env.ASSETS.fetch(request);

    } catch (e) {
      return error('ERR_CORE', 'Internal Server Error', 500);
    }
  }
};
