// ============================================================
// Nexus - Main Entry Point
// SECURITY: Handles routing, Bootstrap interception, and static assets.
// ============================================================

import { json, error } from './utils/response.js';
import { handleSetupAPI } from './routes/setup.js'; // Assuming this exists
import { getPublicConfig } from './routes/config.js';
import { handleAuthAPI } from './routes/auth.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // 1. Bootstrap Check (The First Gate)
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
        // Redirect all frontend requests to setup page
        if (!path.includes('.')) return Response.redirect(`${url.origin}/setup.html`, 302);
      }

      // 2. Prevent accessing setup after initialization
      if (isInitialized && path === '/api/setup') {
        return error('ERR_ALREADY_INIT', 'System already initialized', 403);
      }

      // 3. API Routing (After Initialization)
      if (path.startsWith('/api/')) {
        if (path === '/api/config/public' && request.method === 'GET') {
          return getPublicConfig(env);
        }
        
        if (path.startsWith('/api/auth')) {
          return handleAuthAPI(request, env);
        }
        
        // Future routes (oauth, user, admin, etc.) will be mapped here
        
        return error('ERR_NOT_FOUND', 'API route not found', 404);
      }

      // 4. Serve Static Files (from /public directory)
      // Assuming Cloudflare Workers Assets is configured to serve static files.
      return env.ASSETS.fetch(request);

    } catch (e) {
      console.error('[Core Error]', e);
      return error('ERR_SYSTEM_ERROR', 'Internal Server Error', 500);
    }
  }
};
