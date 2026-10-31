// ============================================================
// Nexus - Main Entry Point (Updated)
// ============================================================

import { json, error } from './utils/response.js';
import { handleSetupAPI } from './routes/setup.js';
import { getPublicConfig } from './routes/config.js';
import { handleAuthAPI } from './routes/auth.js';
import { handleOAuth } from './routes/oauth.js'; // NEW: Import OAuth handler

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
        isInitialized = false;
      }

      if (!isInitialized) {
        if (path === '/api/setup') return handleSetupAPI(request, env);
        if (path.startsWith('/api/')) return error('ERR_NOT_INIT', 'System not initialized', 403);
        if (!path.includes('.')) return Response.redirect(`${url.origin}/setup.html`, 302);
      }

      if (isInitialized && path === '/api/setup') {
        return error('ERR_ALREADY_INIT', 'System already initialized', 403);
      }

      // 2. API Routing
      if (path.startsWith('/api/')) {
        if (path === '/api/config/public' && request.method === 'GET') {
          return getPublicConfig(env);
        }
        
        if (path.startsWith('/api/auth')) {
          return handleAuthAPI(request, env);
        }

        if (path.startsWith('/api/oauth')) { // NEW: Route OAuth requests
          return handleOAuth(request, env);
        }
        
        return error('ERR_NOT_FOUND', 'API route not found', 404);
      }

      // 3. Serve Static Files
      return env.ASSETS.fetch(request);

    } catch (e) {
      console.error('[Core Error]', e);
      return error('ERR_SYSTEM_ERROR', 'Internal Server Error', 500);
    }
  }
};
