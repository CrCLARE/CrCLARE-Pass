// ============================================================
// Nexus - Main Entry Point
// SECURITY: Implements Bootstrap interception and routing.
// ============================================================

import { handleSetupAPI } from './routes/setup.js';
import { getPublicConfig } from './routes/config.js';
import { handleAuthAPI } from './routes/auth.js';
import { handleGithubOAuth } from './routes/oauth.js';
import { error, json } from './utils/response.js';

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
        // Force redirect to setup UI
        return Response.redirect(`${url.origin}/setup.html`, 302);
      }

      // 2. System is initialized. Proceed to Routing.
      if (path === '/api/setup') return error('ERR_ALREADY_INIT', 'System already initialized', 403);

      // Public Config API
      if (path === '/api/config/public' && request.method === 'GET') {
        return getPublicConfig(env);
      }

      // Auth API (Login, Register, etc.)
      if (path.startsWith('/api/auth')) {
        return handleAuthAPI(request, env);
      }

      // GitHub OAuth Endpoints
      if (path.startsWith('/api/oauth/github')) {
        return handleGithubOAuth(request, env);
      }

      // Serve Static Files (from /public directory)
      // Assuming Cloudflare Workers Assets is configured to fallback to index.html or similar
      return env.ASSETS.fetch(request);

    } catch (e) {
      console.error('[Core Error]', e);
      return error('ERR_SYSTEM_ERROR', 'Internal Server Error', 500);
    }
  }
};
